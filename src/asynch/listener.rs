use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet, resources,
    session::{self, Sessions},
};

use super::{
    authenticator::{AuthType, Authenticator},
    client::EncryptionConfig,
    socket::{TSocket, TSockets},
};

pub type AsyncListenerOkHandler<P, S, R> =
    Arc<dyn Fn(TSocket<S>, P, PoolRef<S>, ResourceRef<R>) -> BoxFuture<'static, ()> + Send + Sync>;

pub type AsyncListenerErrorHandler<S, R> = Arc<
    dyn Fn(TSocket<S>, Error, PoolRef<S>, ResourceRef<R>) -> BoxFuture<'static, ()> + Send + Sync,
>;

#[derive(Clone)]
pub struct PoolRef<S: session::Session + 'static>(pub Arc<RwLock<HashMap<String, TSockets<S>>>>);

#[derive(Clone)]
pub struct ResourceRef<R: resources::Resource + 'static>(pub Arc<R>);

pub struct AsyncListener<P, S, R>
where
    P: packet::Packet + 'static,
    S: session::Session + 'static,
    R: resources::Resource + 'static,
{
    listener: TcpListener,
    ok_handler: AsyncListenerOkHandler<P, S, R>,
    error_handler: AsyncListenerErrorHandler<S, R>,
    authenticator: Authenticator,
    encryption: EncryptionConfig,
    sessions: Arc<RwLock<Sessions<S>>>,
    pub keep_alive_pool: TSockets<S>,
    pub pools: Arc<RwLock<HashMap<String, TSockets<S>>>>,
    resources: Arc<R>,
    _packet: PhantomData<P>,
}

impl<P, S, R> AsyncListener<P, S, R>
where
    P: packet::Packet + 'static,
    S: session::Session + 'static,
    R: resources::Resource + 'static,
{
    pub async fn new(
        ip_port: (&str, u16),
        clean_interval: u64,
        ok_handler: AsyncListenerOkHandler<P, S, R>,
        error_handler: AsyncListenerErrorHandler<S, R>,
    ) -> Self {
        let sessions = Arc::new(RwLock::new(Sessions::new()));

        // Start the background cleanup task
        let sessions_clone = sessions.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(clean_interval));
            loop {
                interval.tick().await;
                sessions_clone.write().await.clear_expired();
            }
        });

        Self {
            listener: TcpListener::bind(ip_port).await.unwrap(),
            ok_handler,
            error_handler,
            authenticator: Authenticator::new(AuthType::None),
            encryption: EncryptionConfig::default(),
            sessions,
            keep_alive_pool: TSockets::new(),
            pools: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(R::new()),
            _packet: PhantomData,
        }
    }

    pub async fn with_encryption_config(mut self, config: EncryptionConfig) -> Self {
        self.encryption = config;
        self
    }

    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption.enabled
    }

    pub fn with_authenticator(mut self, authenticator: Authenticator) -> Self {
        self.authenticator = authenticator;
        self
    }

    pub async fn with_pool(&self, pool_name: &str) {
        self.pools
            .write()
            .await
            .insert(pool_name.to_string(), TSockets::new());
    }

    pub async fn with_resource(mut self, resource: R) -> Self {
        self.resources = Arc::new(resource);
        self
    }

    pub async fn add_socket_to_pool(&mut self, pool_name: &str, socket: &TSocket<S>) {
        let socket = socket.clone();
        let mut pools = self.pools.write().await;
        let pool = pools.get_mut(pool_name).expect("Unknown Pool");
        pool.add(socket).await;
    }

    pub async fn get_pool_ref(&self) -> PoolRef<S> {
        PoolRef(self.pools.clone())
    }

    pub async fn get_resources(&self) -> Arc<R> {
        self.resources.clone()
    }

    async fn handle_encryption_handshake(
        &self,
        socket: &mut TSocket<S>,
    ) -> std::io::Result<Encryptor> {
        let mut client_public = [0u8; 32];
        {
            let mut sock = socket.socket.lock().await;
            sock.read_exact(&mut client_public).await?;
        }

        let key_exchange = KeyExchange::new();
        let server_public = key_exchange.get_public_key();

        {
            let mut sock = socket.socket.lock().await;
            sock.write_all(&server_public).await?;
            sock.flush().await?;
        }

        let shared_secret = key_exchange.compute_shared_secret(&client_public);

        Ok(Encryptor::new(&shared_secret))
    }

    async fn handle_authentication(
        &mut self,
        tsocket: &mut TSocket<S>,
    ) -> Result<Option<Encryptor>, Error> {
        self.sessions.write().await.clear_expired();

        // Step 1: Handle Encryption Setup
        let encryptor = if self.encryption.enabled {
            let enc = self
                .handle_encryption_handshake(tsocket)
                .await
                .map_err(|e| Error::EncryptionError(e.to_string()))?;
            tsocket.encryptor = Some(enc.clone()); // Set the encryptor in TSocket
            Some(enc)
        } else {
            None
        };

        // Step 2: Handle No Authentication Case
        if matches!(self.authenticator.auth_type, AuthType::None) {
            let session_id = uuid::Uuid::new_v4().to_string();
            self.sessions
                .write()
                .await
                .new_session(S::empty(session_id.clone()));
            tsocket.session_id = Some(session_id.clone());

            self.keep_alive_pool.add(tsocket.clone()).await;
            // Send OK response with new session ID
            let mut ok = P::ok();
            ok.session_id(Some(session_id));
            tsocket.send(ok).await?;

            return Ok(encryptor);
        }

        // Step 3: Handle Authentication Cases
        let packet = tsocket.recv::<P>().await?;
        let body = packet.body();

        // Case 3a: Session ID Authentication
        if let Some(id) = body.session_id {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get_session(&id) {
                if session.is_expired() {
                    return Err(Error::ExpriedSessionId(id));
                }
                tsocket.session_id = Some(id);
                tsocket.send(P::ok()).await?;
                self.keep_alive_pool.add(tsocket.clone()).await;
                return Ok(encryptor);
            }
            return Err(Error::InvalidSessionId(id));
        }

        // Case 3b: Username/Password Authentication
        if let (Some(username), Some(password)) = (body.username, body.password) {
            match self.authenticator.authenticate(username, password).await {
                Ok(_) => {
                    // Create new session after successful authentication
                    let session_id = uuid::Uuid::new_v4().to_string();
                    self.sessions
                        .write()
                        .await
                        .new_session(S::empty(session_id.clone()));
                    tsocket.session_id = Some(session_id.clone());

                    // Send OK response with new session ID
                    let mut ok = P::ok();
                    ok.session_id(Some(session_id));
                    tsocket.send(ok).await?;

                    Ok(encryptor)
                }
                Err(e) => {
                    let err = P::error(e.clone());
                    tsocket.send(err).await?;

                    Err(e)
                }
            }
        } else {
            Err(Error::InvalidCredentials)
        }
    }

    pub async fn broadcast(&self, packet: P) -> Result<(), Error> {
        // Send to all connected clients in the keep_alive_pool
        for socket in self.keep_alive_pool.sockets.write().await.iter_mut() {
            socket.send(packet.clone()).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        println!("Server Started!");
        loop {
            let opt = self.listener.accept().await;

            if let Err(e) = opt {
                eprintln!("Failed to accept connection: {}", e);
                break;
            }

            let (socket, addr) = opt.unwrap();

            println!("Accepted connection from {}", addr);

            let mut tsocket = TSocket::new(socket, self.sessions.clone());
            let ok_handler = self.ok_handler.clone();
            let error_handler = self.error_handler.clone();
            let mut keep_alive_pool = self.keep_alive_pool.clone();
            let pools = self.pools.clone();
            let resources = self.resources.clone();

            let auth_resp = self.handle_authentication(&mut tsocket).await;

            if let Err(e) = auth_resp {
                error_handler(
                    tsocket,
                    e,
                    PoolRef(pools.clone()),
                    ResourceRef(resources.clone()),
                )
                .await;
            } else {
                tokio::spawn(async move {
                    loop {
                        let resp = tsocket.recv::<P>().await;

                        if let Err(e) = resp.as_ref() {
                            if e == &Error::ConnectionClosed {
                                println!("Client disconnected.");
                                break;
                            }
                            error_handler(
                                tsocket.clone(),
                                e.to_owned(),
                                PoolRef(pools.clone()),
                                ResourceRef(resources.clone()),
                            )
                            .await;
                        }

                        let packet = resp.unwrap();

                        if packet.header() == P::keep_alive().header() {
                            let mut response = P::keep_alive();
                            if let Some(id) = &tsocket.session_id {
                                response.session_id(Some(id.clone()));
                            }
                            if let Err(e) = tsocket.send(response).await {
                                eprintln!("Failed to send keepalive response: {}", e);
                                break;
                            }
                            if let Some(first_ka_packet) = packet.body().is_first_keep_alive_packet
                            {
                                if first_ka_packet {
                                    let socket_clone = tsocket.clone();
                                    keep_alive_pool.add(socket_clone).await;
                                }
                            }
                        } else {
                            ok_handler(
                                tsocket.clone(),
                                packet,
                                PoolRef(pools.clone()),
                                ResourceRef(resources.clone()),
                            )
                            .await;
                        }
                    }
                });
            }
        }
    }
}
