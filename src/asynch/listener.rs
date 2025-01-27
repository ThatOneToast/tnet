use std::{marker::PhantomData, sync::Arc};

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet,
    session::{self, Sessions},
};

use super::{
    authenticator::{AuthType, Authenticator},
    client::EncryptionConfig,
    socket::TSocket,
};

pub type AsyncListenerOkHandler<P, S> =
    Arc<dyn Fn(TSocket<S>, P) -> BoxFuture<'static, ()> + Send + Sync>;

pub type AsyncListenerErrorHandler<S> =
    Arc<dyn Fn(TSocket<S>, Error) -> BoxFuture<'static, ()> + Send + Sync>;

pub struct AsyncListener<P, S>
where
    P: packet::Packet + 'static,
    S: session::Session + 'static,
{
    listener: TcpListener,
    ok_handler: AsyncListenerOkHandler<P, S>,
    error_handler: AsyncListenerErrorHandler<S>,
    authenticator: Authenticator,
    encryption: EncryptionConfig,
    sessions: Arc<RwLock<Sessions<S>>>,
    _packet: PhantomData<P>,
}

impl<P, S> AsyncListener<P, S>
where
    P: packet::Packet + 'static,
    S: session::Session + 'static,
{
    pub async fn new(
        ip_port: (&str, u16),
        clean_interval: u64,
        ok_handler: AsyncListenerOkHandler<P, S>,
        error_handler: AsyncListenerErrorHandler<S>,
    ) -> Self {
        let sessions = Arc::new(RwLock::new(Sessions::new()));

        // Start the background cleanup task
        let sessions_clone = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(clean_interval));
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

    async fn handle_encryption_handshake(
        &self,
        socket: &mut TcpStream,
    ) -> std::io::Result<Encryptor> {
        println!("Starting encryption handshake");

        let mut client_public = [0u8; 32];
        println!("Reading client's public key");
        socket.read_exact(&mut client_public).await?;

        let key_exchange = KeyExchange::new();
        let server_public = key_exchange.get_public_key();

        println!("Sending server's public key");
        socket.write_all(&server_public).await?;
        socket.flush().await?;

        println!("Computing shared secret");
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
                .handle_encryption_handshake(&mut tsocket.socket)
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

    pub async fn run(&mut self) {
        loop {
            match self.listener.accept().await {
                Ok((socket, addr)) => {
                    println!("Accepted connection from {}", addr);

                    let mut tsocket = TSocket::new(socket, self.sessions.clone());

                    // Handle authentication and encryption
                    match self.handle_authentication(&mut tsocket).await {
                        Ok(_) => {
                            // Create session if it hasn't been created during authentication
                            if tsocket.session_id.is_none() {
                                let ses_id = uuid::Uuid::new_v4().to_string();
                                let ses = S::empty(ses_id.clone());
                                tsocket.session_id = Some(ses_id.clone());
                                self.sessions.write().await.new_session(ses);
                            }

                            let ok_handler = self.ok_handler.clone();

                            // Call handler with the packet received during authentication
                            if let Ok(packet) = tsocket.recv::<P>().await {
                                ok_handler(tsocket, packet).await;
                            }
                        }
                        Err(e) => {
                            let error_handler = self.error_handler.clone();
                            eprintln!("Authentication failed: {}", e);
                            error_handler(tsocket, e).await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                    break;
                }
            }
        }
    }
}
