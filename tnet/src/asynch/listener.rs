use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    handler_registry, packet, resources,
    session::{self, Sessions},
};

use super::{
    authenticator::{AuthType, Authenticator},
    client::EncryptionConfig,
    socket::{TSocket, TSockets},
};

/// A collection of resources provided to packet handlers.
///
/// `HandlerSources` bundles together the socket connection, connection pools,
/// and application resources needed by packet handler functions. This abstraction
/// simplifies handler function signatures and provides all the necessary context
/// for processing network events.
///
/// # Type Parameters
///
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Examples
///
/// ```
/// async fn handle_login_packet(sources: HandlerSources<MySession, MyResource>, packet: LoginPacket) {
///     let socket = sources.socket;
///     let pools = sources.pools;
///     let resources = sources.resources;
///
///     // Process login and respond
///     let response = LoginResponse::new(true);
///     socket.send(response).await.expect("Failed to send response");
///
///     // Add to appropriate connection pool
///     pools.insert("authenticated", &socket).await;
/// }
/// ```
#[derive(Clone)]
pub struct HandlerSources<S, R>
where
    S: crate::session::Session,
    R: crate::resources::Resource,
{
    pub socket: TSocket<S>,
    pub pools: PoolRef<S>,
    pub resources: ResourceRef<R>,
}

/// Type alias for the success handler function in the async listener.
///
/// This handler is called when a packet is successfully received and validated.
/// It processes the packet and performs any necessary business logic.
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
pub type AsyncListenerOkHandler<P, S, R> =
    Arc<dyn Fn(HandlerSources<S, R>, P) -> BoxFuture<'static, ()> + Send + Sync>;

/// Type alias for the error handler function in the async listener.
///
/// This handler is called when an error occurs during packet processing.
/// It handles error conditions and performs any necessary cleanup or logging.
///
/// # Type Parameters
///
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
pub type AsyncListenerErrorHandler<S, R> =
    Arc<dyn Fn(HandlerSources<S, R>, Error) -> BoxFuture<'static, ()> + Send + Sync>;

/// Thread-safe reference to a pool of socket connections.
///
/// Provides access to a shared hashmap of named socket collections, allowing
/// multiple handlers to access and modify connection pools concurrently.
///
/// # Type Parameters
///
/// * `S` - The session type implementing the `Session` trait
///
/// # Example
///
/// ```rust
/// use tnet::asynch::listener::PoolRef;
///
/// async fn handle_pool(pool_ref: PoolRef<MySession>) {
///     let pools = pool_ref.0.write().await;
///     // Work with pools...
/// }
/// ```
#[derive(Clone)]
pub struct PoolRef<S: session::Session>(pub Arc<RwLock<HashMap<String, TSockets<S>>>>);

impl<S: session::Session> PoolRef<S> {
    pub async fn write(&mut self) -> RwLockWriteGuard<'_, HashMap<String, TSockets<S>>> {
        self.0.write().await
    }

    pub async fn read(&self) -> RwLockReadGuard<'_, HashMap<String, TSockets<S>>> {
        self.0.read().await
    }

    pub async fn insert(&mut self, name: impl ToString, socket: &TSocket<S>) {
        self.0
            .write()
            .await
            .get_mut(name.to_string().as_str())
            .expect("Socket collection not found")
            .add(socket.clone())
            .await;
    }

    pub async fn get(&self, name: impl ToString) -> Option<TSockets<S>> {
        let lock = self.0.read().await;
        lock.get(name.to_string().as_str()).cloned()
    }

    pub async fn broadcast<P: packet::Packet>(&self, packet: P) -> Result<(), Error> {
        let pools_to_broadcast = {
            let pools = self.0.read().await;
            pools.values().cloned().collect::<Vec<_>>()
        };

        for pool in pools_to_broadcast {
            pool.broadcast(packet.clone()).await?;
        }

        Ok(())
    }

    // Broadcast to a specific pool
    pub async fn broadcast_to<P: packet::Packet>(
        &self,
        pool_name: &str,
        packet: P,
    ) -> Result<(), Error> {
        let pools = self.0.read().await;
        if let Some(pool) = pools.get(pool_name) {
            pool.broadcast(packet).await?;
            Ok(())
        } else {
            Err(Error::InvalidPool(pool_name.to_string()))
        }
    }
}

/// Thread-safe reference to shared resources.
///
/// Provides concurrent access to application resources that need to be shared
/// across multiple connection handlers.
///
/// # Type Parameters
///
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Example
///
/// ```rust
/// use tnet::asynch::listener::ResourceRef;
///
/// async fn use_resources(resources: ResourceRef<MyResource>) {
///     let resource_guard = resources.read().await;
///     // Work with resources...
/// }
/// ```
#[derive(Clone)]
pub struct ResourceRef<R: resources::Resource>(pub Arc<RwLock<R>>);

impl<R: resources::Resource + 'static> ResourceRef<R> {
    /// Creates a new `ResourceRef` wrapping the provided resource.
    pub fn new(resource: R) -> Self {
        Self(Arc::new(RwLock::new(resource)))
    }

    /// Obtains a read lock on the resources.
    pub async fn read(&self) -> RwLockReadGuard<R> {
        self.0.read().await
    }

    /// Obtains a write lock on the resources.
    pub async fn write(&self) -> RwLockWriteGuard<R> {
        self.0.write().await
    }
}

/// The main server component for handling network connections and packet processing.
///
/// `AsyncListener` provides a robust framework for:
/// - Accepting network connections
/// - Managing client sessions
/// - Handling authentication
/// - Processing packets
/// - Managing connection pools
/// - Sharing resources
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Example
///
/// ```rust
/// use tnet::asynch::listener::AsyncListener;
///
/// async fn create_server() {
///     let listener = AsyncListener::new(
///         ("127.0.0.1", 8080),
///         30,
///         ok_handler,
///         error_handler
///     ).await;
///
///     // Configure and run the server...
/// }
/// ```
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
    resources: ResourceRef<R>,
    _packet: PhantomData<P>,
}

impl<P, S, R> AsyncListener<P, S, R>
where
    P: packet::Packet + 'static,
    S: session::Session + 'static,
    R: resources::Resource + 'static,
{
    /// Creates a new `AsyncListener` instance.
    ///
    /// # Arguments
    ///
    /// * `ip_port` - Tuple of IP address and port to bind to
    /// * `clean_interval` - Interval in seconds for cleaning expired sessions
    /// * `ok_handler` - Handler for successful packet processing
    /// * `error_handler` - Handler for error conditions
    ///
    /// # Returns
    ///
    /// * The configured `AsyncListener` instance
    ///
    /// # Panics
    ///
    /// * Panics if unable to bind to the specified IP address and port
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
            resources: ResourceRef::new(R::new()),
            _packet: PhantomData,
        }
    }

    /// Registers a handler for a specific packet type.
    ///
    /// # Arguments
    ///
    /// * `packet_type` - The packet type string that triggers this handler
    /// * `handler` - The handler function to register
    ///
    /// # Returns
    ///
    /// * `Self` - The configured listener instance
    #[must_use]
    pub fn with_handler(self, packet_type: &str, handler: AsyncListenerOkHandler<P, S, R>) -> Self {
        crate::handler_registry::register_handler(packet_type, move |sources, packet| {
            handler(sources, packet)
        });

        self
    }

    /// Configures encryption settings for the listener.
    ///
    /// # Arguments
    ///
    /// * `config` - Encryption configuration settings
    ///
    /// # Returns
    ///
    /// * The modified `AsyncListener` instance
    #[must_use]
    pub const fn with_encryption_config(mut self, config: EncryptionConfig) -> Self {
        self.encryption = config;
        self
    }

    /// Checks if encryption is enabled for this listener.
    pub const fn is_encryption_enabled(&self) -> bool {
        self.encryption.enabled
    }

    /// Configures authentication settings for the listener.
    ///
    /// # Arguments
    ///
    /// * `authenticator` - The authenticator instance to use for client authentication
    ///
    /// # Returns
    ///
    /// * `Self` - The configured listener instance
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnet::{Authenticator, AuthType};
    ///
    /// async fn configure_auth(listener: AsyncListener<P, S, R>) {
    ///     let auth = Authenticator::new(AuthType::UserPassword)
    ///         .with_auth_fn(|user, pass| Box::pin(async move {
    ///             // Authentication logic here
    ///             Ok(())
    ///         }));
    ///     let listener = listener.with_authenticator(auth);
    /// }
    /// ```
    #[must_use]
    pub fn with_authenticator(mut self, authenticator: Authenticator) -> Self {
        self.authenticator = authenticator;
        self
    }

    /// Creates a new connection pool with the specified name.
    ///
    /// # Arguments
    ///
    /// * `pool_name` - Name for the new connection pool
    ///
    /// # Example
    ///
    /// ```rust
    /// async fn setup_pool(listener: &AsyncListener<P, S, R>) {
    ///     listener.with_pool("main_pool").await;
    /// }
    /// ```
    pub async fn with_pool(&self, pool_name: impl ToString) {
        self.pools
            .write()
            .await
            .insert(pool_name.to_string(), TSockets::new());
    }

    /// Configures shared resources for the listener.
    ///
    /// # Arguments
    ///
    /// * `resource` - The resource instance to share across connections
    ///
    /// # Returns
    ///
    /// * `Self` - The configured listener instance
    #[must_use]
    pub fn with_resource(mut self, resource: R) -> Self {
        self.resources = ResourceRef::new(resource);
        self
    }

    /// Adds a socket to a specified connection pool.
    ///
    /// # Arguments
    ///
    /// * `pool_name` - Name of the pool to add the socket to
    /// * `socket` - The socket to add
    ///
    /// # Panics
    ///
    /// * Panics if the specified pool doesn't exist
    pub async fn add_socket_to_pool(&mut self, pool_name: &str, socket: &TSocket<S>) {
        self.pools
            .write()
            .await
            .get_mut(pool_name)
            .expect("Unknown Pool")
            .add(socket.clone())
            .await;
    }

    /// Gets a reference to the connection pools.
    ///
    /// # Returns
    ///
    /// * `PoolRef<S>` - Reference to the connection pools
    pub fn get_pool_ref(&self) -> PoolRef<S> {
        PoolRef(self.pools.clone())
    }

    /// Gets a reference to the shared resources.
    ///
    /// # Returns
    ///
    /// * `ResourceRef<R>` - Reference to the shared resources
    pub fn get_resources(&self) -> ResourceRef<R> {
        self.resources.clone()
    }

    /// Handles the encryption handshake with a client.
    ///
    /// Performs key exchange and establishes encrypted communication.
    ///
    /// # Arguments
    ///
    /// * `socket` - The client socket
    ///
    /// # Returns
    ///
    /// * `std::io::Result<Encryptor>` - The configured encryptor or an error
    async fn handle_encryption_handshake(&self, socket: &TSocket<S>) -> std::io::Result<Encryptor> {
        let mut sock = socket.socket.lock().await;

        // Read length prefix
        let mut length_buf = [0u8; 4];
        sock.read_exact(&mut length_buf).await?;
        let length = u32::from_be_bytes(length_buf) as usize;

        if length != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid client public key length",
            ));
        }

        // Read client's public key
        let mut client_public_key = [0u8; 32];
        sock.read_exact(&mut client_public_key).await?;

        let key_exchange = KeyExchange::new();
        let server_public = key_exchange.get_public_key();

        // Send length-prefixed public key
        let mut response = Vec::new();
        response.extend_from_slice(&(server_public.len() as u32).to_be_bytes());
        response.extend_from_slice(&server_public);

        sock.write_all(&response).await?;
        sock.flush().await?;
        drop(sock);

        let shared_secret = key_exchange.compute_shared_secret(&client_public_key);
        Ok(Encryptor::new(&shared_secret).expect("Failed to create encryptor"))
    }

    /// Handles the authentication process for a client connection.
    ///
    /// Processes various authentication methods including:
    /// - Session ID authentication
    /// - Username/password authentication
    /// - No authentication (if configured)
    ///
    /// # Arguments
    ///
    /// * `tsocket` - The client socket
    ///
    /// # Returns
    ///
    /// * `Result<Option<Encryptor>, Error>` - The encryption configuration or an error
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
            let session_result = {
                let sessions = self.sessions.read().await;
                sessions.get_session(&id).cloned()
            };

            if let Some(session) = session_result {
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

    /// Broadcasts a packet to all connected clients.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to broadcast
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Success or failure of the broadcast operation
    ///
    /// # Errors
    ///
    /// * Returns error if sending to any client fails
    ///
    /// # Example
    ///
    /// ```rust
    /// async fn broadcast_message(listener: &AsyncListener<P, S, R>, packet: P) {
    ///     listener.broadcast(packet).await.expect("Broadcast failed");
    /// }
    /// ```
    pub async fn broadcast(&self, packet: P) -> Result<(), Error> {
        let pool = self.keep_alive_pool.clone().sockets;
        {
            let mut sockets = pool.write().await;

            for socket in sockets.iter_mut() {
                socket.send(packet.clone()).await?;
            }
        }
        Ok(())
    }

    /// Starts the listener and begins accepting connections.
    ///
    /// This is the main event loop that:
    /// 1. Accepts incoming connections
    /// 2. Handles authentication
    /// 3. Processes packets
    /// 4. Manages connection lifecycle
    ///
    /// # Example
    ///
    /// ```rust
    /// async fn start_server(mut listener: AsyncListener<P, S, R>) {
    ///     println!("Starting server...");
    ///     listener.run().await;
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// * Panics if accepting a connection fails unexpectedly
    pub async fn run(&mut self) {
        println!("Server Started!");
        loop {
            let opt = match self.listener.accept().await {
                Ok(opt) => opt,
                Err(e) => {
                    eprintln!("Failed to accept connection: {e}");
                    break;
                }
            };

            let (socket, addr) = opt;

            println!("Accepted connection from {addr}");

            let mut tsocket = TSocket::new(socket, self.sessions.clone());
            let ok_handler = self.ok_handler.clone();
            let error_handler = self.error_handler.clone();
            let mut keep_alive_pool = self.keep_alive_pool.clone();
            let pools = self.pools.clone();
            let resources = self.resources.clone();

            let auth_resp = self.handle_authentication(&mut tsocket).await;

            if let Err(e) = auth_resp {
                let sources = HandlerSources {
                    socket: tsocket,
                    pools: PoolRef(pools.clone()),
                    resources: resources.clone(),
                };
                error_handler(sources, e).await;
            } else {
                tokio::spawn(async move {
                    loop {
                        let resp = tsocket.recv::<P>().await;

                        if let Err(e) = resp.as_ref() {
                            if e == &Error::ConnectionClosed {
                                println!("Client disconnected.");
                                break;
                            }
                            let sources = HandlerSources {
                                socket: tsocket.clone(),
                                pools: PoolRef(pools.clone()),
                                resources: resources.clone(),
                            };
                            error_handler(sources, e.to_owned()).await;
                        }

                        let packet = resp.unwrap();

                        if packet.header() == P::keep_alive().header() {
                            let mut response = P::keep_alive();
                            if let Some(id) = &tsocket.session_id {
                                response.session_id(Some(id.clone()));
                            }
                            if let Err(e) = tsocket.send(response).await {
                                eprintln!("Failed to send keepalive response: {e}");
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
                            let sources = HandlerSources {
                                socket: tsocket.clone(),
                                pools: PoolRef(pools.clone()),
                                resources: resources.clone(),
                            };

                            // Get all handlers for this packet type
                            let handlers =
                                handler_registry::get_handlers::<P, S, R>(&packet.header());

                            if !handlers.is_empty() {
                                // Run all handlers for this packet type
                                for handler in handlers {
                                    handler(sources.clone(), packet.clone()).await;
                                }
                            } else {
                                // Fall back to default handler if no registered handlers
                                ok_handler(sources, packet).await;
                            }
                        }
                    }
                });
            }
        }
    }
}
