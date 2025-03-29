use std::{sync::Arc, vec::IntoIter};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, RwLock},
};

use crate::{
    encrypt::Encryptor,
    errors::Error,
    packet::Packet,
    session::{self, Sessions},
};

/// A thread-safe collection of network sockets that can be shared across multiple tasks.
///
/// `TSockets` provides a way to manage multiple socket connections in a thread-safe manner,
/// particularly useful for broadcasting messages to multiple connected clients.
///
/// # Type Parameters
///
/// * `S`: A type that implements the `Session` trait for managing connection state
///
/// # Example
///
/// ```rust
/// use tnet::socket::TSockets;
/// use tnet::session::Session;
///
/// #[derive(Clone)]
/// struct MySession { /* ... */ }
/// impl Session for MySession { /* ... */ }
///
/// let mut sockets = TSockets::<MySession>::new();
/// ```
#[derive(Clone)]
pub struct TSockets<S>
where
    S: session::Session,
{
    pub sockets: Arc<RwLock<Vec<TSocket<S>>>>,
}

impl<S> TSockets<S>
where
    S: session::Session,
{
    /// Creates a new empty collection of sockets.
    ///
    /// # Returns
    ///
    /// * A new `TSockets` instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Adds a new socket to the collection.
    ///
    /// # Arguments
    ///
    /// * `socket`: The socket to add to the collection
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::socket::{TSockets, TSocket};
    /// # use tokio::net::TcpStream;
    /// # async fn example() {
    /// # let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
    /// # let socket = TSocket::new(stream, Arc::new(RwLock::new(Sessions::new())));
    /// let mut sockets = TSockets::new();
    /// sockets.add(socket).await;
    /// # }
    /// ```
    pub async fn add(&mut self, socket: TSocket<S>) {
        self.sockets.write().await.push(socket);
    }

    /// Removes a socket from the collection.
    ///
    /// # Arguments
    ///
    /// * `socket`: The socket to remove
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::socket::{TSockets, TSocket};
    /// # async fn example(socket: TSocket<Session>) {
    /// let mut sockets = TSockets::new();
    /// sockets.remove(&socket).await;
    /// # }
    /// ```
    pub async fn remove(&mut self, socket: &TSocket<S>) {
        self.sockets
            .write()
            .await
            .retain(|s| s.session_id != socket.session_id);
    }

    /// Broadcasts a packet to all connected sockets.
    ///
    /// # Arguments
    ///
    /// * `packet`: The packet to broadcast to all connections
    ///
    /// # Panics
    ///
    /// This function will panic if sending to any socket fails
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::socket::TSockets;
    /// # use tnet::packet::Packet;
    /// # async fn example<P: Packet>(sockets: &TSockets<Session>, packet: P) {
    /// sockets.broadcast(packet).await;
    /// # }
    /// ```
    pub async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let errors = {
            let mut errors = Vec::new();

            {
                let mut sockets = self.sockets.write().await;

                for socket in sockets.iter_mut() {
                    if let Err(e) = socket.send(packet.clone()).await {
                        errors.push(e);
                    }
                }
            }

            errors
        };

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!("Broadcast errors: {:?}", errors)))
        }
    }

    pub async fn iter(&self) -> impl Iterator<Item = TSocket<S>> {
        self.sockets.read().await.clone().into_iter()
    }

    pub async fn iter_mut(&mut self) -> impl Iterator<Item = TSocket<S>> {
        self.sockets.write().await.clone().into_iter()
    }
}

impl<S> Default for TSockets<S>
where
    S: session::Session,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<S: session::Session> IntoIterator for &TSockets<S> {
    type Item = TSocket<S>;
    type IntoIter = IntoIter<TSocket<S>>;

    fn into_iter(self) -> Self::IntoIter {
        let sockets = futures::executor::block_on(async { self.sockets.read().await.clone() });
        sockets.into_iter()
    }
}

impl<S: session::Session> IntoIterator for &mut TSockets<S> {
    type Item = TSocket<S>;
    type IntoIter = IntoIter<TSocket<S>>;

    fn into_iter(self) -> Self::IntoIter {
        let sockets = futures::executor::block_on(async { self.sockets.write().await.clone() });
        sockets.into_iter()
    }
}

/// A thread-safe wrapper around a TCP socket with session management and encryption capabilities.
///
/// `TSocket` provides a high-level interface for handling TCP connections with integrated
/// session management and optional encryption.
///
/// # Type Parameters
///
/// * `S`: A type that implements the `Session` trait for managing connection state
///
/// # Example
///
/// ```rust
/// use tnet::socket::TSocket;
/// use tokio::net::TcpStream;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// async fn handle_connection(stream: TcpStream, sessions: Arc<RwLock<Sessions<MySession>>>) {
///     let socket = TSocket::new(stream, sessions);
///     // Use socket for communication...
/// }
/// ```
#[derive(Clone)]
pub struct TSocket<S>
where
    S: session::Session,
{
    pub socket: Arc<Mutex<TcpStream>>,
    pub session_id: Option<String>,
    pub encryptor: Option<Encryptor>,
    sessions: Arc<RwLock<Sessions<S>>>,
}

impl<S> TSocket<S>
where
    S: session::Session,
{
    /// Creates a new `TSocket` instance.
    ///
    /// # Arguments
    ///
    /// * `socket`: The TCP stream to wrap
    /// * `sessions`: The session manager
    ///
    /// # Returns
    ///
    /// * A new `TSocket` instance
    pub fn new(socket: TcpStream, sessions: Arc<RwLock<Sessions<S>>>) -> Self {
        Self {
            socket: Arc::new(Mutex::new(socket)),
            session_id: None,
            encryptor: None,
            sessions,
        }
    }

    /// Adds encryption capabilities to the socket.
    ///
    /// # Arguments
    ///
    /// * `encryptor`: The encryptor to use for secure communication
    ///
    /// # Returns
    ///
    /// * The modified `TSocket` instance
    #[must_use]
    pub fn with_encryptor(mut self, encryptor: Encryptor) -> Self {
        self.encryptor = Some(encryptor);
        self
    }

    /// Associates a session ID with the socket.
    ///
    /// # Arguments
    ///
    /// * `session_id`: The session ID to associate
    ///
    /// # Returns
    ///
    /// * The modified `TSocket` instance
    #[must_use]
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Retrieves the current session associated with this socket.
    ///
    /// # Returns
    ///
    /// * An Option containing the current session if it exists
    pub async fn get_session(&self) -> Option<S> {
        if let Some(id) = &self.session_id {
            let sessions = self.sessions.read().await;
            sessions.get_session(id).cloned()
        } else {
            None
        }
    }

    /// Updates the current session using the provided function.
    ///
    /// # Arguments
    ///
    /// * `f`: A function that takes a mutable reference to the session and returns a value
    ///
    /// # Returns
    ///
    /// * A Result containing the function's return value or an error
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidSessionId` if no session ID is set or if the session ID is invalid
    pub async fn update_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut S) -> T + Send,
    {
        if let Some(id) = &self.session_id {
            let mut sessions = self.sessions.write().await;
            sessions.get_session_mut(id).map_or_else(
                || Err(Error::InvalidSessionId(id.clone())),
                |session| Ok(f(session)),
            )
        } else {
            Err(Error::InvalidSessionId("No session ID".to_string()))
        }
    }

    /// Sends a packet through the socket, with optional encryption.
    ///
    /// # Arguments
    ///
    /// * `packet`: The packet to send
    ///
    /// # Returns
    ///
    /// * A Result indicating success or failure
    ///
    /// # Errors
    ///
    /// Returns `Error::IoError` if writing to the socket fails
    pub async fn send<P: Packet>(&mut self, packet: P) -> Result<(), Error> {
        let data = self
            .encryptor
            .as_ref()
            .map_or_else(|| packet.ser(), |encryptor| packet.encrypted_ser(encryptor));

        let mut socket = self.socket.lock().await;
        socket
            .write_all(&data)
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        socket
            .flush()
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        drop(socket);
        Ok(())
    }

    /// Receives a packet from the socket, with optional decryption.
    ///
    /// # Returns
    ///
    /// * A Result containing the received packet or an error
    ///
    /// # Errors
    ///
    /// Returns `Error::IoError` if reading from the socket fails
    /// Returns `Error::ConnectionClosed` if the connection is closed
    pub async fn recv<P: Packet>(&mut self) -> Result<P, Error> {
        let mut buf = vec![0; 4096];
        let n = {
            let mut socket = self.socket.lock().await;
            socket
                .read(&mut buf)
                .await
                .map_err(|e| Error::IoError(e.to_string()))?
        };

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        buf.truncate(n);

        Ok(self
            .encryptor
            .as_ref()
            .map_or_else(|| P::de(&buf), |encryptor| P::encrypted_de(&buf, encryptor)))
    }

    /// Sends raw data through the socket.
    ///
    /// # Arguments
    ///
    /// * `packet`: The raw data to send
    ///
    /// # Returns
    ///
    /// * A Result indicating success or failure
    ///
    /// # Errors
    ///
    /// Returns `Error::IoError` if writing to the socket fails
    pub async fn send_raw(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        let mut socket = self.socket.lock().await;
        socket
            .write_all(&packet)
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        socket
            .flush()
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        drop(socket);
        Ok(())
    }

    /// Receives raw data from the socket.
    ///
    /// # Returns
    ///
    /// * A Result containing the received data or an error
    ///
    /// # Errors
    ///
    /// Returns `Error::IoError` if reading from the socket fails
    /// Returns `Error::ConnectionClosed` if the connection is closed
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; 4096];
        let n = {
            let mut socket = self.socket.lock().await;
            socket
                .read(&mut buf)
                .await
                .map_err(|e| Error::IoError(e.to_string()))?
        };

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        buf.truncate(n);

        Ok(buf)
    }

    /// Gets the peer address of the socket.
    ///
    /// # Returns
    ///
    /// * A String containing the peer address
    ///
    /// # Panics
    ///
    /// Panics if getting the peer address fails
    pub async fn addr(&self) -> String {
        let socket = self.socket.lock().await;
        socket.peer_addr().unwrap().to_string()
    }
}

pub trait BroadcastExt<S: session::Session> {
    #[allow(async_fn_in_trait)]
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error>;
}

impl<S: session::Session> BroadcastExt<S> for (TSocket<S>, TSocket<S>) {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Err(e) = self.0.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.1.clone().send(packet).await {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Tuple broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for (TSocket<S>, TSocket<S>, TSocket<S>) {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Err(e) = self.0.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.1.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.2.clone().send(packet).await {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Triple tuple broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for &(TSocket<S>, TSocket<S>) {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Err(e) = self.0.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.1.clone().send(packet).await {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Tuple broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for &(TSocket<S>, TSocket<S>, TSocket<S>) {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Err(e) = self.0.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.1.clone().send(packet.clone()).await {
            errors.push(e);
        }
        if let Err(e) = self.2.clone().send(packet).await {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Triple tuple broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for &[TSocket<S>] {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        for socket in self.iter() {
            if let Err(e) = socket.clone().send(packet.clone()).await {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Slice broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for [TSocket<S>] {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        for socket in self.iter() {
            if let Err(e) = socket.clone().send(packet.clone()).await {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Slice broadcast errors: {:?}",
                errors
            )))
        }
    }
}

impl<S: session::Session> BroadcastExt<S> for [&TSocket<S>] {
    async fn broadcast<P: Packet>(&self, packet: P) -> Result<(), Error> {
        let mut errors = Vec::new();

        for socket in self.iter() {
            let sock = *socket;
            if let Err(e) = sock.clone().send(packet.clone()).await {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Broadcast(format!(
                "Slice broadcast errors: {:?}",
                errors
            )))
        }
    }
}