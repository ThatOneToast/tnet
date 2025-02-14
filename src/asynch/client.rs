use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex},
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet::{self, Packet},
    phantom::PhantomPacket,
};

use super::client_ext::AsyncClientRef;

/// Represents the encryption state of a client connection.
///
/// This enum defines whether a connection is encrypted and, if so,
/// contains the encryption provider.
///
/// # Variants
///
/// * `None` - No encryption is being used
/// * `Encrypted` - Connection is encrypted using the provided encryptor
#[derive(Clone)]
pub enum ClientEncryption {
    None,
    Encrypted(Box<Encryptor>),
}

/// Configuration settings for client encryption.
///
/// Defines how the client should handle encryption, including whether it's enabled,
/// what key to use, and whether to perform automatic key exchange.
///
/// # Fields
///
/// * `enabled` - Whether encryption is enabled
/// * `key` - Optional encryption key (32 bytes)
/// * `auto_key_exchange` - Whether to automatically perform key exchange
///
/// # Example
///
/// ```rust
/// use tnet::asynch::client::EncryptionConfig;
///
/// let config = EncryptionConfig {
///     enabled: true,
///     key: Some([0u8; 32]),
///     auto_key_exchange: true,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub key: Option<[u8; 32]>,
    pub auto_key_exchange: bool,
}

impl EncryptionConfig {
    /// Creates a new configuration with encryption enabled and automatic key exchange.
    #[must_use]
    pub const fn default_on() -> Self {
        Self {
            enabled: true,
            key: None,
            auto_key_exchange: true,
        }
    }

    /// Creates a new configuration with encryption disabled (const version).
    #[must_use]
    pub const fn default_const() -> Self {
        Self {
            enabled: false,
            key: None,
            auto_key_exchange: true,
        }
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key: None,
            auto_key_exchange: true,
        }
    }
}

/// Configuration settings for keep-alive functionality.
///
/// Defines whether and how often keep-alive messages should be sent
/// to maintain the connection.
///
/// # Fields
///
/// * `enabled` - Whether keep-alive is enabled
/// * `interval` - Time in seconds between keep-alive messages
#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    pub enabled: bool,
    pub interval: u64,
}

impl KeepAliveConfig {
    /// Creates a new configuration with keep-alive enabled and a 30-second interval.
    #[must_use]
    pub const fn default_on() -> Self {
        Self {
            enabled: true,
            interval: 30,
        }
    }
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 30,
        }
    }
}

/// Messages that can be sent through the client's internal channels.
///
/// Used for internal communication between different parts of the client.
///
/// # Variants
///
/// * `Data` - Regular data packet
/// * `Keepalive` - Keep-alive message
/// * `Ping` - Connection test with response channel
#[derive(Debug)]
pub enum ClientMessage {
    Data(Vec<u8>),
    Keepalive(Vec<u8>),
    Ping(tokio::sync::oneshot::Sender<bool>),
}

/// Handles the connection's I/O channels.
///
/// Provides channels for sending and receiving data through the connection.
///
/// # Fields
///
/// * `writer_tx` - Channel for sending data
/// * `reader_tx` - Channel for receiving data
#[derive(Debug)]
pub struct ConnectionHandler {
    pub writer_tx: mpsc::Sender<ClientMessage>,
    pub reader_tx: mpsc::Sender<Vec<u8>>,
}

/// Type alias for message handling functions.
pub type MessageHandler<P> = Box<dyn Fn(&P) -> bool + Send + Sync>;

/// Type alias for broadcast handling functions.
pub type BroadcastHandler<P> = Box<dyn Fn(&P) + Send + Sync>;

/// The main asynchronous client implementation.
///
/// Provides a full-featured network client with support for:
/// - Encrypted communications
/// - Session management
/// - Authentication
/// - Keep-alive mechanisms
/// - Broadcast handling
///
/// # Type Parameters
///
/// * `P` - The packet type used for communication
///
/// # Fields
///
/// * `connection` - Handles the underlying network connection
/// * `encryption` - Manages encryption state
/// * `session_id` - Current session identifier
/// * `user` - Username for authentication
/// * `pass` - Password for authentication
/// * `keep_alive` - Keep-alive configuration
/// * `keep_alive_cold_start` - Indicates first keep-alive cycle
/// * `keep_alive_running` - Keep-alive active status
/// * `response_rx` - Channel for receiving responses
/// * `broadcast_handler` - Optional handler for broadcast messages
pub struct AsyncClient<P>
where
    P: packet::Packet,
{
    connection: ConnectionHandler,
    pub(crate) encryption: ClientEncryption,
    session_id: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    keep_alive: KeepAliveConfig,
    keep_alive_cold_start: Arc<Mutex<bool>>,
    keep_alive_running: Arc<AtomicBool>,
    response_rx: mpsc::Receiver<Vec<u8>>,
    broadcast_handler: Option<Arc<BroadcastHandler<P>>>,
    _packet: PhantomData<P>,
}

impl<P> AsyncClient<P>
where
    P: packet::Packet,
{
    /// Creates a new `AsyncClient` instance.
    ///
    /// Establishes a connection to the specified server and initializes all necessary
    /// components for network communication.
    ///
    /// # Arguments
    ///
    /// * `ip` - Server IP address
    /// * `port` - Server port number
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - The initialized client or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Unable to establish TCP connection
    /// - IO error occurs during connection setup
    ///
    /// # Example
    ///
    /// ```rust
    /// async fn connect() -> Result<AsyncClient<MyPacket>, Error> {
    ///     let client = AsyncClient::new("127.0.0.1", 8080).await?;
    ///     Ok(client)
    /// }
    /// ```
    pub async fn new(ip: &str, port: u16) -> Result<Self, Error> {
        // Connect with error handling
        let server = tokio::net::TcpStream::connect((ip, port))
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;

        let (writer_tx, mut writer_rx) = mpsc::channel::<ClientMessage>(32);
        let (reader_tx, reader_rx) = mpsc::channel::<Vec<u8>>(32);

        // Split the connection
        let (mut read_half, mut write_half) = server.into_split();

        // Spawn writer task
        tokio::spawn({
            async move {
                while let Some(msg) = writer_rx.recv().await {
                    match msg {
                        ClientMessage::Data(data) | ClientMessage::Keepalive(data) => {
                            if let Err(e) = write_half.write_all(&data).await {
                                eprintln!("Write error: {e}");
                                break;
                            }
                            if let Err(e) = write_half.flush().await {
                                eprintln!("Flush error: {e}");
                                break;
                            }
                        }
                        ClientMessage::Ping(response) => {
                            let _ = response.send(true);
                        }
                    }
                }
            }
        });

        // Clone reader_tx before moving it
        let reader_tx_clone = reader_tx.clone();

        // Spawn reader task
        tokio::spawn({
            async move {
                let mut buf = vec![0; 4096];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let data = buf[..n].to_vec();
                            if let Err(e) = reader_tx_clone.send(data).await {
                                eprintln!("Reader send error: {e}");
                                break;
                            }
                        }
                        Ok(n) => {
                            if n == 0 {
                                println!("Connection closed by peer");
                            }
                            break;
                        }
                        Err(e) => {
                            eprintln!("Read error: {e}");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            connection: ConnectionHandler {
                writer_tx,
                reader_tx,
            },
            encryption: ClientEncryption::None,
            session_id: None,
            user: None,
            pass: None,
            keep_alive: KeepAliveConfig::default(),
            keep_alive_cold_start: Arc::new(Mutex::new(true)),
            keep_alive_running: Arc::new(AtomicBool::new(false)),
            response_rx: reader_rx,
            broadcast_handler: None,
            _packet: PhantomData,
        })
    }

    /// Adds authentication credentials to the client.
    ///
    /// # Arguments
    ///
    /// * `user` - Username for authentication
    /// * `pass` - Password for authentication
    ///
    /// # Returns
    ///
    /// * `Self` - The configured client instance
    #[must_use]
    pub fn with_credentials(mut self, user: &str, pass: &str) -> Self {
        self.user = Some(user.to_string());
        self.pass = Some(pass.to_string());
        self
    }

    /// Sets up root authentication credentials.
    ///
    /// # Arguments
    ///
    /// * `pass` - Root password for authentication
    ///
    /// # Returns
    ///
    /// * `Self` - The configured client instance
    #[must_use]
    pub fn with_root_password(mut self, pass: &str) -> Self {
        self.user = Some("root".to_string());
        self.pass = Some(pass.to_string());
        self
    }

    /// Configures keep-alive functionality.
    ///
    /// # Arguments
    ///
    /// * `config` - Keep-alive configuration settings
    ///
    /// # Returns
    ///
    /// * `Self` - The configured client instance
    #[must_use]
    pub const fn with_keep_alive(mut self, config: KeepAliveConfig) -> Self {
        self.keep_alive = config;
        self
    }

    /// Adds a handler for broadcast messages.
    ///
    /// # Arguments
    ///
    /// * `handler` - Function to handle broadcast messages
    ///
    /// # Returns
    ///
    /// * `Self` - The configured client instance
    #[must_use]
    pub fn with_broadcast_handler(mut self, handler: BroadcastHandler<P>) -> Self {
        self.broadcast_handler = Some(Arc::new(handler));
        self
    }

    /// Finalizes the client setup and establishes the connection.
    ///
    /// This method should be called after all configuration is complete and
    /// before starting normal operations.
    ///
    /// # Panics
    ///
    /// Panics if there is an error sending the initial packet or starting keepalive.
    pub async fn finalize(&mut self) {
        self.send_recv(P::ok())
            .await
            .expect("Unknown Error Occured");

        if self.keep_alive.enabled {
            self.start_keepalive().unwrap();
        }
    }

    /// Finalizes the client setup using a phantom packet.
    ///
    /// # Panics
    ///
    /// Panics if there is an error sending the phantom packet or starting keepalive.
    pub async fn finalize_phantom(&mut self) {
        self.send_phantom_packet(PhantomPacket::ok()).await.unwrap();

        if self.keep_alive.enabled {
            self.start_keepalive().unwrap();
        }
    }

    /// Converts this client into a reference-counted version.
    ///
    /// # Returns
    ///
    /// * `AsyncClientRef<P>` - A reference-counted version of the client
    #[must_use]
    pub fn convert_to_ref(self) -> AsyncClientRef<P> {
        AsyncClientRef::new(self)
    }

    /// Configures encryption for the client.
    ///
    /// # Arguments
    ///
    /// * `config` - Encryption configuration settings
    ///
    /// # Returns
    ///
    /// * `std::io::Result<Self>` - The configured client or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key exchange fails
    /// - Authentication fails
    /// - No session ID is received
    pub async fn with_encryption_config(
        mut self,
        config: EncryptionConfig,
    ) -> std::io::Result<Self> {
        if !config.enabled {
            return Ok(self);
        }

        if let Some(key) = config.key {
            self.encryption = ClientEncryption::Encrypted(Box::new(Encryptor::new(&key)));
            return Ok(self);
        }

        if config.auto_key_exchange {
            self.establish_encrypted_connection().await?;
        }

        // After encryption setup, handle authentication response
        if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
            let mut auth_packet = P::ok();
            auth_packet.body_mut().username = Some(user.clone());
            auth_packet.body_mut().password = Some(pass.clone());

            match self.send_recv(auth_packet).await {
                Ok(mut response) => {
                    if let Some(id) = response.session_id(None) {
                        self.session_id = Some(id);
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "No session ID received".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                }
            }
        }

        Ok(self)
    }

    /// Establishes an encrypted connection with the server.
    ///
    /// Performs key exchange and sets up encryption for secure communication.
    async fn establish_encrypted_connection(&mut self) -> std::io::Result<()> {
        let key_exchange = KeyExchange::new();
        let public_key = key_exchange.get_public_key();

        // Send length-prefixed public key
        let mut data = Vec::new();
        data.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
        data.extend_from_slice(&public_key);

        self.connection
            .writer_tx
            .send(ClientMessage::Data(data))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        // Receive server's length prefix
        let mut server_response = Vec::new();
        while server_response.len() < 4 {
            if let Some(data) = self.response_rx.recv().await {
                server_response.extend(data);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Connection closed while reading length prefix",
                ));
            }
        }

        let length = u32::from_be_bytes(server_response[0..4].try_into().unwrap()) as usize;

        // Continue receiving until we have the full key
        while server_response.len() < 4 + length {
            if let Some(data) = self.response_rx.recv().await {
                server_response.extend(data);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Connection closed while reading public key",
                ));
            }
        }

        let mut server_public_key = [0u8; 32];
        server_public_key.copy_from_slice(&server_response[4..4 + length]);

        let shared_secret = key_exchange.compute_shared_secret(&server_public_key);
        self.encryption = ClientEncryption::Encrypted(Box::new(Encryptor::new(&shared_secret)));

        Ok(())
    }

    /// Sends a packet to the server.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to send
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Success or failure of the send operation
    ///
    /// # Errors
    ///
    /// Returns an error if sending the packet fails
    pub async fn send(&mut self, mut packet: P) -> Result<(), Error> {
        tokio::time::sleep(Duration::from_nanos(500_000)).await;

        if let Some(id) = self.session_id.clone() {
            packet.session_id(Some(id));
        } else if let Some(user) = &self.user {
            if let Some(pass) = &self.pass {
                packet.body_mut().username = Some(user.to_owned());
                packet.body_mut().password = Some(pass.to_owned());
            }
        }

        let data = match &self.encryption {
            ClientEncryption::None => packet.ser(),
            ClientEncryption::Encrypted(encryptor) => packet.encrypted_ser(encryptor),
        };

        self.connection
            .writer_tx
            .send(ClientMessage::Data(data))
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    /// Sends a phantom packet to the server.
    ///
    /// # Arguments
    ///
    /// * `packet` - The phantom packet to send
    ///
    /// # Returns
    ///
    /// * `Result<PhantomPacket, Error>` - The response packet or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sending the packet fails
    /// - Connection is closed
    pub async fn send_phantom_packet(
        &mut self,
        mut packet: PhantomPacket,
    ) -> Result<PhantomPacket, Error> {
        tokio::time::sleep(Duration::from_nanos(500_000)).await;

        if let Some(id) = self.session_id.clone() {
            packet.session_id(Some(id));
        } else if let Some(user) = &self.user {
            if let Some(pass) = &self.pass {
                packet.body_mut().username = Some(user.to_owned());
                packet.body_mut().password = Some(pass.to_owned());
            }
        }

        let data = match &self.encryption {
            ClientEncryption::None => packet.ser(),
            ClientEncryption::Encrypted(encryptor) => packet.encrypted_ser(encryptor),
        };

        self.connection
            .writer_tx
            .send(ClientMessage::Data(data))
            .await
            .map_err(|e| Error::Other(e.to_string()))?;

        tokio::time::sleep(Duration::from_nanos(750)).await;

        let data = self
            .response_rx
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)?;

        let packet = match &self.encryption {
            ClientEncryption::None => PhantomPacket::de(&data),
            ClientEncryption::Encrypted(encryptor) => PhantomPacket::encrypted_de(&data, encryptor),
        };

        Ok(packet)
    }

    /// Receives a packet from the server.
    ///
    /// # Returns
    ///
    /// * `Result<P, Error>` - The received packet or an error
    ///
    /// # Errors
    ///
    /// Returns an error if the connection is closed
    pub async fn recv(&mut self) -> Result<P, Error> {
        loop {
            let data = self
                .response_rx
                .recv()
                .await
                .ok_or(Error::ConnectionClosed)?;

            let mut packet = match &self.encryption {
                ClientEncryption::None => P::de(&data),
                ClientEncryption::Encrypted(encryptor) => P::encrypted_de(&data, encryptor),
            };

            // Check if this is a broadcast packet
            if packet.is_broadcasting() {
                if let Some(handler) = &self.broadcast_handler {
                    let handler = handler.clone();
                    handler(&packet);
                }
                continue;
            }

            if let Some(id) = packet.session_id(None) {
                self.session_id = Some(id);
            }

            return Ok(packet);
        }
    }

    /// Sends a packet and waits for a response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to send
    ///
    /// # Returns
    ///
    /// * `Result<P, Error>` - The response packet or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Sending the packet fails
    /// - Receiving the response fails
    pub async fn send_recv(&mut self, packet: P) -> Result<P, Error> {
        self.send(packet).await?;
        self.recv().await
    }

    /// Starts the keep-alive mechanism.
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Success or failure of keep-alive initialization
    fn start_keepalive<'a>(&self) -> Result<(), Error>
    where
        P: 'a,
    {
        if !self.keep_alive.enabled || self.keep_alive_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        let session_id = self
            .session_id
            .clone()
            .ok_or_else(|| Error::Other("Cannot start keepalive without session ID".to_string()))?;

        let interval = self.keep_alive.interval;
        let encryption = self.encryption.clone();
        let keep_alive_running = self.keep_alive_running.clone();
        let writer_tx = self.connection.writer_tx.clone();
        let cold_start = self.keep_alive_cold_start.clone();
        keep_alive_running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval));

            while keep_alive_running.load(Ordering::SeqCst) {
                interval.tick().await;

                let mut packet = if cold_start.lock().await.to_owned() {
                    let mut packet = P::ok();
                    packet.body_mut().session_id = Some(session_id.clone());
                    packet.body_mut().is_first_keep_alive_packet = Some(true);

                    packet
                } else {
                    let mut packet = P::ok();
                    packet.body_mut().session_id = Some(session_id.clone());

                    packet
                };

                packet.session_id(Some(session_id.clone()));

                let data = match &encryption {
                    ClientEncryption::None => packet.ser(),
                    ClientEncryption::Encrypted(encryptor) => packet.encrypted_ser(encryptor),
                };

                if writer_tx
                    .send(ClientMessage::Keepalive(data))
                    .await
                    .is_err()
                {
                    keep_alive_running.store(false, Ordering::SeqCst);
                    break;
                }
            }
        });

        Ok(())
    }

    /// Stops the keep-alive mechanism.
    pub fn stop_keepalive(&mut self) {
        self.keep_alive_running.store(false, Ordering::SeqCst);
    }

    /// Checks if keep-alive is currently active.
    ///
    /// # Returns
    ///
    /// * `bool` - True if keep-alive is running, false otherwise
    #[must_use]
    pub fn is_keepalive_running(&self) -> bool {
        self.keep_alive_running.load(Ordering::SeqCst)
    }
}
