use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex},
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet::{Packet, PacketBody},
    phantom::{ClientConfig, PhantomPacket},
};

use super::client::{
    ClientEncryption, ClientMessage, ConnectionHandler, EncryptionConfig, KeepAliveConfig,
};

/// `AsyncPhantomClient` is a specialized network client for handling phantom protocol communications.
///
/// This client provides functionality for:
/// - Secure connections with optional encryption
/// - Session management
/// - Keep-alive mechanisms
/// - Packet relay operations
///
/// The phantom client acts as an intermediary, capable of relaying packets between
/// different network endpoints while maintaining security and session state.
///
/// # Fields
///
/// * `connection` - Handles the underlying network connection
/// * `encryption` - Manages the encryption state and operations
/// * `session_id` - Unique identifier for the current session
/// * `user` - Optional username for authentication
/// * `pass` - Optional password for authentication
/// * `keep_alive` - Configuration for keep-alive functionality
/// * `keep_alive_cold_start` - Indicates if this is the first keep-alive cycle
/// * `keep_alive_running` - Indicates if keep-alive is currently active
/// * `response_rx` - Channel for receiving network responses
pub struct AsyncPhantomClient {
    connection: ConnectionHandler,
    pub(crate) encryption: ClientEncryption,
    session_id: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    keep_alive: KeepAliveConfig,
    keep_alive_cold_start: Arc<Mutex<bool>>,
    keep_alive_running: Arc<AtomicBool>,
    response_rx: mpsc::Receiver<Vec<u8>>,
}

impl AsyncPhantomClient {
    /// Creates a new `AsyncPhantomClient` instance.
    ///
    /// Establishes a connection to the specified server and initializes all necessary
    /// components for network communication.
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address of the server
    /// * `port` - The port number to connect to
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - The initialized client or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Connection to server fails
    /// - Channel creation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnet::asynch::phantom_client::AsyncPhantomClient;
    ///
    /// async fn connect() -> Result<(), Error> {
    ///     let client = AsyncPhantomClient::new("127.0.0.1", 8080).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(ip: &str, port: u16) -> Result<Self, Error> {
        println!("Connecting to phantom server at {}:{}", ip, port);
        let server = tokio::net::TcpStream::connect((ip, port))
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;

        println!("Connected to phantom server");

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
                            println!("DEBUG: Writing {} bytes to phantom server", data.len());
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
                println!("DEBUG: Writer task ended");
            }
        });

        // Clone reader_tx before moving it
        let reader_tx_clone = reader_tx.clone();

        // Spawn reader task
        tokio::spawn({
            async move {
                println!("DEBUG: Reader task started");
                let mut buf = vec![0; 4096];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            println!("DEBUG: Read {} bytes from phantom server", n);
                            let data = buf[..n].to_vec();
                            if let Err(e) = reader_tx_clone.send(data).await {
                                eprintln!("Reader send error: {e}");
                                break;
                            }
                        }
                        Ok(n) => {
                            println!("DEBUG: Connection closed by phantom server ({} bytes)", n);
                            break;
                        }
                        Err(e) => {
                            eprintln!("Read error: {e}");
                            break;
                        }
                    }
                }
                println!("DEBUG: Reader task ended");
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
        })
    }

    /// Creates a new `AsyncPhantomClient` from a configuration object.
    ///
    /// This factory method creates a client with predefined settings from a
    /// `ClientConfig` structure, including encryption and authentication details.
    ///
    /// # Arguments
    ///
    /// * `config` - The client configuration object
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - The configured client or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Client creation fails
    /// - Encryption configuration fails
    ///
    /// # Panics
    ///
    /// Panics if encryption configuration fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use tnet::phantom::ClientConfig;
    ///
    /// async fn create_client(config: &ClientConfig) -> Result<AsyncPhantomClient, Error> {
    ///     let client = AsyncPhantomClient::from_client_config(config).await?;
    ///     Ok(client)
    /// }
    /// ```
    pub async fn from_client_config(config: &ClientConfig) -> Result<Self, Error> {
        let addr = &config.server_addr;
        let port = config.server_port;

        let mut client = Self::new(addr.as_str(), port)
            .await?
            .with_encryption_config(config.encryption_config.clone())
            .await
            .unwrap();

        if let Some(user) = &config.user {
            if let Some(pass) = &config.pass {
                client = client.with_credentials(user, pass);
            }
        }

        Ok(client)
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
    /// * `Self` - The modified client instance
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
    /// * `Self` - The modified client instance
    #[must_use]
    pub fn with_root_password(mut self, pass: &str) -> Self {
        self.user = Some("root".to_string());
        self.pass = Some(pass.to_string());
        self
    }

    /// Configures keep-alive functionality for the client.
    ///
    /// # Arguments
    ///
    /// * `config` - Keep-alive configuration settings
    ///
    /// # Returns
    ///
    /// * `Self` - The modified client instance
    #[must_use]
    pub const fn with_keep_alive(mut self, config: KeepAliveConfig) -> Self {
        self.keep_alive = config;
        self
    }

    /// Finalizes the client setup and establishes the connection.
    ///
    /// This method should be called after all configuration is complete and
    /// before starting normal operations.
    ///
    /// # Panics
    ///
    /// May panic if:
    /// - Send operation fails
    /// - Keep-alive initialization fails
    pub async fn finalize(&mut self) {
        let mut packet = PhantomPacket::ok();
        packet.body.username.clone_from(&self.user);
        packet.body.password.clone_from(&self.pass);
        self.send(packet).await.expect("Unknown Error Occured");
        if self.keep_alive.enabled {
            self.start_keepalive().unwrap();
        }
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
    /// Returns error if:
    /// - Key exchange fails
    /// - Authentication fails
    pub async fn with_encryption_config(
        mut self,
        config: EncryptionConfig,
    ) -> std::io::Result<Self> {
        if !config.enabled {
            return Ok(self);
        }

        if let Some(key) = config.key {
            self.encryption = ClientEncryption::Encrypted(Box::new(
                Encryptor::new(&key).expect("Failed to create encryptor"),
            ));
            return Ok(self);
        }

        if config.auto_key_exchange {
            self.establish_encrypted_connection().await?;
        }

        if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
            let mut auth_packet = PhantomPacket {
                header: "OK".to_string(),
                body: PacketBody::default(),
                ..Default::default()
            };
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
    ///
    /// # Returns
    ///
    /// * `std::io::Result<()>` - Success or failure of encryption setup
    async fn establish_encrypted_connection(&mut self) -> std::io::Result<()> {
        let key_exchange = KeyExchange::new();
        let public_key = key_exchange.get_public_key();

        // Send our public key
        self.connection
            .writer_tx
            .send(ClientMessage::Data(public_key.to_vec()))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

        // Receive server's public key
        let server_public = self.response_rx.recv().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection closed while waiting for server's public key",
            )
        })?;

        if server_public.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid server public key length",
            ));
        }

        let mut server_public_key = [0u8; 32];
        server_public_key.copy_from_slice(&server_public[..32]);

        let shared_secret = key_exchange.compute_shared_secret(&server_public_key);
        self.encryption = ClientEncryption::Encrypted(Box::new(
            Encryptor::new(&shared_secret).expect("Failed to create encryptor"),
        ));

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
    /// Returns error if:
    /// - Sending data fails
    /// - Channel send fails
    pub async fn send(&mut self, packet: PhantomPacket) -> Result<(), Error> {
        tokio::time::sleep(Duration::from_nanos(250_000)).await;

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

    /// Receives a packet from the server.
    ///
    /// # Returns
    ///
    /// * `Result<PhantomPacket, Error>` - The received packet or an error
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Connection is closed
    /// - Packet decryption fails
    pub async fn recv(&mut self) -> Result<PhantomPacket, Error> {
        tokio::time::sleep(Duration::from_nanos(250_000)).await;

        let data = self
            .response_rx
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)?;

        let packet = match &self.encryption {
            ClientEncryption::None => PhantomPacket::de(&data),
            ClientEncryption::Encrypted(encryptor) => PhantomPacket::encrypted_de(&data, encryptor),
        };

        if let Some(ses_id) = packet.body.session_id.clone() {
            self.session_id = Some(ses_id);
        }

        Ok(packet)
    }

    /// Sends a packet and waits for a response.
    ///
    /// # Arguments
    ///
    /// * `packet` - The packet to send
    ///
    /// # Returns
    ///
    /// * `Result<PhantomPacket, Error>` - The response packet or an error
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Send operation fails
    /// - Receive operation fails
    pub async fn send_recv(&mut self, packet: PhantomPacket) -> Result<PhantomPacket, Error> {
        self.send(packet).await?;
        self.recv().await
    }

    /// Sends a packet and waits for a response with debug output.
    ///
    /// This is a debug version of send_recv with more logging.
    pub async fn send_recv_with_debug(
        &mut self,
        packet: PhantomPacket,
    ) -> Result<PhantomPacket, Error> {
        println!("DEBUG: Sending phantom packet: {:?}", packet);

        self.send(packet).await.map_err(|e| {
            println!("DEBUG: Error sending packet: {:?}", e);
            e
        })?;

        println!("DEBUG: Waiting for response...");
        let response = self.recv().await.map_err(|e| {
            println!("DEBUG: Error receiving response: {:?}", e);
            e
        })?;

        println!("DEBUG: Received response: {:?}", response);
        Ok(response)
    }

    /// Starts the keep-alive mechanism.
    ///
    /// Initiates periodic keep-alive messages to maintain the connection.
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Success or failure of keep-alive initialization
    fn start_keepalive(&self) -> Result<(), Error> {
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

                let mut packet = PhantomPacket::ok();
                packet.body_mut().session_id = Some(session_id.clone());

                if cold_start.lock().await.to_owned() {
                    packet.body_mut().is_first_keep_alive_packet = Some(true);
                }

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

    /// Check if keepalive is running
    #[must_use]
    pub fn is_keepalive_running(&self) -> bool {
        self.keep_alive_running.load(Ordering::SeqCst)
    }

    /// Sends raw data to the server.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw data to send
    ///
    /// # Returns
    ///
    /// * `Result<(), Error>` - Success or failure of the send operation
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Encryption fails
    /// - Send operation fails
    ///
    /// # Panics
    ///
    /// May panic if:
    /// - Encryption fails
    /// - UTF-8 conversion fails
    pub async fn send_raw(&mut self, packet: Vec<u8>) -> Result<(), Error> {
        tokio::time::sleep(Duration::from_nanos(250_000)).await;

        let data = match &self.encryption {
            ClientEncryption::Encrypted(encryptor) => encryptor.encrypt(&packet).unwrap(),
            ClientEncryption::None => String::from_utf8(packet).unwrap(),
        }
        .as_bytes()
        .to_vec();

        self.connection
            .writer_tx
            .send(ClientMessage::Data(data))
            .await
            .map_err(|e| Error::Other(e.to_string()))
    }

    /// Receives raw data from the server.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - The received data or an error
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Connection is closed
    /// - Decryption fails
    ///
    /// # Panics
    ///
    /// May panic if:
    /// - Decryption fails
    /// - UTF-8 conversion fails
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, Error> {
        let data = match tokio::time::timeout(Duration::from_secs(5), self.response_rx.recv()).await
        {
            Ok(Some(data)) => data,
            Ok(None) => return Err(Error::ConnectionClosed),
            Err(_) => return Err(Error::Other("Timeout waiting for response".to_string())),
        };

        // For debugging
        println!("DEBUG: Received raw data of length: {}", data.len());

        // No need to sleep here as we're already waiting in the timeout
        let data = match &self.encryption {
            ClientEncryption::Encrypted(encryptor) => {
                let text = String::from_utf8_lossy(&data);
                match encryptor.decrypt(&text) {
                    Ok(decrypted) => decrypted,
                    Err(e) => return Err(Error::EncryptionError(e.to_string())),
                }
            }
            ClientEncryption::None => data,
        };

        Ok(data)
    }

    /// Sends raw data and waits for a raw response.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw data to send
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, Error>` - The raw response data or an error
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Send operation fails
    /// - Receive operation fails
    pub async fn send_recv_raw(&mut self, packet: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.send_raw(packet).await?;
        self.recv_raw().await
    }
}
