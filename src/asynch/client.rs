use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use futures::future::BoxFuture;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet,
};

#[derive(Clone)]
pub enum ClientEncryption {
    None,
    Encrypted(Encryptor),
}

#[derive(Debug)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub key: Option<[u8; 32]>,
    pub auto_key_exchange: bool,
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

#[derive(Debug, Clone)]
pub struct KeepAliveConfig {
    pub enabled: bool,
    pub interval: u64, // in seconds
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: 30,
        }
    }
}

#[derive(Debug)]
enum ClientMessage {
    Data(Vec<u8>),
    Keepalive(Vec<u8>),
    Ping(tokio::sync::oneshot::Sender<bool>),
}

#[derive(Debug)]
struct ConnectionHandler {
    writer_tx: mpsc::Sender<ClientMessage>,
    reader_tx: mpsc::Sender<Vec<u8>>,
}

pub type MessageHandler<P> = Box<dyn Fn(&P) -> bool + Send + Sync>;
pub type BroadcastHandler<P> = Box<dyn Fn(&P) -> BoxFuture<'static, ()> + Send + Sync>;

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
    keep_alive_running: Arc<AtomicBool>,
    response_rx: mpsc::Receiver<Vec<u8>>,
    broadcast_handler: Option<BroadcastHandler<P>>,
    _packet: PhantomData<P>,
}

impl<P> AsyncClient<P>
where
    P: packet::Packet,
{
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
                                eprintln!("Write error: {}", e);
                                break;
                            }
                            if let Err(e) = write_half.flush().await {
                                eprintln!("Flush error: {}", e);
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
                                eprintln!("Reader send error: {}", e);
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
                            eprintln!("Read error: {}", e);
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
            keep_alive_running: Arc::new(AtomicBool::new(false)),
            response_rx: reader_rx,
            broadcast_handler: None,
            _packet: PhantomData,
        })
    }

    pub fn with_credentials(mut self, user: &str, pass: &str) -> Self {
        self.user = Some(user.to_string());
        self.pass = Some(pass.to_string());
        self
    }

    pub async fn is_connected(&mut self) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Err(_) = self
            .connection
            .writer_tx
            .send(ClientMessage::Ping(tx))
            .await
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    pub fn with_keep_alive(mut self, config: KeepAliveConfig) -> Self {
        self.keep_alive = config;
        self
    }

    pub fn with_broadcast_handler(mut self, handler: BroadcastHandler<P>) -> Self {
        self.broadcast_handler = Some(handler);
        self
    }

    pub async fn with_encryption_config(
        mut self,
        config: EncryptionConfig,
    ) -> std::io::Result<Self> {
        if !config.enabled {
            return Ok(self);
        }

        if let Some(key) = config.key {
            self.encryption = ClientEncryption::Encrypted(Encryptor::new(&key));
            return Ok(self);
        }

        if config.auto_key_exchange {
            self.establish_encrypted_connection().await?;
        }

        // After encryption setup, handle authentication response
        if let (Some(user), Some(pass)) = (&self.user, &self.pass) {
            let mut auth_packet = P::ok(); // or create a specific auth packet type
            auth_packet.body_mut().username = Some(user.clone());
            auth_packet.body_mut().password = Some(pass.clone());
            self.send(auth_packet)
                .await
                .expect("Failed to send auth packet");

            // Wait for authentication response
            match self.recv().await {
                Ok(mut response) => {
                    if let Some(id) = response.session_id(None) {
                        println!("Authentication successful, received session ID: {}", id);
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

    async fn establish_encrypted_connection(&mut self) -> std::io::Result<()> {
        println!("Starting encrypted connection setup");

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

        println!("Computing shared secret");
        let shared_secret = key_exchange.compute_shared_secret(&server_public_key);

        println!("Setting up encryption");
        self.encryption = ClientEncryption::Encrypted(Encryptor::new(&shared_secret));

        Ok(())
    }

    pub async fn send(&mut self, mut packet: P) -> Result<(), Error> {
        tokio::time::sleep(Duration::from_nanos(500_000)).await;
        if !self.is_connected().await {
            return Err(Error::ConnectionClosed);
        }

        if let Some(id) = self.session_id.to_owned() {
            packet.session_id(Some(id));
        } else if let Some(user) = &self.user {
            if let Some(pass) = &self.pass {
                packet.body_mut().username = Some(user.to_owned());
                packet.body_mut().password = Some(pass.to_owned());
            }
        }

        let data = match &self.encryption {
            ClientEncryption::None => packet.ser(),
            ClientEncryption::Encrypted(encryptor) => {
                println!("Encrypting packet");
                packet.encrypted_ser(encryptor)
            }
        };

        println!("Sending {} bytes", data.len());
        self.connection
            .writer_tx
            .send(ClientMessage::Data(data))
            .await
            .map_err(|e| Error::Other(e.to_string()))?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<P, Error> {
        loop {
            let data = self
                .response_rx
                .recv()
                .await
                .ok_or_else(|| Error::ConnectionClosed)?;

            let mut packet = match &self.encryption {
                ClientEncryption::None => P::de(&data),
                ClientEncryption::Encrypted(encryptor) => {
                    println!("Decrypting packet");
                    P::encrypted_de(&data, encryptor)
                }
            };

            // Check if this is a broadcast packet
            if packet.is_broadcasting() {
                if let Some(handler) = &self.broadcast_handler {
                    // Call the async handler
                    handler(&packet).await;
                }
                // Continue listening for non-broadcast packets
                continue;
            }

            if let Some(id) = packet.session_id(None) {
                println!("Received session ID: {}", id);
                self.session_id = Some(id);
            }

            return Ok(packet);
        }
    }

    pub async fn send_recv(&mut self, packet: P) -> Result<P, Error> {
        self.send(packet).await?;
        self.recv().await
    }

    pub async fn start_keepalive(&mut self) -> Result<(), Error>
    where
        P: 'static,
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
        keep_alive_running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval));

            while keep_alive_running.load(Ordering::SeqCst) {
                interval.tick().await;

                let mut packet = P::keep_alive();
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
                println!("Keepalive packet sent");
            }
        });

        Ok(())
    }

    pub async fn send_keepalive_packet(&mut self) -> Result<(), Error> {
        let mut packet = P::ok();
        packet.body_mut().is_first_keep_alive_packet = Some(true);
        Ok(())
    }

    pub async fn stop_keepalive(&mut self) {
        self.keep_alive_running.store(false, Ordering::SeqCst);
    }

    // Add a method to check if keepalive is running
    pub fn is_keepalive_running(&self) -> bool {
        self.keep_alive_running.load(Ordering::SeqCst)
    }
}
