use std::{
    io::{Read, Write},
    marker::PhantomData,
    net::TcpStream,
};

use crate::{
    encrypt::{Encryptor, KeyExchange},
    errors::Error,
    packet,
};

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

pub struct AsyncClient<P>
where
    P: packet::Packet,
{
    server: TcpStream,
    pub(crate) encryption: ClientEncryption,
    session_id: Option<String>,
    user: Option<String>,
    pass: Option<String>,
    _packet: PhantomData<P>,
}

impl<P> AsyncClient<P>
where
    P: packet::Packet,
{
    pub fn new(ip: &str, port: u16) -> Self {
        Self {
            server: TcpStream::connect((ip, port)).unwrap(),
            encryption: ClientEncryption::None,
            session_id: None,
            user: None,
            pass: None,
            _packet: PhantomData,
        }
    }

    pub fn with_credentials(mut self, user: &str, pass: &str) -> Self {
        self.user = Some(user.to_string());
        self.pass = Some(pass.to_string());
        self
    }

    pub async fn with_encryption_config(mut self, config: EncryptionConfig) -> std::io::Result<Self> {
        if !config.enabled {
            return Ok(self);
        }

        if let Some(key) = config.key {
            self.encryption = ClientEncryption::Encrypted(Encryptor::new(&key));
            return Ok(self);
        }

        if config.auto_key_exchange {
            self.establish_encrypted_connection()?;
        }

        // After encryption setup, handle authentication response
        if self.user.is_some() {
            match self.recv().await {
                Ok(mut response) => {
                    if let Some(id) = response.session_id(None) {
                        println!("Authentication successful, received session ID: {}", id);
                        self.session_id = Some(id);
                    }
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Authentication failed: {}", e),
                    ));
                }
            }
        }

        Ok(self)
    }

    fn establish_encrypted_connection(&mut self) -> std::io::Result<()> {
        println!("Starting encrypted connection setup");

        let key_exchange = KeyExchange::new();
        let public_key = key_exchange.get_public_key();

        println!("Sending public key");
        self.server.write_all(&public_key)?;
        self.server.flush()?;

        let mut server_public = [0u8; 32];
        println!("Waiting for server's public key");
        self.server.read_exact(&mut server_public)?;

        println!("Computing shared secret");
        let shared_secret = key_exchange.compute_shared_secret(&server_public);

        println!("Setting up encryption");
        self.encryption = ClientEncryption::Encrypted(Encryptor::new(&shared_secret));

        Ok(())
    }

    pub async fn send(&mut self, mut packet: P) -> Result<(), Error> {
        if let Some(id) = self.session_id.to_owned() {
            println!("Setting session ID: {}", id);
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
        self.server
            .write_all(&data)
            .expect("Failed to write packet.");
        self.server.flush().unwrap();
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<P, Error> {
        let mut buf = vec![0; 4096]; // Increased buffer size
        let n = self.server.read(&mut buf).expect("Failed to read buffer");

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        println!("Received {} bytes", n);
        buf.truncate(n);

        let mut packet = match &self.encryption {
            ClientEncryption::None => P::de(&buf),
            ClientEncryption::Encrypted(encryptor) => {
                println!("Decrypting packet");
                P::encrypted_de(&buf, encryptor)
            }
        };

        if let Some(id) = packet.session_id(None) {
            println!("Received session ID: {}", id);
            self.session_id = Some(id);
        }

        Ok(packet)
    }

    pub async fn send_recv(&mut self, packet: P) -> Result<P, Error> {
        self.send(packet).await?;
        self.recv().await
    }
}
