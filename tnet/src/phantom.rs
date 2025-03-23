//! Types and utilities for the phantom relay system.
//!
//! The phantom system enables network traffic relay through an intermediary server,
//! allowing clients to communicate with servers they might not be able to reach directly.
//! This is useful for creating proxies, gateways, and other intermediary network components.

use serde::{Deserialize, Serialize};

use crate::{
    errors::Error,
    packet::{Packet, PacketBody},
    prelude::EncryptionConfig,
};

/// Configuration for phantom relay operations in a const context.
///
/// `PhantomConf` provides a way to define relay configuration with string literals
/// and other const-compatible types. It can be converted to a `ClientConfig` for use
/// with the phantom client system.
///
/// # Fields
///
/// * `header` - The packet header for relay operations
/// * `username` - Optional username for authentication
/// * `password` - Optional password for authentication
/// * `server_addr` - The target server address
/// * `server_port` - The target server port
/// * `enc_conf` - Encryption configuration for the connection
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// let phantom_conf = PhantomConf {
///     header: "relay",
///     username: Some("user"),
///     password: Some("pass"),
///     server_addr: "target.server.com",
///     server_port: 8080,
///     enc_conf: EncryptionConfig::default_on(),
/// };
///
/// // Convert to ClientConfig
/// let client_config = ClientConfig::from(&phantom_conf);
/// ```
#[derive(Debug, Clone)]
pub struct PhantomConf<'a> {
    pub header: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub server_addr: &'a str,
    pub server_port: u16,
    pub enc_conf: EncryptionConfig,
}

impl<'a> From<&'a ClientConfig> for PhantomConf<'a> {
    fn from(value: &'a ClientConfig) -> Self {
        Self {
            header: "relay",
            enc_conf: value.encryption_config.clone(),
            username: value.user.as_deref(),
            password: value.pass.as_deref(),
            server_addr: value.server_addr.as_str(),
            server_port: value.server_port,
        }
    }
}

/// Configuration for a phantom client connection.
///
/// `ClientConfig` contains all the information needed for a phantom client to
/// connect to a target server. It is typically embedded in a `PhantomPacket`
/// to instruct a phantom server where to relay the packet.
///
/// # Fields
///
/// * `encryption_config` - Encryption settings for the connection
/// * `server_addr` - The target server address
/// * `server_port` - The target server port
/// * `user` - Optional username for authentication
/// * `pass` - Optional password for authentication
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// let client_config = ClientConfig {
///     encryption_config: EncryptionConfig::default_on(),
///     server_addr: "target.server.com".to_string(),
///     server_port: 8080,
///     user: Some("username".to_string()),
///     pass: Some("password".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub encryption_config: EncryptionConfig,
    pub server_addr: String,
    pub server_port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

impl From<&PhantomConf<'_>> for ClientConfig {
    fn from(conf: &PhantomConf<'_>) -> Self {
        Self {
            encryption_config: conf.enc_conf.clone(),
            server_addr: conf.server_addr.to_string(),
            server_port: conf.server_port,
            user: conf.username.map(|v| v.to_string()),
            pass: conf.password.map(|v| v.to_string()),
        }
    }
}

/// Packet type used for relay operations in the phantom system.
///
/// `PhantomPacket` encapsulates a serialized packet and routing information for
/// relay operations. It is used to transport packets between a client, phantom server,
/// and target server.
///
/// # Fields
///
/// * `header` - The packet header
/// * `body` - The packet body
/// * `sent_packet` - Optional serialized packet to be sent to the target server
/// * `recv_packet` - Optional serialized response from the target server
/// * `client_config` - Optional configuration for connecting to the target server
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
/// use serde::{Serialize, Deserialize};
///
/// // Define a packet type to be relayed
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// struct MyPacket {
///     message: String
/// }
///
/// // Create phantom configuration
/// let conf = PhantomConf {
///     header: "relay",
///     username: Some("user"),
///     password: Some("pass"),
///     server_addr: "target.com",
///     server_port: 8080,
///     enc_conf: EncryptionConfig::default(),
/// };
///
/// // Create the packet to relay
/// let my_packet = MyPacket { message: "Hello".to_string() };
///
/// // Produce a phantom packet with the configuration and underlying packet
/// let phantom_packet = PhantomPacket::produce_from_conf(&conf, &my_packet);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomPacket {
    pub header: String,
    pub body: PacketBody,
    pub sent_packet: Option<String>,
    pub recv_packet: Option<String>,
    pub client_config: Option<ClientConfig>,
}

impl PhantomPacket {
    /// Creates a `PhantomPacket` from configuration and an underlying packet.
    ///
    /// This method serializes the provided packet and packages it with the
    /// connection configuration for relay operations.
    ///
    /// # Type Parameters
    ///
    /// * `A` - Any type that implements `Serialize`
    ///
    /// # Arguments
    ///
    /// * `conf` - The phantom configuration
    /// * `underlying_packet` - The packet to be relayed
    ///
    /// # Returns
    ///
    /// * A new `PhantomPacket` instance
    ///
    /// # Panics
    ///
    /// This function will panic if the underlying packet cannot be serialized to JSON.
    pub fn produce_from_conf<A: Serialize>(conf: &PhantomConf, underlying_packet: A) -> Self {
        let up_ser = serde_json::to_string(&underlying_packet)
            .expect("Failed to produce PhantomPacket from UnderlyingPacket, cannot be converted to string json.");

        Self {
            header: conf.header.to_string(),
            client_config: Some(ClientConfig::from(conf)),
            sent_packet: Some(up_ser),
            ..Default::default()
        }
    }

    /// Creates a new response packet for relay operations.
    ///
    /// # Returns
    ///
    /// * A new `PhantomPacket` configured for relay responses
    #[must_use]
    pub fn response() -> Self {
        Self {
            header: "relay-response".to_string(),
            ..Default::default()
        }
    }

    /// Deserializes the received packet string into the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The packet type to deserialize into
    ///
    /// # Returns
    ///
    /// * `Option<T>` - The deserialized packet or None if deserialization fails
    ///
    /// # Example
    ///
    /// ```rust
    /// // Assuming a PhantomPacket with a response from the target server
    /// if let Some(response) = phantom_packet.cast_recv_packet::<MyPacket>() {
    ///     println!("Received response: {:?}", response);
    /// }
    /// ```
    pub fn cast_recv_packet<T: Packet>(&self) -> Option<T> {
        self.recv_packet
            .as_ref()
            .and_then(|packet_str| serde_json::from_str::<T>(packet_str).ok())
    }
}

impl Packet for PhantomPacket {
    fn header(&self) -> String {
        self.header.clone()
    }

    fn body(&self) -> PacketBody {
        self.body.clone()
    }

    fn body_mut(&mut self) -> &mut PacketBody {
        &mut self.body
    }

    fn ok() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody::default(),
            sent_packet: None,
            recv_packet: None,
            client_config: None,
        }
    }

    fn error(error: Error) -> Self {
        Self {
            header: "ERROR".to_string(),
            body: PacketBody::with_error_string(error.to_string().as_str()),
            ..Default::default()
        }
    }

    fn keep_alive() -> Self {
        Self {
            header: "KeepAlive".to_string(),
            ..Default::default()
        }
    }
}

impl Default for PhantomPacket {
    fn default() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody::default(),
            sent_packet: None,
            recv_packet: None,
            client_config: None,
        }
    }
}
