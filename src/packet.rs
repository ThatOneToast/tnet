use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{encrypt::Encryptor, errors::Error};

/// Represents the body of a packet containing optional fields for authentication,
/// session management, error handling, and packet type identification.
///
/// This body is usually handled for you.
///
/// # Fields
///
/// * `username`: Optional username for authentication
/// * `password`: Optional password for authentication
/// * `session_id`: Optional session identifier for maintaining state
/// * `error_string`: Optional error message for error handling
/// * `is_first_keep_alive_packet`: Optional flag for initial keepalive packets
/// * `is_broadcast_packet`: Optional flag for broadcast messages
///
/// # Example
///
/// ```rust
/// use tnet::packet::PacketBody;
///
/// let body = PacketBody {
///     username: Some("user123".to_string()),
///     password: Some("pass123".to_string()),
///     session_id: None,
///     error_string: None,
///     is_first_keep_alive_packet: Some(false),
///     is_broadcast_packet: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PacketBody {
    pub username: Option<String>,
    pub password: Option<String>,
    pub session_id: Option<String>,
    pub error_string: Option<String>,
    pub is_first_keep_alive_packet: Option<bool>,
    pub is_broadcast_packet: Option<bool>,
}

impl PacketBody {
    /// Creates a new empty packet body with all fields set to None.
    ///
    /// # Returns
    ///
    /// * A new `PacketBody` instance
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new packet body configured for broadcasting.
    ///
    /// # Returns
    ///
    /// * A new `PacketBody` instance with `is_broadcast_packet` set to true
    #[must_use]
    pub fn broadcasting() -> Self {
        Self {
            is_broadcast_packet: Some(true),
            ..Default::default()
        }
    }

    /// Creates a new packet body with an error message.
    ///
    /// # Arguments
    ///
    /// * `string`: The error message to include in the packet
    ///
    /// # Returns
    ///
    /// * A new `PacketBody` instance with the specified error message
    #[must_use]
    pub fn with_error_string(string: impl ToString) -> Self {
        Self {
            error_string: Some(string.to_string()),
            ..Default::default()
        }
    }
}

/// The `Packet` trait defines the interface for network communication packets.
/// It provides methods for serialization, deserialization, encryption, and basic packet operations.
///
/// # Type Requirements
///
/// The implementing type must be:
/// * Serializable (`Serialize`)
/// * Deserializable (`DeserializeOwned`)
/// * Cloneable (`Clone`)
/// * Thread-safe (`Send + Sync`)
///
/// # Example Implementation
///
/// ```rust
/// use serde::{Serialize, Deserialize};
/// use tnet::packet::{Packet, PacketBody};
/// use tnet::errors::Error;
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// struct MyPacket {
///     header: String,
///     body: PacketBody,
/// }
///
/// impl Packet for MyPacket {
///     fn header(&self) -> String {
///         self.header.clone()
///     }
///
///     fn body(&self) -> PacketBody {
///         self.body.clone()
///     }
///
///     fn body_mut(&mut self) -> &mut PacketBody {
///         &mut self.body
///     }
///
///     fn ok() -> Self {
///         Self {
///             header: "OK".to_string(),
///             body: PacketBody::default(),
///         }
///     }
///
///     fn error(error: Error) -> Self {
///         Self {
///             header: "ERROR".to_string(),
///             body: PacketBody::with_error_string(&error.to_string()),
///         }
///     }
///
///     fn keep_alive() -> Self {
///         Self {
///             header: "KEEPALIVE".to_string(),
///             body: PacketBody::default(),
///         }
///     }
/// }
/// ```
pub trait Packet: Serialize + DeserializeOwned + Clone + Send + Sync {
    /// Serializes and encrypts the packet using the provided encryptor.
    ///
    /// # Arguments
    ///
    /// * `encryptor`: The encryption provider
    ///
    /// # Returns
    ///
    /// * A Vec<u8> containing the encrypted packet data
    fn encrypted_ser(&self, encryptor: &Encryptor) -> Vec<u8> {
        let json_data = serde_json::to_string(self).expect("Failed to serialize packet to JSON");

        let encrypted = encryptor
            .encrypt(json_data.as_bytes())
            .expect("Failed to encrypt data");

        encrypted.as_bytes().to_vec()
    }

    /// Deserializes an encrypted packet using the provided encryptor.
    ///
    /// # Arguments
    ///
    /// * `data`: The encrypted packet data
    /// * `encryptor`: The encryption provider
    ///
    /// # Returns
    ///
    /// * A new instance of the implementing type
    #[must_use]
    fn encrypted_de(data: &[u8], encryptor: &Encryptor) -> Self {
        let encrypted_str = String::from_utf8_lossy(data).to_string();

        let decrypted = encryptor
            .decrypt(&encrypted_str)
            .unwrap_or_else(|e| panic!("Decryption failed: {}", e));

        serde_json::from_slice(&decrypted)
            .unwrap_or_else(|e| panic!("Failed to deserialize packet: {}", e))
    }

    /// Serializes the packet to a byte vector.
    ///
    /// # Returns
    ///
    /// * A Vec<u8> containing the serialized packet data
    fn ser(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    /// Serializes the packet to a JSON string.
    ///
    /// # Returns
    ///
    /// * A String containing the JSON representation of the packet
    fn ser_str(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Deserializes a packet from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `data`: The serialized packet data
    ///
    /// # Returns
    ///
    /// * A new instance of the implementing type
    #[must_use]
    fn de(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap_or_else(|_| Self::ok())
    }

    /// Converts serialized packet data to a JSON string.
    ///
    /// # Arguments
    ///
    /// * `data`: The serialized packet data
    ///
    /// # Returns
    ///
    /// * A String containing the JSON representation of the packet
    #[must_use]
    fn de_str(data: &[u8]) -> String {
        serde_json::to_string(data).unwrap()
    }

    /// Returns the packet header.
    ///
    /// # Returns
    ///
    /// * A String containing the packet header
    fn header(&self) -> String;

    /// Returns a clone of the packet body.
    ///
    /// # Returns
    ///
    /// * A `PacketBody` instance
    fn body(&self) -> PacketBody;

    /// Returns a mutable reference to the packet body.
    ///
    /// # Returns
    ///
    /// * A mutable reference to the `PacketBody`
    fn body_mut(&mut self) -> &mut PacketBody;

    /// Inserts authentication credentials into the packet.
    ///
    /// # Arguments
    ///
    /// * `user`: The username
    /// * `pass`: The password
    fn insert_creds(&mut self, user: String, pass: String) {
        let body = self.body_mut();
        body.username = Some(user);
        body.password = Some(pass);
    }

    /// Gets or sets the session ID for the packet.
    ///
    /// # Arguments
    ///
    /// * `session_id`: Optional session ID to set
    ///
    /// # Returns
    ///
    /// * The current session ID if getting, or the new session ID if setting
    fn session_id(&mut self, session_id: Option<String>) -> Option<String> {
        match session_id {
            Some(id) => {
                self.body_mut().session_id = Some(id.clone());
                Some(id)
            }
            None => self.body().session_id,
        }
    }

    /// Creates a new "OK" packet.
    ///
    /// # Returns
    ///
    /// * A new instance representing a successful operation
    fn ok() -> Self;

    /// Verifies that this is an "OK" packet.
    ///
    /// # Returns
    ///
    /// * Ok(()) if this is an OK packet, Error otherwise
    ///
    /// # Errors
    ///
    /// Returns `Error::ExpectedOkPacket` if this is not an OK packet
    fn expected_ok(&self) -> Result<(), Error> {
        if self.header() == Self::ok().header() {
            Ok(())
        } else {
            Err(Error::ExpectedOkPacket)
        }
    }

    /// Creates a new error packet.
    ///
    /// # Arguments
    ///
    /// * `error`: The error to encapsulate
    ///
    /// # Returns
    ///
    /// * A new instance representing an error condition
    fn error(error: Error) -> Self;

    /// Creates a new keepalive packet.
    ///
    /// # Returns
    ///
    /// * A new instance representing a keepalive message
    fn keep_alive() -> Self;

    /// Marks the packet as a broadcast packet.
    ///
    /// # Returns
    ///
    /// * A new instance configured for broadcasting
    #[must_use]
    fn set_broadcasting(mut self) -> Self {
        self.body_mut().is_broadcast_packet = Some(true);
        self
    }

    /// Checks if this is a broadcast packet.
    ///
    /// # Returns
    ///
    /// * true if this is a broadcast packet, false otherwise
    fn is_broadcasting(&self) -> bool {
        self.body().is_broadcast_packet.unwrap_or(false)
    }
}
