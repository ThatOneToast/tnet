use std::any::Any;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tnet_proc_macros::Packet as DPacket;

use crate::prelude::Session;

/// A trait for network-transmittable packets with serialization and type conversion capabilities
///
/// This trait provides a standard interface for packet types that can be sent over the network,
/// with built-in serialization using bincode and type conversion capabilities through Any.
///
/// # Required Traits
/// * `Serialize` - For converting packet to bytes
/// * `DeserializeOwned` - For recreating packet from bytes
/// * `Debug` - For debugging and logging
/// * `Any` - For runtime type conversion
/// * `Clone` - For packet duplication
/// * `Default` - For creating empty packets
///
/// # Example
/// ```rust
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// struct ChatPacket {
///     message: String,
///     timestamp: u64,
/// }
///
/// impl Packet for ChatPacket {}
///
/// // The trait provides default implementations for:
/// // - encode() using bincode
/// // - decode() using bincode
/// // - as_any() for type conversion
///
/// fn send_chat(packet: &impl Packet) {
///     let bytes = packet.encode();
///     // Send bytes over network...
/// }
///
/// fn receive_chat(bytes: &[u8]) -> ChatPacket {
///     ChatPacket::decode(bytes)
/// }
/// ```
pub trait Packet: Serialize + DeserializeOwned + std::fmt::Debug + Any + Clone + Default {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    fn decode<T: DeserializeOwned>(data: &[u8]) -> T {
        bincode::deserialize(data).unwrap()
    }
}

/// A wrapper packet for network communication that handles different types of actions
///
/// This packet type wraps other packets and includes metadata for routing and authentication.
/// It supports different actions through the action_id field:
/// * 0: Passthrough (no authentication required)
/// * 1: Authentication request
/// * 2: Error response
/// * 3: Normal authenticated communication
///
/// # Fields
/// * `action_id` - Identifies the type of action (0-3)
/// * `session_id` - Unique identifier for the client session
/// * `session_data` - Optional serialized session state
/// * `packet` - Optional payload packet as bytes
/// * `username` - Optional username for authentication
/// * `password` - Optional password for authentication
///
/// # Example
/// ```rust
/// // Creating an authentication packet
/// let auth_packet = NetWrapperPacket {
///     action_id: 1,
///     username: Some("user123".to_string()),
///     password: Some("pass456".to_string()),
///     ..Default::default()
/// };
///
/// // Creating a data packet
/// let chat = ChatPacket {
///     message: "Hello".to_string(),
///     timestamp: 12345,
/// };
/// let data_packet = NetWrapperPacket::new(
///     3,
///     chat.encode(),
///     Some("session123".to_string())
/// );
/// ```
#[derive(DPacket, Debug, Clone, Serialize, Deserialize)]
pub struct NetWrapperPacket {
    pub action_id: u16,
    pub session_id: String,
    pub session_data: Option<Vec<u8>>,
    pub packet: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Default for NetWrapperPacket {
    fn default() -> Self {
        Self {
            action_id: 0,
            session_id: "".to_string(),
            session_data: None,
            packet: None,
            username: None,
            password: None,
        }
    }
}

impl NetWrapperPacket {
    /// Creates a new wrapper packet with specified action, payload, and optional session ID
    ///
    /// # Arguments
    /// * `action_id` - The type of action this packet represents
    /// * `packet` - The payload packet as bytes
    /// * `ses_id` - Optional session identifier
    ///
    /// # Returns
    /// A new NetWrapperPacket configured with the provided values
    pub fn new(action_id: u16, packet: Vec<u8>, ses_id: Option<String>) -> Self {
        Self {
            action_id,
            session_id: ses_id.unwrap_or("".to_string()),
            packet: Some(packet),
            ..Default::default()
        }
    }

    /// Creates a response packet with payload data and session information
    ///
    /// # Arguments
    /// * `packet` - The payload packet as bytes
    /// * `ses_id` - Session identifier
    /// * `ses_data` - Serialized session data
    ///
    /// # Returns
    /// A new NetWrapperPacket configured for response (action_id = 3)
    pub fn respond(packet: Vec<u8>, ses_id: String, ses_data: Vec<u8>) -> Self {
        Self {
            action_id: 3,
            session_id: ses_id,
            session_data: Some(ses_data),
            packet: Some(packet),
            ..Default::default()
        }
    }

    /// Creates a packet with both packet payload and session data using generic types
    ///
    /// # Type Parameters
    /// * `P` - Type implementing Packet trait
    /// * `S` - Type implementing Session trait
    ///
    /// # Arguments
    /// * `packet` - The payload packet
    /// * `session` - The session data
    ///
    /// # Returns
    /// A new NetWrapperPacket with encoded packet and session data
    pub fn just_this<P: Packet, S: Session>(packet: P, session: S) -> Self {
        Self {
            action_id: 3,
            packet: Some(packet.encode()),
            session_data: Some(session.encode()),
            ..Default::default()
        }
    }

    /// Creates an empty packet with just an action ID
    ///
    /// # Arguments
    /// * `action_id` - The type of action this packet represents
    ///
    /// # Returns
    /// A new NetWrapperPacket with only the action_id set
    pub fn new_empty(action_id: u16) -> Self {
        Self {
            action_id,
            session_id: "".to_string(),
            packet: None,
            ..Default::default()
        }
    }
}

/// A packet type for communicating error conditions
///
/// This packet is typically wrapped in a NetWrapperPacket with action_id 2
/// to indicate error conditions to the client.
///
/// # Fields
/// * `error` - Description of the error
///
/// # Example
/// ```rust
/// let error = NetErrorPacket::new("Authentication failed".to_string());
/// let wrapper = NetWrapperPacket {
///     action_id: 2,
///     packet: Some(error.encode()),
///     ..Default::default()
/// };
/// ```
#[derive(DPacket, Debug, Clone, Serialize, Deserialize)]
pub struct NetErrorPacket {
    pub error: String,
}

impl Default for NetErrorPacket {
    fn default() -> Self {
        Self {
            error: "Unknown Error".to_string(),
        }
    }
}

impl NetErrorPacket {
    /// Creates a new error packet with the specified error message
    ///
    /// # Arguments
    /// * `error` - Description of the error condition
    ///
    /// # Returns
    /// A new NetErrorPacket containing the error message
    pub fn new(error: String) -> Self {
        Self { error }
    }
}
