use std::any::Any;

use serde::{de::DeserializeOwned, Serialize};

/// A trait for managing stateful session data in a networked application
///
/// The Session trait provides a standard interface for session management with
/// built-in serialization and thread-safe state handling. It's designed to work
/// with the network system to maintain client state across connections.
///
/// # Required Traits
/// * `Debug` - For debugging and logging session state
/// * `Any` - For runtime type conversion
/// * `Send` - For thread-safe transmission
/// * `Sync` - For thread-safe sharing
/// * `Clone` - For session state duplication
/// * `Default` - For creating empty sessions
/// * `Serialize` - For converting session to bytes
/// * `DeserializeOwned` - For recreating session from bytes
///
/// # Example
/// ```rust
/// use serde::{Serialize, Deserialize};
/// use uuid::Uuid;
///
/// #[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// struct GameSession {
///     id: String,
///     player_name: String,
///     score: u32,
///     last_active: u64,
///     is_admin: bool,
/// }
///
/// impl Session for GameSession {
///     fn get_id(&self) -> String {
///         if self.id.is_empty() {
///             // Generate new UUID if none exists
///             Uuid::new_v4().to_string()
///         } else {
///             self.id.clone()
///         }
///     }
/// }
///
/// // Using the session in a network context
/// fn handle_game_update(mut session: GameSession, score_delta: i32) {
///     // Update session state
///     if score_delta > 0 {
///         session.score += score_delta as u32;
///     }
///     
///     // Serialize for network transmission
///     let bytes = session.encode();
///     
///     // Later, reconstruct the session
///     let updated_session: GameSession = GameSession::decode(&bytes);
/// }
///
/// // Example with authentication and privileges
/// #[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// struct AuthSession {
///     id: String,
///     user_id: u64,
///     permissions: Vec<String>,
///     token: String,
///     expiry: u64,
/// }
///
/// impl Session for AuthSession {
///     fn get_id(&self) -> String {
///         self.id.clone()
///     }
/// }
///
/// impl AuthSession {
///     fn has_permission(&self, permission: &str) -> bool {
///         self.permissions.contains(&permission.to_string())
///     }
///     
///     fn is_expired(&self) -> bool {
///         let now = std::time::SystemTime::now()
///             .duration_since(std::time::UNIX_EPOCH)
///             .unwrap()
///             .as_secs();
///         now > self.expiry
///     }
/// }
/// ```
///
/// # Implementation Notes
/// * The trait provides default implementations for serialization/deserialization using bincode
/// * Sessions should be designed to be lightweight and easily serializable
/// * Consider implementing additional methods for session validation and state management
/// * Use the `Any` trait methods for runtime type checking and conversion
/// * Ensure thread safety when modifying session state in multi-threaded contexts
///
/// # Common Use Cases
/// 1. User authentication and authorization
/// 2. Game state management
/// 3. Stateful API connections
/// 4. Real-time application state synchronization
/// 5. User preference and configuration storage
///
/// # Best Practices
/// * Keep session data minimal and relevant
/// * Implement proper cleanup for expired sessions
/// * Include timestamps for session validity checking
/// * Use secure methods for generating session IDs
/// * Handle serialization errors gracefully
pub trait Session: std::fmt::Debug + Any + Send + Sync + Clone + Default + Serialize + DeserializeOwned{
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn get_id(&self) -> String;
    
    fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    fn decode<T: DeserializeOwned>(data: &[u8]) -> T {
        bincode::deserialize(data).unwrap()
    }
}
