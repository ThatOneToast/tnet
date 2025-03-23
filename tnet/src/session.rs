use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{de::DeserializeOwned, Serialize};

use crate::encrypt::Encryptor;

/// `Sessions` is a container type that manages a collection of session instances.
/// It provides functionality for creating, retrieving, and managing sessions.
///
/// # Type Parameters
///
/// * `S`: A type that implements the `Session` trait, representing individual session instances
///
/// # Example
///
/// ```rust
/// use tnet::session::{Sessions, Session};
///
/// #[derive(Debug, Clone)]
/// struct MySession {
///     id: String,
///     created: u64,
/// }
///
/// impl Session for MySession {
///     // ... implementation details ...
/// }
///
/// let mut sessions = Sessions::<MySession>::new();
/// ```
#[derive(Debug, Clone)]
pub struct Sessions<S>
where
    S: Session,
{
    sessions: Vec<S>,
}

impl<S> Sessions<S>
where
    S: Session,
{
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    /// Adds a new session to the container.
    ///
    /// # Arguments
    ///
    /// * `session`: The session instance to add
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::session::{Sessions, Session};
    /// # #[derive(Debug, Clone)]
    /// # struct MySession { id: String, created: u64 }
    /// # impl Session for MySession { /* ... */ }
    /// let mut sessions = Sessions::<MySession>::new();
    /// // sessions.new_session(my_session);
    /// ```
    pub fn new_session(&mut self, session: S) {
        self.sessions.push(session);
    }

    /// Retrieves a reference to a session by its ID.
    ///
    /// # Arguments
    ///
    /// * `id`: The ID of the session to retrieve
    ///
    /// # Returns
    ///
    /// * `Option<&S>`: Some reference to the session if found, None otherwise
    #[must_use] 
    pub fn get_session(&self, id: &str) -> Option<&S> {
        self.sessions.iter().find(|s| s.id() == id)
    }

    /// Retrieves a mutable reference to a session by its ID.
    ///
    /// # Arguments
    ///
    /// * `id`: The ID of the session to retrieve
    ///
    /// # Returns
    ///
    /// * `Option<&mut S>`: Some mutable reference to the session if found, None otherwise
    pub fn get_session_mut(&mut self, id: &str) -> Option<&mut S> {
        self.sessions.iter_mut().find(|s| s.id() == id)
    }

    /// Removes a session from the container by its ID.
    ///
    /// # Arguments
    ///
    /// * `id`: The ID of the session to delete
    pub fn delete_session(&mut self, id: &str) {
        self.sessions.retain(|s| s.id() != id);
    }

    /// Removes all expired sessions from the container.
    /// This should be called periodically to clean up expired sessions.
    pub fn clear_expired(&mut self) {
        self.sessions.retain(|s| !s.is_expired());
    }
}

impl<S> Default for Sessions<S>
where
    S: Session,
{
    fn default() -> Self {
        Self::new()
    }
}

/// The `Session` trait defines the interface for session management in the application.
/// It provides methods for session identification, lifetime management, and serialization.
///
/// # Required Methods
///
/// * `id()`: Returns the unique identifier of the session
/// * `created_at()`: Returns the timestamp when the session was created
/// * `lifespan()`: Returns the duration for which the session is valid
/// * `empty()`: Creates a new empty session with the given ID
///
/// # Provided Methods
///
/// * `is_expired()`: Checks if the session has expired
/// * `encrypted_ser()`: Serializes the session with encryption
/// * `encrypted_de()`: Deserializes an encrypted session
/// * `ser()`: Serializes the session
/// * `de()`: Deserializes the session
///
/// # Example Implementation
///
/// ```rust
/// use std::time::{Duration, SystemTime, UNIX_EPOCH};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// pub struct MySession {
///     id: String,
///     timestamp: u64,
///     lifespan: Duration,
/// }
///
/// impl Session for MySession {
///     fn id(&self) -> &str {
///         self.id.as_str()
///     }
///
///     fn created_at(&self) -> u64 {
///         self.timestamp
///     }
///
///     fn lifespan(&self) -> Duration {
///         self.lifespan
///     }
///
///     fn empty(id: String) -> Self {
///         MySession {
///             id,
///             timestamp: SystemTime::now()
///                 .duration_since(UNIX_EPOCH)
///                 .unwrap()
///                 .as_secs(),
///             lifespan: Duration::from_secs(3600),
///         }
///     }
/// }
/// ```
pub trait Session: Debug + Clone + Send + Sync + Serialize + DeserializeOwned {
    /// Returns the unique identifier of the session.
    ///
    /// # Returns
    ///
    /// * A string slice containing the session ID
    fn id(&self) -> &str;

    /// Returns the timestamp when the session was created.
    ///
    /// # Returns
    ///
    /// * A u64 representing the creation time in seconds since UNIX epoch
    fn created_at(&self) -> u64;

    /// Returns the duration for which the session is valid.
    ///
    /// # Returns
    ///
    /// * A Duration representing the session's lifespan
    fn lifespan(&self) -> Duration;

    /// Creates a new empty session with the given ID.
    ///
    /// # Arguments
    ///
    /// * `id`: A String containing the new session's ID
    ///
    /// # Returns
    ///
    /// * A new session instance
    fn empty(id: String) -> Self;

    /// Checks if the session has expired based on its creation time and lifespan.
    ///
    /// # Returns
    ///
    /// * `true` if the session has expired, `false` otherwise
    fn is_expired(&self) -> bool {
        self.created_at() + self.lifespan().as_secs()
            <= SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
    }

    /// Serializes and encrypts the session.
    ///
    /// # Arguments
    ///
    /// * `encryptor`: The Encryptor instance to use for encryption
    ///
    /// # Returns
    ///
    /// * A Vec<u8> containing the encrypted session data
    fn encrypted_ser(&self, encryptor: &Encryptor) -> Vec<u8> {
        let data = self.ser();
        encryptor.encrypt(&data).unwrap().into_bytes()
    }

    /// Deserializes an encrypted session.
    ///
    /// # Arguments
    ///
    /// * `data`: The encrypted session data
    /// * `encryptor`: The Encryptor instance to use for decryption
    ///
    /// # Returns
    ///
    /// * A new session instance
    #[must_use] 
    fn encrypted_de(data: &[u8], encryptor: &Encryptor) -> Self {
        let encrypted = String::from_utf8_lossy(data);
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        Self::de(&decrypted)
    }

    /// Serializes the session to JSON format.
    ///
    /// # Returns
    ///
    /// * A Vec<u8> containing the serialized session data
    fn ser(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    /// Deserializes a session from JSON format.
    ///
    /// # Arguments
    ///
    /// * `data`: The serialized session data
    ///
    /// # Returns
    ///
    /// * A new session instance
    #[must_use] 
    fn de(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap()
    }
}
