use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tcrypt::key_exchange::{protocol::SecureChannel, DHKeyExchange};
use tcrypt::prelude::X25519PublicKey as PublicKey;
use tcrypt::EncryptionError;

/// Provides encryption and decryption capabilities using AES-256-GCM.
///
/// This struct encapsulates the encryption logic using the AES-256-GCM algorithm,
/// providing methods for secure data encryption and decryption.
///
/// # Example
///
/// ```rust
/// use tnet::encrypt::Encryptor;
///
/// let key = Encryptor::generate_key();
/// let encryptor = Encryptor::new(&key);
///
/// let data = b"Secret message";
/// let encrypted = encryptor.encrypt(data).unwrap();
/// let decrypted = encryptor.decrypt(&encrypted).unwrap();
/// assert_eq!(data.to_vec(), decrypted);
/// ```
#[derive(Clone)]
pub struct Encryptor {
    channel: SecureChannel,
}

impl Encryptor {
    /// Creates a new Encryptor instance with the provided key.
    ///
    /// # Arguments
    ///
    /// * `key`: A 32-byte array representing the encryption key
    ///
    /// # Returns
    ///
    /// * A new `Encryptor` instance
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        Ok(Self {
            channel: SecureChannel::new(key)?,
        })
    }

    /// Generates a new random 32-byte encryption key.
    ///
    /// # Returns
    ///
    /// * A 32-byte array containing the generated key
    #[must_use]
    pub fn generate_key() -> [u8; 32] {
        let exchange = DHKeyExchange::new();
        let mut key = [0u8; 32];
        let shared_secret = exchange.generate_shared_secret(exchange.public_key());
        key.copy_from_slice(&shared_secret[..32]);
        key
    }

    /// Encrypts the provided data using AES-256-GCM.
    ///
    /// # Arguments
    ///
    /// * `data`: The data to encrypt
    ///
    /// # Returns
    ///
    /// * A Result containing the Base64-encoded encrypted data or an error
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails or if the data cannot be processed
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::encrypt::Encryptor;
    /// let key = Encryptor::generate_key();
    /// let encryptor = Encryptor::new(&key);
    /// let encrypted = encryptor.encrypt(b"Secret data").unwrap();
    /// ```
    pub fn encrypt(&self, data: &[u8]) -> Result<String, EncryptionError> {
        let encrypted = self.channel.encrypt(data)?;
        Ok(BASE64.encode(&encrypted))
    }

    /// Decrypts the provided encrypted data.
    ///
    /// # Arguments
    ///
    /// * `data`: The Base64-encoded encrypted data
    ///
    /// # Returns
    ///
    /// * A Result containing the decrypted data or an error
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is not valid Base64
    /// - The input data is too short
    /// - Decryption fails
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::encrypt::Encryptor;
    /// let key = Encryptor::generate_key();
    /// let encryptor = Encryptor::new(&key);
    /// let encrypted = encryptor.encrypt(b"Secret data").unwrap();
    /// let decrypted = encryptor.decrypt(&encrypted).unwrap();
    /// ```
    pub fn decrypt(&self, data: &str) -> Result<Vec<u8>, EncryptionError> {
        let decoded = BASE64
            .decode(data)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;
        self.channel.decrypt(&decoded)
    }
}

/// Handles key exchange operations using the X25519 protocol.
///
/// This struct provides functionality for performing Diffie-Hellman key exchange
/// using the X25519 elliptic curve.
///
/// # Example
///
/// ```rust
/// use tnet::encrypt::KeyExchange;
///
/// let alice = KeyExchange::new();
/// let bob = KeyExchange::new();
///
/// let alice_public = alice.get_public_key();
/// let bob_public = bob.get_public_key();
///
/// let alice_shared = alice.compute_shared_secret(&bob_public);
/// let bob_shared = bob.compute_shared_secret(&alice_public);
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
pub struct KeyExchange {
    exchange: DHKeyExchange,
}

impl KeyExchange {
    /// Creates a new `KeyExchange` instance with randomly generated keys.
    ///
    /// # Returns
    ///
    /// * A new `KeyExchange` instance
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchange: DHKeyExchange::new(),
        }
    }

    /// Returns the public key as a 32-byte array.
    ///
    /// # Returns
    ///
    /// * A 32-byte array containing the public key
    #[must_use]
    pub fn get_public_key(&self) -> [u8; 32] {
        *self.exchange.public_key().as_bytes()
    }

    /// Computes the shared secret using the other party's public key.
    ///
    /// # Arguments
    ///
    /// * `other_public`: The other party's public key as a 32-byte array
    ///
    /// # Returns
    ///
    /// * A 32-byte array containing the computed shared secret
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tnet::encrypt::KeyExchange;
    /// let alice = KeyExchange::new();
    /// let bob = KeyExchange::new();
    ///
    /// let shared_secret = alice.compute_shared_secret(&bob.get_public_key());
    /// ```
    #[must_use]
    pub fn compute_shared_secret(&self, other_public: &[u8; 32]) -> [u8; 32] {
        let mut key = [0u8; 32];
        let shared = self
            .exchange
            .generate_shared_secret(&PublicKey::from(*other_public));
        key.copy_from_slice(&shared[..32]);
        key
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}
