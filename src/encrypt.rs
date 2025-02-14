use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

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
    cipher: Aes256Gcm,
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
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    /// Generates a new random 32-byte encryption key.
    ///
    /// # Returns
    ///
    /// * A 32-byte array containing the generated key
    #[must_use]
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
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
    pub fn encrypt(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| e.to_string())?;

        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(combined))
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
    pub fn decrypt(&self, data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let decoded = BASE64
            .decode(data.as_bytes())
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if decoded.len() < 12 {
            return Err("Data too short".into());
        }

        let nonce = Nonce::from_slice(&decoded[0..12]);
        let ciphertext = &decoded[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e).into())
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
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl KeyExchange {
    /// Creates a new `KeyExchange` instance with randomly generated keys.
    ///
    /// # Returns
    ///
    /// * A new `KeyExchange` instance
    #[must_use]
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Returns the public key as a 32-byte array.
    ///
    /// # Returns
    ///
    /// * A 32-byte array containing the public key
    #[must_use]
    pub fn get_public_key(&self) -> [u8; 32] {
        self.public_key.to_bytes()
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
        let other_public = PublicKey::from(*other_public);
        let shared_secret = self.private_key.diffie_hellman(&other_public);
        shared_secret.to_bytes()
    }
}

impl Default for KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}
