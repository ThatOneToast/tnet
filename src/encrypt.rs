use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    pub fn new(key: &[u8]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }


    pub fn encrypt(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce = Nonce::from_slice(&nonce);

        println!("Encrypting data of length: {}", data.len());

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(combined))
    }

    pub fn decrypt(&self, data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        println!("Decrypting data: {}", data);

        let data = BASE64
            .decode(data.as_bytes())
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if data.len() < 12 {
            return Err("Data too short".into());
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e).into())
    }
}

pub struct KeyExchange {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let private_key = StaticSecret::random_from_rng(rand::thread_rng());
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn get_public_key(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn compute_shared_secret(&self, other_public: &[u8; 32]) -> [u8; 32] {
        let other_public = PublicKey::from(*other_public);
        let shared_secret = self.private_key.diffie_hellman(&other_public);
        shared_secret.to_bytes()
    }
}
