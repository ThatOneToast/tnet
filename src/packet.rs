use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    encrypt::Encryptor,
    errors::Error,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PacketBody {
    pub username: Option<String>,
    pub password: Option<String>,
    pub session_id: Option<String>,
    pub error_string: Option<String>,
}

pub trait Packet: Serialize + DeserializeOwned + Clone + Send + Sync {
    fn encrypted_ser(&self, encryptor: &Encryptor) -> Vec<u8> {
        let data = serde_json::to_vec(self).expect("Failed to serialize packet");
        let encrypted = encryptor.encrypt(&data).expect("Failed to encrypt data");
        encrypted.into_bytes()
    }

    fn encrypted_de(data: &[u8], encryptor: &Encryptor) -> Self {
        let encrypted = String::from_utf8_lossy(data);
        let decrypted = encryptor
            .decrypt(&encrypted)
            .expect("Failed to decrypt data");
        serde_json::from_slice(&decrypted).expect("Failed to deserialize packet")
    }

    fn ser(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    fn de(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap()
    }

    fn header(&self) -> String;
    fn body(&self) -> PacketBody;
    fn body_mut(&mut self) -> &mut PacketBody;
    
    /// IF `session_id` is some the user would like to set one.
    ///
    /// IF `session_id` is none the user would like the id.
    fn session_id(&mut self, session_id: Option<String>) -> Option<String>;

    fn ok() -> Self;
    fn error(error: Error) -> Self;
}
