use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{encrypt::Encryptor, errors::Error};

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn broadcasting() -> Self {
        Self {
            is_broadcast_packet: Some(true),
            ..Default::default()
        }
    }

    pub fn with_error_string(string: &str) -> Self {
        Self {
            error_string: Some(string.to_string()),
            ..Default::default()
        }
    }
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
    fn session_id(&mut self, session_id: Option<String>) -> Option<String> {
        match session_id {
            Some(id) => {
                self.body_mut().session_id = Some(id.clone());
                Some(id)
            }
            None => self.body().session_id,
        }
    }

    fn ok() -> Self;
    fn error(error: Error) -> Self;
    fn keep_alive() -> Self;
    fn set_broadcasting(mut self) -> Self {
        self.body_mut().is_broadcast_packet = Some(true);
        self
    }
    fn is_broadcasting(&self) -> bool {
        self.body().is_broadcast_packet.unwrap_or(false)
    }
}
