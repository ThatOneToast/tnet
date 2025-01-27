use std::{fmt::Debug, time::Duration};

use serde::{de::DeserializeOwned, Serialize};

use crate::encrypt::Encryptor;

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
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    pub fn new_session(&mut self, session: S) {
        self.sessions.push(session);
    }

    pub fn get_session(&self, id: &str) -> Option<&S> {
        self.sessions.iter().find(|s| s.id() == id)
    }

    pub fn get_session_mut(&mut self, id: &str) -> Option<&mut S> {
        self.sessions.iter_mut().find(|s| s.id() == id)
    }

    pub fn delete_session(&mut self, id: &str) {
        self.sessions.retain(|s| s.id() != id);
    }
    
    pub fn clear_expired(&mut self) {
        println!("Session Clear Wave");
        self.sessions.retain(|s| !s.is_expired());
    }
}

pub trait Session: Debug + Clone + Send + Sync + Serialize + DeserializeOwned {
    fn id(&self) -> &str;
    fn created_at(&self) -> i64;
    fn lifespan(&self) -> Duration;
    fn empty(id: String) -> Self;

    fn is_expired(&self) -> bool {
        self.created_at() + self.lifespan().as_secs() as i64 <= chrono::Utc::now().timestamp()
    }

    fn encrypted_ser(&self, encryptor: &Encryptor) -> Vec<u8> {
        let data = self.ser();
        encryptor.encrypt(&data).unwrap().into_bytes()
    }

    fn encrypted_de(data: &[u8], encryptor: &Encryptor) -> Self {
        let encrypted = String::from_utf8_lossy(data);
        let decrypted = encryptor.decrypt(&encrypted).unwrap();
        Self::de(&decrypted)
    }

    fn ser(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    fn de(data: &[u8]) -> Self {
        serde_json::from_slice(data).unwrap()
    }
}

