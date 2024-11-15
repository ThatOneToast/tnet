use std::any::Any;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tnet_proc_macros::Packet as DPacket;

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
    pub fn new(action_id: u16, packet: Vec<u8>, ses_id: Option<String>) -> Self {
        Self {
            action_id,
            session_id: ses_id.unwrap_or("".to_string()),
            packet: Some(packet),
            ..Default::default()
        }
    }
    
    pub fn respond(packet: Vec<u8>, ses_id: String, ses_data: Vec<u8>) -> Self {
        Self {
            action_id: 3,
            session_id: ses_id,
            session_data: Some(ses_data),
            packet: Some(packet),
            ..Default::default()
        }
    }
    
    pub fn new_empty(action_id: u16) -> Self {
        Self {
            action_id,
            session_id: "".to_string(),
            packet: None,
            ..Default::default()
        }
    }
}

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
    pub fn new(error: String) -> Self {
        Self { error }
    }
}