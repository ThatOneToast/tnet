use std::any::Any;

use serde::{de::DeserializeOwned, Serialize};

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
