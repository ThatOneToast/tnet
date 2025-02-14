use std::sync::Arc;

use tokio::sync::RwLock;

use crate::packet;

use super::client::AsyncClient;

#[derive(Clone)]
pub struct AsyncClientRef<P: packet::Packet>(Arc<RwLock<AsyncClient<P>>>);

impl<P: packet::Packet> AsyncClientRef<P> {
    #[must_use]
    pub fn new(client: AsyncClient<P>) -> Self {
        Self(Arc::new(RwLock::new(client)))
    }

    pub async fn write(&mut self) -> tokio::sync::RwLockWriteGuard<'_, AsyncClient<P>> {
        self.0.write().await
    }

    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, AsyncClient<P>> {
        self.0.read().await
    }
}
