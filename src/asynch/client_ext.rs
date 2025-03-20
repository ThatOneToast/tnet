use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{errors::Error, packet};

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

    pub async fn signal_reconnect(&self) -> Result<(), Error> {
        let client = self.0.read().await;

        if let Some(tx) = &client.keepalive_reconnect_tx {
            // Clone the channel to avoid holding the read lock during send
            let tx_clone = tx.clone();
            drop(client);

            // Send the reconnect signal
            match tx_clone.send(()).await {
                Ok(()) => Ok(()),
                Err(_) => Err(Error::Error("Failed to signal reconnection".to_string())),
            }
        } else {
            Err(Error::Error(
                "Keepalive reconnection channel not available".to_string(),
            ))
        }
    }
}
