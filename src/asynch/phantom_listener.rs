use crate::packet::Packet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    errors::Error,
    phantom::PhantomPacket,
    prelude::{AsyncListener, PoolRef, ResourceRef},
    resources::Resource,
    session::Session,
    wrap_handler,
};

use super::{phantom_client::AsyncPhantomClient, socket::TSocket};

/// `PhantomSession` represents a session in the phantom network protocol.
///
/// This structure maintains the state and lifecycle information for a network session,
/// including its unique identifier, creation timestamp, and duration of validity.
///
/// # Fields
///
/// * `id` - A unique identifier for the session
/// * `timestamp` - The Unix timestamp when the session was created
/// * `lifespan` - The duration for which the session remains valid
///
/// # Example
///
/// ```rust
/// use tnet::asynch::phantom_listener::PhantomSession;
///
/// let session = PhantomSession::empty("unique_id".to_string());
/// assert!(!session.is_expired());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomSession {
    id: String,
    timestamp: u64,
    lifespan: Duration,
}

impl Session for PhantomSession {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn created_at(&self) -> u64 {
        self.timestamp
    }

    fn lifespan(&self) -> std::time::Duration {
        self.lifespan
    }

    fn empty(id: String) -> Self {
        Self {
            id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            lifespan: Duration::from_secs(3600),
        }
    }
}

/// `PhantomResources` serves as a container for any shared resources needed by the phantom network.
///
/// This structure implements the `Resource` trait and can be extended to hold any
/// application-specific resources that need to be shared across different parts of the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomResources {}

impl Resource for PhantomResources {
    fn new() -> Self {
        Self {}
    }
}

/// `PhantomListener` is the main server component for handling phantom network communications.
///
/// This listener is used to relay packets to another endpoint.
///
/// This struct wraps an `AsyncListener` and provides the core functionality for:
/// - Accepting incoming connections
/// - Managing client sessions
/// - Handling packet relay operations
/// - Maintaining network security
///
/// # Example
///
/// ```rust
/// use tnet::asynch::phantom_listener::PhantomListener;
///
/// async fn start_server() {
///     let listener = PhantomListener::new(Some(("127.0.0.1".to_string(), 8080))).await;
///     // Server is now ready to handle connections
/// }
/// ```
pub struct PhantomListener {
    pub server: AsyncListener<PhantomPacket, PhantomSession, PhantomResources>,
}

async fn ok(
    mut socket: TSocket<PhantomSession>,
    packet: PhantomPacket,
    _pools: PoolRef<PhantomSession>,
    _resources: ResourceRef<PhantomResources>,
) {
    if packet.header.as_str() == "relay" {
        let sent_packet = match &packet.sent_packet {
            Some(p) => p,
            None => {
                socket
                    .send(PhantomPacket::error(Error::Other(
                        "No packet to relay".to_string(),
                    )))
                    .await
                    .expect("Failed to send error packet for SentPacket");
                return;
            }
        };

        let client_config = match &packet.client_config {
            Some(config) => config,
            None => {
                socket
                    .send(PhantomPacket::error(Error::InvalidClientConfig))
                    .await
                    .expect("Failed to send error packet for ClientConfig");
                return;
            }
        };

        println!(
            "Received a relay request from {:?} -> {}:{}",
            socket.addr().await,
            client_config.server_addr,
            client_config.server_port
        );

        match AsyncPhantomClient::from_client_config(client_config).await {
            Ok(mut phantom_client) => {
                phantom_client.finalize().await;
                println!("Phantom client connection established");

                tokio::time::sleep(Duration::from_millis(100)).await;

                match phantom_client
                    .send_recv_raw(sent_packet.as_bytes().to_vec())
                    .await
                {
                    Ok(response_data) => {
                        let response_str = String::from_utf8(response_data)
                            .map_err(|e| eprintln!("Failed to convert response to string ::: {e}"))
                            .unwrap();
                        println!("Received response from destination: {}", response_str);

                        let mut response_packet = PhantomPacket::response();
                        response_packet.recv_packet = Some(response_str);

                        if let Err(e) = socket.send(response_packet).await {
                            eprintln!("Failed to send response back to client: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving response from destination: {}", e);
                        let _ = socket.send(PhantomPacket::error(e)).await;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to create phantom client: {}", e);
                let _ = socket.send(PhantomPacket::error(e)).await;
            }
        }
    }
}

async fn bad(
    mut socket: TSocket<PhantomSession>,
    error: Error,
    _pools: PoolRef<PhantomSession>,
    _resources: ResourceRef<PhantomResources>,
) {
    eprintln!("Error in phantom listener: {error}");
    let _ = socket.send(PhantomPacket::error(error)).await;
}

impl PhantomListener {
    /// Supplying a tuple (String, u16) IP:PORT will start the server on zed ip:port,
    ///
    /// Supplying None will start the server on `127.0.0.1:3030`
    pub async fn new(dest: Option<(String, u16)>) -> Self {
        let dest0 = dest
            .as_ref()
            .map_or(("127.0.0.1", 3030), |dest1| (dest1.0.as_str(), dest1.1));

        let server = AsyncListener::new(dest0, 30, wrap_handler!(ok), wrap_handler!(bad)).await;

        Self { server }
    }
}
