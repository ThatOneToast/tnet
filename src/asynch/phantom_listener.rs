use crate::packet::{Packet, PacketBody};
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
    println!("Phantom listener received packet: {:?}", packet);

    if packet.header.as_str() == "relay" {
        let sent_packet = match &packet.sent_packet {
            Some(p) => p,
            None => {
                println!("No packet to relay - sending error response");
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
                println!("No client config - sending error response");
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

        // Create a new phantom client for the target server
        match AsyncPhantomClient::from_client_config(client_config).await {
            Ok(mut phantom_client) => {
                println!("Successfully created phantom client, finalizing...");
                phantom_client.finalize().await;
                println!("Phantom client connection established");

                // Wait a bit for the connection to stabilize
                tokio::time::sleep(Duration::from_millis(300)).await;

                // Get the raw bytes from the sent packet
                let sent_bytes = sent_packet.as_bytes().to_vec();
                println!(
                    "Sending {} bytes to destination server...",
                    sent_bytes.len()
                );

                // Try to send the data and wait for response
                match phantom_client.send_recv_raw(sent_bytes).await {
                    Ok(response_data) => {
                        println!(
                            "Received response from destination ({} bytes)",
                            response_data.len()
                        );

                        // Convert the response to a string
                        let response_str = String::from_utf8(response_data).expect("Failed to convert response data to string");
                        println!("Response content: {}", response_str);

                        // Create a relay-response packet
                        let response_packet = PhantomPacket {
                            header: "relay-response".to_string(), 
                            body: PacketBody::default(),
                            sent_packet: None,
                            recv_packet: Some(response_str),
                            client_config: None,
                        };

                        println!(
                            "Sending relay response back to client: {:?}",
                            response_packet
                        );
                        if let Err(e) = socket.send(response_packet).await {
                            eprintln!("Failed to send response back to client: {}", e);
                        } else {
                            println!("Response sent successfully to client");
                        }
                    }
                    Err(e) => {
                        eprintln!("Error receiving response from destination: {}", e);
                        let err_packet = PhantomPacket::error(e.clone());
                        println!("Sending error response: {:?}", err_packet);
                        if let Err(send_err) = socket.send(err_packet).await {
                            eprintln!("Also failed to send error response: {}", send_err);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to create phantom client: {}", e);
                let err_packet = PhantomPacket::error(e.clone());
                println!("Sending error response: {:?}", err_packet);
                if let Err(send_err) = socket.send(err_packet).await {
                    eprintln!("Also failed to send error response: {}", send_err);
                }
            }
        }
    } else {
        println!("Received non-relay packet: {:?}", packet);
        let _ = socket.send(PhantomPacket::ok()).await;
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
