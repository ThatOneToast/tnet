use crate::{
    asynch::{phantom_client::AsyncPhantomClient, phantom_listener::PhantomListener},
    phantom::{ClientConfig, PhantomPacket},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Custom packet type for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestPacket {
    header: String,
    body: PacketBody,
    message: String,
}

impl ImplPacket for TestPacket {
    fn header(&self) -> String {
        self.header.clone()
    }

    fn body(&self) -> PacketBody {
        self.body.clone()
    }

    fn body_mut(&mut self) -> &mut PacketBody {
        &mut self.body
    }

    fn ok() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody::default(),
            message: String::new(),
        }
    }

    fn error(error: Error) -> Self {
        Self {
            header: "ERROR".to_string(),
            body: PacketBody::with_error_string(&error.to_string()),
            message: String::new(),
        }
    }

    fn keep_alive() -> Self {
        Self {
            header: "KEEPALIVE".to_string(),
            body: PacketBody::default(),
            message: String::new(),
        }
    }
}

// Session and Resource types (similar to previous tests)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MySession {
    id: String,
    created_at: u64,
    duration: Duration,
}

impl ImplSession for MySession {
    fn id(&self) -> &str {
        &self.id
    }

    fn created_at(&self) -> u64 {
        self.created_at
    }

    fn lifespan(&self) -> Duration {
        self.duration
    }

    fn empty(id: String) -> Self {
        Self {
            id,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            duration: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug, Clone)]
struct MyResource {}

impl ImplResource for MyResource {
    fn new() -> Self {
        Self {}
    }
}

// Endpoint server handler
async fn endpoint_server_handler(
    mut socket: TSocket<MySession>,
    packet: TestPacket,
    _pools: PoolRef<MySession>,
    _resources: ResourceRef<MyResource>,
) {
    println!("Endpoint server received packet: {:?}", packet);

    let mut response = TestPacket::ok();
    response.message = format!("There is a {}", packet.message);

    if let Some(session_id) = packet.body().session_id {
        response.body_mut().session_id = Some(session_id);
    }

    println!("Endpoint server sending response: {:?}", response);
    if let Err(e) = socket.send(response).await {
        eprintln!("Failed to send response: {}", e);
    } else {
        println!("Endpoint server sent response successfully");
    }
}

async fn endpoint_error_handler(
    _socket: TSocket<MySession>,
    _error: Error,
    _pools: PoolRef<MySession>,
    _resources: ResourceRef<MyResource>,
) {
}

// Phantom server relay tests
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_phantom_relay_hello_world() {
    let (tx_endpoint, rx_endpoint) = tokio::sync::oneshot::channel();
    let (tx_phantom, rx_phantom) = tokio::sync::oneshot::channel();

    println!("Setting up endpoint server...");
    let mut endpoint_server = AsyncListener::<TestPacket, MySession, MyResource>::new(
        ("127.0.0.1", 8090),
        30,
        wrap_handler!(endpoint_server_handler),
        wrap_handler!(endpoint_error_handler),
    )
    .await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::RootPassword).with_root_password("rootpassword".to_string()),
    );

    println!("Setting up phantom server...");
    let mut phantom_listener = PhantomListener::new(Some(("127.0.0.1".to_string(), 8091))).await;

    // Spawn servers
    let endpoint_handle = tokio::spawn(async move {
        endpoint_server.run().await;
    });

    let phantom_handle = tokio::spawn(async move {
        phantom_listener.server.run().await;
    });

    // Wait for servers to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    let test_result = async {
        let mut phantom_client = AsyncPhantomClient::new("127.0.0.1", 8091)
            .await
            .map_err(|e| format!("Failed to create phantom client: {}", e))?;

        // Add delay after client creation
        tokio::time::sleep(Duration::from_millis(100)).await;

        phantom_client.finalize().await;

        let original_packet = TestPacket {
            header: "test".to_string(),
            body: PacketBody {
                username: Some("root".to_string()),
                password: Some("rootpassword".to_string()),
                ..Default::default()
            },
            message: "hello".to_string(),
        };

        let client_config = ClientConfig {
            encryption_config: EncryptionConfig::default_on(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 8090,
            user: Some("root".to_string()),
            pass: Some("rootpassword".to_string()),
        };

        let packet =
            PhantomPacket::produce_from_conf(&PhantomConf::from(&client_config), original_packet);

        // Use the new relay method
        let response = phantom_client.send_recv(packet).await.unwrap();
        let underlying_response = response.sent_packet.expect("did not get packet back");
        
        let up_packet: TestPacket = serde_json::from_str(&underlying_response).expect("failed to deserialize packet");
        
        assert_eq!(
            up_packet.message, "There is a hello",
            "Unexpected response message"
        );

        Ok::<(), String>(())
    };

    match tokio::time::timeout(Duration::from_secs(5), test_result).await {
        Ok(Ok(())) => println!("Test completed successfully"),
        Ok(Err(e)) => panic!("Test failed: {}", e),
        Err(_) => panic!("Test timed out"),
    }

    // Clean shutdown
    let _ = tx_endpoint.send(());
    let _ = tx_phantom.send(());

    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), phantom_handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_phantom_relay_with_authentication() {
    let (tx_endpoint, rx_endpoint) = tokio::sync::oneshot::channel();
    let (tx_phantom, rx_phantom) = tokio::sync::oneshot::channel();

    // Setup Endpoint Server
    let mut endpoint_server = AsyncListener::<TestPacket, MySession, MyResource>::new(
        ("127.0.0.1", 8092),
        30,
        wrap_handler!(endpoint_server_handler),
        wrap_handler!(endpoint_error_handler),
    )
    .await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::UserPassword).with_auth_fn(|user, pass| {
            Box::pin(async move {
                if user == "testuser" && pass == "testpass" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            })
        }),
    );

    // Spawn endpoint server with shutdown signal
    let endpoint_handle = tokio::spawn(async move {
        tokio::select! {
            _ = endpoint_server.run() => println!("Endpoint server stopped"),
            _ = rx_endpoint => println!("Endpoint server received shutdown signal"),
        }
    });

    // Setup Phantom Listener with shutdown signal
    let mut phantom_listener = PhantomListener::new(Some(("127.0.0.1".to_string(), 8093))).await;

    let phantom_handle = tokio::spawn(async move {
        tokio::select! {
            _ = phantom_listener.server.run() => println!("Phantom server stopped"),
            _ = rx_phantom => println!("Phantom server received shutdown signal"),
        }
    });

    println!("Starting authentication test...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let test_result = async {
        println!("Creating phantom client...");
        let mut phantom_client = AsyncPhantomClient::new("127.0.0.1", 8093)
            .await
            .map_err(|e| format!("Failed to create phantom client: {}", e))?;

        phantom_client.finalize().await;
        println!("Phantom client initialized");

        // Test with valid credentials
        let original_packet = TestPacket {
            header: "test".to_string(),
            body: PacketBody {
                username: Some("testuser".to_string()),
                password: Some("testpass".to_string()),
                ..Default::default()
            },
            message: "authenticate me".to_string(),
        };

        let client_config = ClientConfig {
            encryption_config: EncryptionConfig::default_on(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 8092,
            user: Some("testuser".to_string()),
            pass: Some("testpass".to_string()),
        };

        let phantom_packet = PhantomPacket {
            header: "relay".to_string(),
            body: PacketBody::default(),
            sent_packet: Some(serde_json::to_string(&original_packet).map_err(|e| e.to_string())?),
            recv_packet: None,
            client_config: Some(client_config),
        };

        println!("Testing valid credentials...");
        let response = phantom_client
            .send_recv(phantom_packet)
            .await
            .map_err(|e| format!("Failed to send/receive: {}", e))?;

        assert_eq!(
            response.header, "relay-response",
            "Valid auth response header incorrect"
        );

        let original_packet = TestPacket {
            header: "test".to_string(),
            body: PacketBody {
                username: Some("wrong".to_string()),
                password: Some("wrong".to_string()),
                ..Default::default()
            },
            message: "authenticate me".to_string(),
        };

        let client_config = ClientConfig {
            encryption_config: EncryptionConfig::default_on(),
            server_addr: "127.0.0.1".to_string(),
            server_port: 8092,
            user: Some("wrong".to_string()),
            pass: Some("wrong".to_string()),
        };

        let phantom_packet = PhantomPacket {
            header: "relay".to_string(),
            body: PacketBody::default(),
            sent_packet: Some(serde_json::to_string(&original_packet).map_err(|e| e.to_string())?),
            recv_packet: None,
            client_config: Some(client_config),
        };

        println!("Testing invalid credentials...");
        let response = phantom_client
            .send_recv(phantom_packet)
            .await
            .map_err(|e| format!("Failed to send/receive: {}", e))?;

        assert_eq!(
            response.header, "ERROR",
            "Invalid auth response header incorrect"
        );

        Ok::<(), String>(())
    };

    // Run test with timeout
    match tokio::time::timeout(Duration::from_secs(90), test_result).await {
        Ok(Ok(())) => println!("Test completed successfully"),
        Ok(Err(e)) => panic!("Test failed: {}", e),
        Err(_) => panic!("Test timed out - check server logs for details"),
    }

    // Shutdown servers
    println!("Shutting down servers...");
    let _ = tx_endpoint.send(());
    let _ = tx_phantom.send(());

    // Wait for server shutdown with timeout
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint_handle).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), phantom_handle).await;
    println!("Authentication test finished");
}
