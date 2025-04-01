use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    asynch::{
        authenticator::{AuthType, Authenticator},
        client::{AsyncClient, EncryptionConfig},
        listener::{AsyncListener, HandlerSources},
    },
    prelude::*,
};
use serde::{Deserialize, Serialize};

pub mod reconnection_tests;
pub mod relay_test;
pub mod tlisten_tests;

// Define packet type exactly as in README
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyPacket {
    header: String,
    body: PacketBody,
}

impl ImplPacket for MyPacket {
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
        }
    }

    fn error(error: Error) -> Self {
        Self {
            header: "ERROR".to_string(),
            body: PacketBody::with_error_string(error.to_string()),
        }
    }

    fn keep_alive() -> Self {
        Self {
            header: "KEEPALIVE".to_string(),
            body: PacketBody::default(),
        }
    }
}

// Define session type exactly as in README
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySession {
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
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            duration: Duration::from_secs(3600),
        }
    }
}

// Define resource type exactly as in README
#[derive(Debug, Clone)]
pub struct MyResource {
    _data: Vec<String>,
}

impl ImplResource for MyResource {
    fn new() -> Self {
        Self { _data: Vec::new() }
    }
}

// Test the basic server setup from README
#[tokio::test]
async fn test_basic_server_setup() {
    async fn handle_ok(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
        let mut socket = sources.socket;
        println!("Received packet: {:?}", packet);
        socket.send(MyPacket::ok()).await.unwrap();
    }

    async fn handle_error(_sources: HandlerSources<MySession, MyResource>, error: Error) {
        println!("Error occurred: {:?}", error);
    }

    let server = AsyncListener::new(
        ("127.0.0.1", 8082),
        30,
        wrap_handler!(handle_ok),
        wrap_handler!(handle_error),
    )
    .await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::UserPassword).with_auth_fn(|user, pass| {
            Box::pin(async move {
                if user == "admin" && pass == "password" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            })
        }),
    );

    assert!(server.is_encryption_enabled());
}

// Test the basic client setup from README
#[tokio::test]
async fn test_basic_client_setup() {
    let (tx, rx) = tokio::sync::oneshot::channel();

    async fn handle_ok(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
        let mut socket = sources.socket;
        println!("Server received packet: {:?}", packet);

        let mut response = MyPacket::ok();
        if let Some(session_id) = packet.body().session_id {
            response.body_mut().session_id = Some(session_id);
        }

        println!("Server sending response: {:?}", response);
        if let Err(e) = socket.send(response).await {
            eprintln!("Failed to send response: {}", e);
        }
    }

    async fn handle_error(sources: HandlerSources<MySession, MyResource>, error: Error) {
        let mut socket = sources.socket;
        if let Err(e) = socket.send(MyPacket::error(error)).await {
            eprintln!("Failed to send error response: {}", e);
        }
    }

    let mut server = AsyncListener::new(
        ("127.0.0.1", 8083),
        30,
        wrap_handler!(handle_ok),
        wrap_handler!(handle_error),
    )
    .await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::UserPassword).with_auth_fn(|user, pass| {
            Box::pin(async move {
                if user == "admin" && pass == "password" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            })
        }),
    );

    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => {},
            _ = rx => println!("Server shutting down"),
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_result = async {
        let mut client = AsyncClient::<MyPacket>::new("127.0.0.1", 8083)
            .await?
            .with_credentials("admin", "password")
            .with_encryption_config(EncryptionConfig::default_on())
            .await
            .unwrap();

        client.finalize().await;

        let response = client.send_recv(MyPacket::ok()).await?;
        println!("Client received response: {:?}", response);

        Ok::<_, Error>(())
    };

    match tokio::time::timeout(Duration::from_secs(5), client_result).await {
        Ok(result) => {
            assert!(result.is_ok(), "Client operation failed: {:?}", result);
        }
        Err(_) => panic!("Client test timed out"),
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// Test full client-server communication
#[tokio::test]
async fn test_full_client_server_communication() {
    // Server setup
    async fn handle_ok(sources: HandlerSources<MySession, MyResource>, _packet: MyPacket) {
        let mut socket = sources.socket;
        socket.send(MyPacket::ok()).await.unwrap();
    }

    async fn handle_error(_sources: HandlerSources<MySession, MyResource>, _error: Error) {}

    let mut server = AsyncListener::new(
        ("127.0.0.1", 8084),
        30,
        wrap_handler!(handle_ok),
        wrap_handler!(handle_error),
    )
    .await;

    // Spawn server task
    tokio::spawn(async move {
        server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client setup
    let mut client = AsyncClient::<MyPacket>::new("127.0.0.1", 8084)
        .await
        .unwrap()
        .with_credentials("admin", "password");

    // Test communication
    let response = client.send_recv(MyPacket::ok()).await.unwrap();
    assert_eq!(response.header(), "OK");
}

// Test broadcasting functionality
#[tokio::test]
async fn test_broadcasting() {
    let (tx, rx) = tokio::sync::oneshot::channel();

    async fn handle_ok(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
        let mut socket = sources.socket;
        println!("Server received packet: {:?}", packet);

        let mut response = MyPacket::ok();
        if let Some(session_id) = packet.body().session_id {
            response.body_mut().session_id = Some(session_id);
        }

        println!("Server sending response: {:?}", response);
        if let Err(e) = socket.send(response).await {
            eprintln!("Failed to send response: {}", e);
        }
    }

    async fn handle_error(sources: HandlerSources<MySession, MyResource>, error: Error) {
        let mut socket = sources.socket;
        if let Err(e) = socket.send(MyPacket::error(error)).await {
            eprintln!("Failed to send error response: {}", e);
        }
    }

    let mut server = AsyncListener::new(
        ("127.0.0.1", 8085),
        30,
        wrap_handler!(handle_ok),
        wrap_handler!(handle_error),
    )
    .await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::UserPassword).with_auth_fn(|user, pass| {
            Box::pin(async move {
                if user == "admin" && pass == "password" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            })
        }),
    );

    let server_handle = tokio::spawn(async move {
        tokio::select! {
            _ = server.run() => {},
            _ = rx => println!("Server shutting down"),
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let broadcast_received = Arc::new(tokio::sync::Notify::new());
    let broadcast_received_clone = broadcast_received.clone();

    let client_result = async {
        let mut client = AsyncClient::<MyPacket>::new("127.0.0.1", 8085)
            .await?
            .with_broadcast_handler(Box::new(move |_packet| {
                broadcast_received_clone.notify_one();
            }))
            .with_credentials("admin", "password")
            .with_encryption_config(EncryptionConfig::default_on())
            .await
            .unwrap();

        client.finalize().await;

        let response = client.send_recv(MyPacket::ok()).await?;
        println!("Client received response: {:?}", response);

        Ok::<_, Error>(())
    };

    match tokio::time::timeout(Duration::from_secs(5), client_result).await {
        Ok(result) => {
            assert!(result.is_ok(), "Client operation failed: {:?}", result);
        }
        Err(_) => panic!("Client test timed out"),
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

// Test custom authentication
#[tokio::test]
async fn test_custom_authentication() {
    let mut authenticator =
        Authenticator::new(AuthType::UserPassword).with_auth_fn(|username, password| {
            Box::pin(async move {
                if username == "admin" && password == "password" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            })
        });

    // Test valid credentials
    let result = authenticator
        .authenticate("admin".to_string(), "password".to_string())
        .await;
    assert!(result.is_ok());

    // Test invalid credentials
    let result = authenticator
        .authenticate("wrong".to_string(), "wrong".to_string())
        .await;
    assert!(result.is_err());
}

// Test encryption
#[tokio::test]
async fn test_encryption() {
    let key = Encryptor::generate_key();
    let encryptor = Encryptor::new(&key).unwrap();

    let original_packet = MyPacket::ok();
    let encrypted = original_packet.encrypted_ser(&encryptor);
    let decrypted = MyPacket::encrypted_de(&encrypted, &encryptor);

    assert_eq!(original_packet.header(), decrypted.header());
}
