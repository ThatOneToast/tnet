use std::{sync::Arc, time::Duration};

use crate::{
    asynch::{
        authenticator::{AuthFunction, AuthType, Authenticator},
        client::EncryptionConfig,
        listener::{AsyncListener, AsyncListenerErrorHandler, AsyncListenerOkHandler},
    },
    prelude::*
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestSession {
    data: String,
    id: String,
    created_at: i64,
    lifespan: Duration,
}

impl Session for TestSession {
    fn id(&self) -> &str {
        self.id.as_str()
    }

    fn created_at(&self) -> i64 {
        self.created_at.clone()
    }

    fn lifespan(&self) -> std::time::Duration {
        self.lifespan.clone()
    }

    fn empty(id: String) -> Self {
        TestSession {
            data: String::new(),
            id,
            created_at: chrono::Utc::now().timestamp(),
            lifespan: Duration::from_secs(3600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestPacket {
    header: String,
    body: PacketBody,
}

impl Packet for TestPacket {
    fn header(&self) -> String {
        self.header.clone()
    }

    fn body(&self) -> PacketBody {
        self.body.clone()
    }

    fn body_mut(&mut self) -> &mut PacketBody {
        &mut self.body
    }

    fn session_id(&mut self, session_id: Option<String>) -> Option<String> {
        match session_id {
            Some(id) => {
                self.body.session_id = Some(id.clone());
                return Some(id);
            }
            None => {
                return self.body.session_id.to_owned().clone();
            }
        }
    }

    fn ok() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody {
                username: None,
                password: None,
                session_id: None,
                error_string: None,
            },
        }
    }

    fn error(error: Error) -> Self {
        Self {
            header: "ERROR".to_string(),
            body: PacketBody {
                username: None,
                password: None,
                session_id: None,
                error_string: Some(error.to_string()),
            },
        }
    }
    
    fn keep_alive() -> Self {
        Self {
            header: "KEEP_ALIVE".to_string(),
            body: PacketBody::default(),
        }
    }
}

#[tokio::test]
async fn test_key_exchange() {
    let client_exchange = KeyExchange::new();
    let server_exchange = KeyExchange::new();

    let client_public = client_exchange.get_public_key();
    let server_public = server_exchange.get_public_key();

    let client_shared = client_exchange.compute_shared_secret(&server_public);
    let server_shared = server_exchange.compute_shared_secret(&client_public);

    assert_eq!(client_shared, server_shared);
}

#[tokio::test]
async fn test_async_listener_setup() {
    let ok_handler: AsyncListenerOkHandler<TestPacket, TestSession> =
        Arc::new(|_socket: TSocket<TestSession>, _packet: TestPacket| Box::pin(async move {}));

    let error_handler: AsyncListenerErrorHandler<TestSession> =
        Arc::new(|_socket: TSocket<TestSession>, _error: Error| Box::pin(async move {}));

    let listener = AsyncListener::new(("127.0.0.1", 8081), 10_800, ok_handler, error_handler).await;

    assert!(!listener.is_encryption_enabled());

    let config = EncryptionConfig {
        enabled: true,
        key: Some(Encryptor::generate_key()),
        auto_key_exchange: false,
    };

    let listener = listener.with_encryption_config(config).await;
    assert!(listener.is_encryption_enabled());
}

#[tokio::test]
async fn test_authenticator_chain() {
    let auth_fn: AuthFunction = |username: String, password: String| {
        Box::pin(async move {
            if username == "test" && password == "test" {
                Ok(())
            } else {
                Err(Error::InvalidCredentials)
            }
        })
    };

    let auth = Authenticator::new(AuthType::UserPassword)
        .with_auth_fn(auth_fn)
        .with_root_password("root".to_string());

    assert_eq!(auth.clone().auth_type, AuthType::UserPassword);
}

#[tokio::test]
async fn test_encryption_integration() {
    let key = Encryptor::generate_key();
    let encryptor = Encryptor::new(&key);

    let packet = TestPacket {
        header: "ENCRYPTED".to_string(),
        body: PacketBody {
            username: Some("encrypted_user".to_string()),
            password: Some("encrypted_pass".to_string()),
            session_id: Some("session123".to_string()),
            error_string: None,
        },
    };

    let encrypted = packet.encrypted_ser(&encryptor);
    let decrypted = TestPacket::encrypted_de(&encrypted, &encryptor);

    assert_eq!(packet.header(), decrypted.header());
    assert_eq!(
        packet.body().username.unwrap(),
        decrypted.body().username.unwrap()
    );
    assert_eq!(
        packet.body().session_id.unwrap(),
        decrypted.body().session_id.unwrap()
    );
}

#[tokio::test]
async fn test_packet_error_handling() {
    let error_packet = TestPacket::error(Error::InvalidCredentials);
    assert_eq!(error_packet.header(), "ERROR");
    assert!(error_packet.body().error_string.is_some());
    assert_eq!(
        error_packet.body().error_string.unwrap(),
        Error::InvalidCredentials.to_string()
    );

    let ok_packet = TestPacket::ok();
    assert_eq!(ok_packet.header(), "OK");
    assert!(ok_packet.body().error_string.is_none());
}

#[tokio::test]
async fn test_authentication_flow() {
    let mut auth = Authenticator::new(AuthType::UserPassword).with_auth_fn(|username, password| {
        Box::pin(async move {
            if username == "valid_user" && password == "valid_pass" {
                Ok(())
            } else {
                Err(Error::InvalidCredentials)
            }
        })
    });

    // Test valid authentication
    let result = auth
        .authenticate("valid_user".to_string(), "valid_pass".to_string())
        .await;
    assert!(result.is_ok());

    // Test invalid authentication
    let result = auth
        .authenticate("invalid_user".to_string(), "invalid_pass".to_string())
        .await;
    assert!(result.is_err());
}
