# tnet

A robust async TCP networking library for Rust that provides:
- Secure encrypted connections
- Session management
- Authentication
- Keep-alive mechanisms
- Broadcast capabilities
- Automatic reconnection
- Relay/proxy functionality


## Features

- 🔒 **Encryption** - Built-in support for AES-256-GCM encryption
- 🔑 **Authentication** - Flexible authentication system with multiple auth types
- 📡 **Keep-alive** - Automatic connection maintenance
- 🔄 **Session Management** - Track and manage client sessions
- 📢 **Broadcasting** - Send messages to multiple clients
- 🔌 **Reconnection** - Resilient connections with automatic reconnection and exponential backoff
- 🚀 **Async/Await** - Built on tokio for high performance
- 🌐 **Relay/Proxy** - Network traffic relay with the phantom client/server system
- 🎯 **Attribute Macros** - Easy handler registration with the `#[tlisten_for("PACKET_TYPE")]` macro
- 🏷️ **Derive Macros** - Generate packet header types with `#[derive(PacketHeader)]`


## Example Usage

### Basic Server

```rust
use tnet::prelude::*;
use serde::{Serialize, Deserialize};

// Define your packet type
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MyPacket {
    header: String,
    body: PacketBody,
}

// Implement the Packet trait
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
            body: PacketBody::with_error_string(&error.to_string()),
        }
    }

    fn keep_alive() -> Self {
        Self {
            header: "KEEPALIVE".to_string(),
            body: PacketBody::default(),
        }
    }
}

// Define your session type
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
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            duration: Duration::from_secs(3600),
        }
    }
}

// Define your resource type
#[derive(Debug, Clone)]
struct MyResource {
    data: Vec<String>,
}

impl ImplResource for MyResource {
    fn new() -> Self {
        Self { data: Vec::new() }
    }
}

// Define packet handlers with the tlisten_for attribute macro
#[tlisten_for("LOGIN")]
async fn handle_login(
    sources: HandlerSources<MySession, MyResource>,
    packet: MyPacket
) {
    let mut socket = sources.socket;
    println!("Processing login request");
    
    // Access resources if needed
    let mut resources = sources.resources.write().await;
    resources.data.push("Login processed".to_string());
    
    // Send response
    socket.send(MyPacket::ok()).await.unwrap();
}

#[tlisten_for("LOGOUT")]
async fn handle_logout(
    sources: HandlerSources<MySession, MyResource>,
    packet: MyPacket
) {
    let mut socket = sources.socket;
    println!("Processing logout request");
    socket.send(MyPacket::ok()).await.unwrap();
}

// For packets without specific handlers, we use these default handlers
async fn handle_ok(
    sources: HandlerSources<MySession, MyResource>,
    packet: MyPacket
) {
    println!("Received packet: {:?}", packet);
    sources.socket.send(MyPacket::ok()).await.unwrap();
}

async fn handle_error(
    sources: HandlerSources<MySession, MyResource>,
    error: Error
) {
    println!("Error occurred: {:?}", error);
}

#[tokio::main]
async fn main() {
    // Create and configure server
    let server = AsyncListener::new(
        ("127.0.0.1", 8080),
        30,
        wrap_handler!(handle_ok),
        wrap_handler!(handle_error)
    ).await
    .with_encryption_config(EncryptionConfig::default_on())
    .with_authenticator(
        Authenticator::new(AuthType::UserPassword)
            .with_auth_fn(|user, pass| Box::pin(async move {
                if user == "admin" && pass == "password" {
                    Ok(())
                } else {
                    Err(Error::InvalidCredentials)
                }
            }))
    );

    // Create connection pools if needed
    server.with_pool("authenticated").await;

    // Run the server
    server.run().await;
}
```

### Basic Client

```rust
use tnet::prelude::*;

#[tokio::main]
async fn main() {
    // Create and configure client
    let mut client = AsyncClient::<MyPacket>::new("127.0.0.1", 8080)
        .await
        .unwrap()
        .with_credentials("admin", "password")
        .with_encryption_config(EncryptionConfig::default_on())
        .await
        .unwrap()
        .with_keep_alive(KeepAliveConfig::default_on())
        .with_reconnection(ReconnectionConfig::default_on());

    // Finalize connection
    client.finalize().await;

    // Send a packet and get response
    let response = client.send_recv(MyPacket::ok()).await.unwrap();
    println!("Server response: {:?}", response);
    
    // Send a login packet
    let mut login_packet = MyPacket::ok();
    login_packet.header = "LOGIN".to_string();
    let login_response = client.send_recv(login_packet).await.unwrap();
    println!("Login response: {:?}", login_response);
}
```

## Advanced Usage

### Packet Header Enum with Derive Macro

```rust
use tnet::prelude::*;

// Define packet headers as an enum
#[derive(Debug, Clone, PacketHeader)]
enum MyHeaders {
    Login,
    Logout,
    Message,
    KeepAlive,
    Error,
    Ok,
}

// Now you can use MyHeaders with automatic string conversion
#[tlisten_for("Login")]
async fn handle_login(sources: HandlerSources<MySession, MyResource>, packet: MyPacket) {
    // Login logic here
    
    // The enum provides automatic string conversion
    let response_header = MyHeaders::Ok.to_string();
    let mut response = MyPacket::ok();
    response.header = response_header;
    
    sources.socket.send(response).await.unwrap();
}

// Parse strings to enum values
fn process_header(header_str: &str) -> Result<MyHeaders, String> {
    header_str.parse::<MyHeaders>()
}
```

### Auto-Reconnection

The client can automatically reconnect when the connection is lost, preserving session state:

```rust
// Configure client with reconnection settings
let mut client = AsyncClient::<MyPacket>::new("127.0.0.1", 8080)
    .await
    .unwrap()
    .with_reconnection(ReconnectionConfig {
        // Enable automatic reconnection
        auto_reconnect: true,

        // Fallback endpoints to try if primary connection fails
        endpoints: vec![("backup.server.com".to_string(), 8081)],

        // Maximum number of reconnection attempts (None for unlimited)
        max_attempts: Some(5),

        // Base delay between reconnection attempts in seconds
        initial_retry_delay: 1.0,

        // Maximum delay between reconnection attempts in seconds
        max_retry_delay: 60.0,

        // Multiplier for exponential backoff
        backoff_factor: 1.5,

        // Random jitter factor to add to delay to prevent thundering herd
        jitter: 0.1,

        // Whether to reinitialize session after successful reconnection
        reinitialize: true,

        ..Default::default()
    });

// The client will now automatically reconnect when the connection is lost,
// and will maintain session state across reconnections.
```

### Broadcasting

```rust
// Server-side broadcasting
async fn broadcast_message(server: &AsyncListener<MyPacket, MySession, MyResource>, msg: MyPacket) {
    server.broadcast(msg).await.unwrap();
}

// Client-side broadcast handling
let client = AsyncClient::<MyPacket>::new("127.0.0.1", 8080)
    .await
    .unwrap()
    .with_broadcast_handler(Box::new(|packet| {
        println!("Received broadcast: {:?}", packet);
    }));
```

### Custom Authentication

```rust
let authenticator = Authenticator::new(AuthType::UserPassword)
    .with_auth_fn(|username, password| {
        Box::pin(async move {
            // Your custom authentication logic here
            if verify_credentials(username, password).await {
                Ok(())
            } else {
                Err(Error::InvalidCredentials)
            }
        })
    });
```

### Handling Connection Interruptions

The library is designed to handle connection interruptions gracefully:

```rust
// Send with automatic reconnection if the connection fails
match client.send_recv(MyPacket::ok()).await {
    Ok(response) => {
        println!("Got response: {:?}", response);
    },
    Err(e) => {
        if client.is_reconnected() {
            // The connection was restored, but the operation failed
            println!("Operation failed after reconnection: {}", e);
        } else {
            // The connection could not be restored
            println!("Connection lost and could not be restored: {}", e);
        }
    }
}
```

### Network Relay/Proxy with PhantomClient and PhantomListener

The phantom system allows relaying packets through an intermediary server:

```rust
// 1. Set up a phantom listener (relay server)
let phantom_listener = PhantomListener::new(Some(("127.0.0.1".to_string(), 9090))).await;

// 2. Create a client config for the destination server
let client_config = ClientConfig {
    encryption_config: EncryptionConfig::default_on(),
    server_addr: "destination.server.com".to_string(),
    server_port: 8080,
    user: Some("user".to_string()),
    pass: Some("pass".to_string()),
};

// 3. Create a phantom configuration 
let phantom_conf = PhantomConf {
    header: "relay",
    username: Some("user"),
    password: Some("pass"),
    server_addr: "destination.server.com",
    server_port: 8080,
    enc_conf: EncryptionConfig::default_on(),
};

// 4. Create a packet to send to the destination
let packet_to_relay = MyPacket::ok();

// 5. Create a phantom packet that wraps the real packet
let phantom_packet = PhantomPacket::produce_from_conf(&phantom_conf, &packet_to_relay);

// 6. Connect to the phantom server and send the relay request
let mut client = AsyncClient::<PhantomPacket>::new("127.0.0.1", 9090)
    .await
    .unwrap();

// 7. Send and get response
let relay_response = client.send_recv(phantom_packet).await.unwrap();

// 8. Extract the response from the destination server
if let Some(response_data) = relay_response.recv_packet {
    // Parse the response from the destination
    let destination_response: MyPacket = serde_json::from_str(&response_data).unwrap();
    println!("Response from destination: {:?}", destination_response);
}
```

## License

MIT
