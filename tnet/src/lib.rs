#![warn(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::complexity)]
#![warn(clippy::perf)]
#![warn(clippy::correctness)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

//! # `TNet`
//!
//! A comprehensive networking library providing async TCP client/server functionality with:
//! - Secure connections with encryption
//! - Session management
//! - Authentication
//! - Keep-alive mechanisms
//! - Broadcast capabilities
//! - Automatic reconnection with exponential backoff
//! - Relay/proxy functionality
//!
//! ## Key Components
//!
//! - [`AsyncClient`](asynch::client::AsyncClient): Client implementation for connecting to servers
//! - [`AsyncListener`](asynch::listener::AsyncListener): Server implementation for handling connections
//! - [`Packet`](packet::Packet): Trait for defining network packet formats
//! - [`Session`](session::Session): Trait for managing client sessions
//! - [`Authenticator`](asynch::authenticator::Authenticator): Handles authentication
//! - [`PhantomListener`](asynch::phantom_listener::PhantomListener): Network relay server
//! - [`PhantomClient`](asynch::phantom_client::AsyncPhantomClient): Client for relay operations
//!
//! ## Macros
//!
//! - [`tlisten_for`](../tnet_macros/attr.tlisten_for.html): Register packet handlers
//! - [`PacketHeader`](../tnet_macros/derive.PacketHeader.html): Create enum-based packet headers
//!
//! ## Example
//!
//! ```rust
//! use tnet::prelude::*;
//! use serde::{Serialize, Deserialize};
//! use std::time::{Duration, SystemTime, UNIX_EPOCH};
//!
//! // Define packet type
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! struct MyPacket {
//!     header: String,
//!     body: PacketBody,
//! }
//!
//! // Implement the Packet trait
//! impl ImplPacket for MyPacket {
//!     fn header(&self) -> String { self.header.clone() }
//!     fn body(&self) -> PacketBody { self.body.clone() }
//!     fn body_mut(&mut self) -> &mut PacketBody { &mut self.body }
//!
//!     fn ok() -> Self {
//!         Self { header: "OK".to_string(), body: PacketBody::default() }
//!     }
//!
//!     fn error(error: Error) -> Self {
//!         Self {
//!             header: "ERROR".to_string(),
//!             body: PacketBody::with_error_string(&error.to_string()),
//!         }
//!     }
//!
//!     fn keep_alive() -> Self {
//!         Self { header: "KEEPALIVE".to_string(), body: PacketBody::default() }
//!     }
//! }
//!
//! // Define session type
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! struct MySession {
//!     id: String,
//!     created_at: u64,
//!     duration: Duration,
//! }
//!
//! impl ImplSession for MySession {
//!     fn id(&self) -> &str { &self.id }
//!     fn created_at(&self) -> u64 { self.created_at }
//!     fn lifespan(&self) -> Duration { self.duration }
//!
//!     fn empty(id: String) -> Self {
//!         Self {
//!             id,
//!             created_at: SystemTime::now()
//!                 .duration_since(UNIX_EPOCH)
//!                 .unwrap()
//!                 .as_secs(),
//!             duration: Duration::from_secs(3600),
//!         }
//!     }
//! }
//! ```

use std::sync::Mutex;

use once_cell::sync::Lazy;

pub mod asynch;
pub mod encrypt;
pub mod errors;
pub mod macros;
pub mod packet;
pub mod phantom;
pub mod resources;
pub mod session;

pub mod handler_registry;
pub mod prelude;

#[cfg(test)]
mod tests;
static PACKET_REGISTRY: Lazy<Mutex<Vec<(String, String)>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn refresh_packet_registry() -> bool {
    use std::fs;
    let temp_dir = std::env::temp_dir().join("tnet_registry");
    let trigger_file = temp_dir.join("tnet_rebuild_trigger");

    match fs::create_dir_all(&temp_dir) {
        Ok(_) => fs::write(&trigger_file, "refresh").is_ok(),
        Err(_) => false,
    }
}

pub fn register_packet_type(field_name: &str, type_name: &str) {
    if let Ok(mut registry) = PACKET_REGISTRY.lock() {
        registry.push((field_name.to_string(), type_name.to_string()));
    }
}



/// Includes the generated TnetPacket type in the current scope.
///
/// This macro should be used after setting up your build script with tnet-build.
#[macro_export]
macro_rules! include_tnet_packet {
    () => {
        // For normal compilation, just include the generated file
        #[cfg(not(doctest))]
        include!(concat!(env!("OUT_DIR"), "/tnet_packet.rs"));

        // For doctests, provide a minimal stub
        #[cfg(doctest)]
        pub struct TnetPacket {
            pub header: String,
            pub body: $crate::packet::PacketBody,
        }

        #[cfg(doctest)]
        impl $crate::packet::Packet for TnetPacket {
            fn header(&self) -> String {
                self.header.clone()
            }
            fn body(&self) -> $crate::packet::PacketBody {
                self.body.clone()
            }
            fn body_mut(&mut self) -> &mut $crate::packet::PacketBody {
                &mut self.body
            }
            fn ok() -> Self {
                Self {
                    header: "OK".to_string(),
                    body: $crate::packet::PacketBody::default(),
                }
            }
            fn error(error: $crate::errors::Error) -> Self {
                Self {
                    header: "ERROR".to_string(),
                    body: $crate::packet::PacketBody::with_error_string(error),
                }
            }
            fn keep_alive() -> Self {
                Self {
                    header: "KEEPALIVE".to_string(),
                    body: $crate::packet::PacketBody::default(),
                }
            }
        }
    };
}
