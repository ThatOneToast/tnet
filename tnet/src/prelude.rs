//! Prelude module that re-exports commonly used items.
//!
//! This module provides a convenient way to import all the commonly used types and traits
//! from the `tnet` library with a single import statement, reducing boilerplate in your code.
//!
//! # Example
//!
//! ```rust
//! use tnet::prelude::*;
//!
//! // Now you can use AsyncClient, AsyncListener, ImplPacket, etc. directly
//! ```

pub use crate::{
    asynch::{
        authenticator::{AuthFunction, AuthType, Authenticator},
        client::{AsyncClient, ClientEncryption, EncryptionConfig},
        listener::{
            AsyncListener, AsyncListenerErrorHandler, AsyncListenerOkHandler, HandlerSources,
            PoolRef, ResourceRef,
        },
        phantom_client::AsyncPhantomClient,
        phantom_listener::{PhantomListener, PhantomResources, PhantomSession},
        socket::TSocket,
    },
    include_tnet_packet,
    phantom::{ClientConfig, PhantomConf, PhantomPacket},
};

pub use crate::handler_registry::{HandlerRegistration, get_handler, register_handler};

pub use std::str::FromStr;
pub use tnet_macros::{PacketHeader, register_scan_dir, tlisten_for, tpacket};

pub use crate::encrypt::{Encryptor, KeyExchange};
pub use crate::errors::Error;
pub use crate::packet::{Packet as ImplPacket, PacketBody};
pub use crate::resources::Resource as ImplResource;
pub use crate::session::{Session as ImplSession, Sessions};
pub use crate::wrap_handler;

pub use futures::future::BoxFuture;
pub use serde::de::DeserializeOwned;
pub use serde::{Deserialize, Serialize};
pub use std::future::Future;
pub use std::pin::Pin;
pub use std::sync::Arc;
pub use tokio::net::TcpStream;
