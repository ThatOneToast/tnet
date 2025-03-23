//! Global handler registry for packet handlers.
//!
//! This module provides a central registry for packet handlers that allow
//! different parts of the application to register and retrieve handlers
//! for specific packet types. This enables a decoupled architecture where
//! packet handling logic can be defined separately from the server setup.
//!
//! The registry is particularly useful when combined with the `tlisten_for`
//! attribute macro which automatically registers handler functions.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};

use crate::asynch::listener::HandlerSources;
use crate::packet::Packet;
use crate::resources::Resource;
use crate::session::Session;
use futures::future::BoxFuture;

/// Type alias for packet handler functions.
///
/// This defines the signature for functions that can be registered as packet handlers.
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
pub type HandlerFn<P, S, R> =
    Arc<dyn Fn(HandlerSources<S, R>, P) -> BoxFuture<'static, ()> + Send + Sync>;

/// Global registry for packet handlers.
///
/// This static variable holds all registered packet handlers in a thread-safe container.
/// It's initialized on first use.
static HANDLER_REGISTRY: OnceLock<Mutex<HashMap<String, Box<dyn std::any::Any + Send + Sync>>>> =
    OnceLock::new();

/// Registers a handler function for a specific packet type.
///
/// This function registers a packet handler in the global registry. When a packet with the
/// specified header is received, the `AsyncListener` will look up the appropriate handler
/// and dispatch the packet to it.
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Arguments
///
/// * `packet_type` - The packet header string this handler will respond to
/// * `handler` - The handler function
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// async fn handle_login(
///     sources: HandlerSources<MySession, MyResource>,
///     packet: MyPacket
/// ) {
///     // Login handling logic
/// }
///
/// // Register the handler
/// register_handler::<MyPacket, MySession, MyResource>(
///     "LOGIN",
///     |sources, packet| Box::pin(handle_login(sources, packet))
/// );
/// ```
pub fn register_handler<P, S, R>(
    packet_type: &str,
    handler: impl Fn(HandlerSources<S, R>, P) -> BoxFuture<'static, ()> + Send + Sync + 'static,
) where
    P: Packet + 'static,
    S: Session + 'static,
    R: Resource + 'static,
{
    // Create a registry key
    let key = format!(
        "{}_{}_{}_{}",
        packet_type,
        std::any::type_name::<P>(),
        std::any::type_name::<S>(),
        std::any::type_name::<R>()
    );

    // Wrap the handler in an Arc
    let handler = Arc::new(handler) as HandlerFn<P, S, R>;

    let registry = HANDLER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut reg) = registry.lock() {
        if let Some(existing) = reg.get_mut(&key) {
            if let Some(handlers) = existing.downcast_mut::<Vec<HandlerFn<P, S, R>>>() {
                handlers.push(handler);
                return;
            }
            // If downcast fails, this is the first handler of this type
            // Replace with a new Vec containing both the old and new handlers
            if let Some(old_handler) = existing.downcast_ref::<HandlerFn<P, S, R>>() {
                let mut handlers = Vec::new();
                let old_handler_clone = old_handler.clone();
                handlers.push(old_handler_clone);
                handlers.push(handler);
                reg.insert(key, Box::new(handlers));
                return;
            }
        }

        // If we get here, there was no existing handler, so add this one
        reg.insert(key, Box::new(handler));
    }
}

/// Retrieves a handler for a specific packet type.
///
/// This function looks up the first registered handler for the specified packet type
/// in the global registry.
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Arguments
///
/// * `packet_type` - The packet header string to look up
///
/// # Returns
///
/// * `Option<HandlerFn<P, S, R>>` - The handler function if found, None otherwise
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// // Get handler for LOGIN packets
/// let handler = get_handler::<MyPacket, MySession, MyResource>("LOGIN");
///
/// if let Some(handler) = handler {
///     // Use the handler
/// }
/// ```
pub fn get_handler<P, S, R>(packet_type: &str) -> Option<HandlerFn<P, S, R>>
where
    P: Packet + 'static,
    S: Session + 'static,
    R: Resource + 'static,
{
    let handlers = get_handlers::<P, S, R>(packet_type);
    handlers.into_iter().next()
}

/// Retrieves all handlers for a specific packet type.
///
/// This function looks up all registered handlers for the specified packet type
/// in the global registry.
///
/// # Type Parameters
///
/// * `P` - The packet type implementing the `Packet` trait
/// * `S` - The session type implementing the `Session` trait
/// * `R` - The resource type implementing the `Resource` trait
///
/// # Arguments
///
/// * `packet_type` - The packet header string to look up
///
/// # Returns
///
/// * `Vec<HandlerFn<P, S, R>>` - A vector of handler functions, empty if none found
///
/// # Example
///
/// ```rust
/// use tnet::prelude::*;
///
/// // Get all handlers for LOGIN packets
/// let handlers = get_handlers::<MyPacket, MySession, MyResource>("LOGIN");
///
/// for handler in handlers {
///     // Use each handler
/// }
/// ```
pub fn get_handlers<P, S, R>(packet_type: &str) -> Vec<HandlerFn<P, S, R>>
where
    P: Packet + 'static,
    S: Session + 'static,
    R: Resource + 'static,
{
    // Create the key
    let key = format!(
        "{}_{}_{}_{}",
        packet_type,
        std::any::type_name::<P>(),
        std::any::type_name::<S>(),
        std::any::type_name::<R>()
    );

    #[cfg(test)]
    println!("Looking up handlers for key: {}", key);

    // Look up the handler(s)
    let registry = HANDLER_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(reg) = registry.lock() {
        #[cfg(test)]
        {
            println!("Registry contains {} entries", reg.len());
            for k in reg.keys() {
                println!("  Registry has key: {}", k);
            }
        }

        if let Some(handler) = reg.get(&key) {
            // Try to downcast to Vec first
            if let Some(handlers) = handler.downcast_ref::<Vec<HandlerFn<P, S, R>>>() {
                #[cfg(test)]
                println!("Found {} handlers for key: {}", handlers.len(), key);
                return handlers.clone();
            }

            // If not a Vec, try as a single handler
            if let Some(single_handler) = handler.downcast_ref::<HandlerFn<P, S, R>>() {
                #[cfg(test)]
                println!("Found single handler for key: {}", key);
                return vec![single_handler.clone()];
            }
        }

        #[cfg(test)]
        println!("No handlers found for key: {}", key);
    }

    Vec::new()
}

/// A marker struct for handler registration.
///
/// This struct is used by the `tlisten_for` attribute macro to register handlers
/// at module initialization time.
pub struct HandlerRegistration {
    _marker: PhantomData<Box<dyn std::any::Any + Send + Sync>>,
}

impl HandlerRegistration {
    /// Creates a new `HandlerRegistration` that registers the provided handler.
    ///
    /// # Type Parameters
    ///
    /// * `P` - The packet type implementing the `Packet` trait
    /// * `S` - The session type implementing the `Session` trait
    /// * `R` - The resource type implementing the `Resource` trait
    ///
    /// # Arguments
    ///
    /// * `_packet_type` - The packet header string this handler will respond to
    /// * `handler` - The handler function
    ///
    /// # Returns
    ///
    /// * A new `HandlerRegistration` instance
    #[must_use]
    pub fn new<P, S, R>(
        _packet_type: &'static str,
        handler: impl Fn(HandlerSources<S, R>, P) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> Self
    where
        P: Packet + 'static,
        S: Session + 'static,
        R: Resource + 'static,
    {
        // Register the handler with the actual registry
        register_handler(_packet_type, handler);

        // Return a dummy marker struct
        Self {
            _marker: PhantomData,
        }
    }
}

// Helper module for the macro
#[doc(hidden)]
pub mod __private {
    pub use super::*;
}

#[cfg(test)]
pub fn register_test_handler<P, S, R>(
    packet_type: &str,
    handler: impl Fn(HandlerSources<S, R>, P) -> BoxFuture<'static, ()> + Send + Sync + 'static,
) where
    P: Packet + 'static,
    S: Session + 'static,
    R: Resource + 'static,
{
    register_handler(packet_type, handler);
}

#[cfg(test)]
pub fn reset_registry() {
    if let Some(registry) = HANDLER_REGISTRY.get() {
        if let Ok(mut reg) = registry.lock() {
            println!("Clearing handler registry with {} entries", reg.len());
            reg.clear();
        }
    }
}

#[cfg(test)]
pub fn has_handler<P, S, R>(packet_type: &str) -> bool
where
    P: Packet + 'static,
    S: Session + 'static,
    R: Resource + 'static,
{
    !get_handlers::<P, S, R>(packet_type).is_empty()
}
