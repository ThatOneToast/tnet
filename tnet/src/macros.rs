//! Macros for use with the tnet library.
//!
//! This module provides macros that simplify common operations in the tnet library,
//! making code more concise and easier to maintain.
//!

/// Creates a wrapped async handler function compatible with the tnet server framework.
///
/// This macro transforms a regular async function into a properly wrapped handler that can be
/// used with the `AsyncListener`. It ensures type safety and proper async execution context.
///
/// # Arguments
///
/// The macro takes a single function expression that should match the handler signature requirements.
///
/// # Returns
///
/// Returns an `Arc`-wrapped closure that produces a `Pin<Box<dyn Future<Output = ()> + Send + 'static>>`.
///
/// # Example
///
/// ```rust
/// use tnet::{wrap_handler, packet::Packet, session::Session};
///
/// async fn my_handler<P: Packet, S: Session>(
///     socket: TSocket<S>,
///     packet: P,
///     pools: PoolRef<S>,
///     resources: ResourceRef<R>,
/// ) {
///     // Handler implementation
/// }
///
/// let wrapped_handler = wrap_handler!(my_handler);
/// ```
///
/// # Usage in Server Setup
///
/// ```rust
/// use tnet::{AsyncListener, wrap_handler};
///
/// async fn setup_server() {
///     let listener = AsyncListener::new(
///         ("127.0.0.1", 8080),
///         30,
///         wrap_handler!(ok_handler),
///         wrap_handler!(error_handler)
///     ).await;
/// }
/// ```
#[macro_export]
macro_rules! wrap_handler {
    ($func:expr) => {
        std::sync::Arc::new(move |sources, packet| {
            Box::pin($func(sources, packet))
                as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
        })
    };
}
