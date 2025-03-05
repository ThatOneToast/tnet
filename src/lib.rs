#![warn(clippy::all)]
#![warn(clippy::nursery)]
#![warn(clippy::complexity)]
#![warn(clippy::perf)]
#![warn(clippy::correctness)]
#![warn(clippy::cargo)]

//! # `TNet`
//!
//! A networking library providing async TCP client/server functionality with:
//! - Secure connections with encryption
//! - Session management
//! - Authentication
//! - Keep-alive mechanisms
//! - Broadcast capabilities
//!
//!

pub mod asynch;
pub mod encrypt;
pub mod errors;
pub mod macros;
pub mod packet;
pub mod phantom;
pub mod resources;
pub mod session;

pub mod prelude;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod relay_test;
