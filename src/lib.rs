#[cfg(feature = "transaction")]
pub mod packet;
pub mod prelude;
#[cfg(feature = "transaction")]
pub mod session;
pub mod standard;
#[cfg(feature = "async")]
pub mod asynchronous;

pub fn init() {
    tlogger::opts::set_debug(false);
}

#[cfg(all(feature = "server", feature = "client"))]
compile_error!("features \"server\" and \"client\" cannot be enabled at the same time");

