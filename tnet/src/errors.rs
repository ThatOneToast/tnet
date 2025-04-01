use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Invalid sessiond id: {0}")]
    InvalidSessionId(String),

    #[error("Session id expired: {0}")]
    ExpriedSessionId(String),

    #[error("Expected an OK Response, did not get that")]
    ExpectedOkPacket,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("DB error: {0}")]
    DbError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Session ID is required for a keep alive session")]
    KeepAliveNoSessionId,

    #[error("Invalid Client Config")]
    InvalidClientConfig,

    #[error("Invalid Client Config - There was none")]
    UnwrappedInvalidClientConfig,
    
    #[error("Invalid pool {0}")]
    InvalidPool(String),        
    
    #[error("Failed to send packet {0}")]
    FailedPacketSend(String),
    
    #[error("Failed to read packet {0}")]
    FailedPacketRead(String),
    
    #[error("Broadcast: {0}")]
    Broadcast(String),
    
    #[error("Read timeout")]
    ReadTimeout,
    
    #[error("{0}")]
    Error(String),
}