use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum Error {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Invalid sessiond id: {0}")]
    InvalidSessionId(String),
    
    #[error("Session id expired: {0}")]
    ExpriedSessionId(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),
}
