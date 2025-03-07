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

    #[error("Error: {0}")]
    Other(String),

    #[error("Invalid Client Config")]
    InvalidClientConfig,

    #[error("Invalid Client Config - There was none")]
    UnwrappedInvalidClientConfig,
}