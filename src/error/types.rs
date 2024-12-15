use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    IO(#[from] io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Operator system error: {0}")]
    OSError(String),

    #[error("SOCKS5 error: {0}")]
    Socks5Error(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

impl From<tokio::time::error::Elapsed> for ProxyError {
    fn from(err: tokio::time::error::Elapsed) -> ProxyError {
        ProxyError::Timeout(err.to_string())
    }
}
