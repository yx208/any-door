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

    /// 调用系统参数产生的错误
    #[error("Operator system error: {0}")]
    OSError(String),
}

impl From<tokio::time::error::Elapsed> for ProxyError {
    fn from(err: tokio::time::error::Elapsed) -> ProxyError {
        ProxyError::Timeout(err.to_string())
    }
}
