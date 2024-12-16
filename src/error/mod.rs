mod types;

pub use types::ProxyError;

pub type Result<T> = anyhow::Result<T, ProxyError>;
