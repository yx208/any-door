pub mod types;

pub type Result<T> = anyhow::Result<T, types::ProxyError>;
