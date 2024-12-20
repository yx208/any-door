mod server_config;
mod client_config;

use std::path::Path;
use serde::Deserialize;
use crate::error::Result;
pub use server_config::ServerConfig;
pub use client_config::ClientConfig;

/// 通用配置 trait
pub trait LoadConfig: Sized {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self>;
    fn validate(&self) -> Result<()>;
}

impl<T> LoadConfig for T
where
    T: for<'de> Deserialize<'de>
{
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&content);
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

