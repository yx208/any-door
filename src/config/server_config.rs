use std::net::SocketAddr;
use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::error::ProxyError;
use crate::error::Result;

fn default_max_connections() -> usize { 1000 }
fn default_timeout() -> u64 { 300 }
fn default_buffer_size() -> usize { 1024 * 8 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,

    /// Authentication password
    pub password: String,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default)]
    pub verbose: bool,

    /// TLS certificate path (optional)
    pub tls_cert: Option<String>,

    /// TLS key path (optional)
    pub tls_key: Option<String>,

    /// Buffer size for network operations
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl ServerConfig {
    pub fn new(listen_addr: SocketAddr, password: String) -> Self {
        Self {
            listen_addr,
            password,
            max_connections: default_max_connections(),
            timeout: default_timeout(),
            buffer_size: default_buffer_size(),
            verbose: true,
            tls_cert: None,
            tls_key: None,
        }
    }

    pub fn with_tle(mut self, cert: String, key: Option<String>) -> Self {
        self.tls_cert = Some(cert);
        self.tls_key = key;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.password.len() < 8 {
            return Err(
                ProxyError::ConfigError(
                    "Password must be at least 8 characters long".to_string()
                )
            )
        }

        match (&self.tls_cert, &self.tls_key) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ProxyError::ConfigError(
                    "Both TLS certificate and key must be provided".to_string()
                ))
            }
            (Some(cert_path), Some(key_path)) => {
                if !Path::new(cert_path).exists() {
                    return Err(ProxyError::ConfigError(
                        format!("TLS certificate file not found: {}", cert_path)
                    ))
                }
                if !Path::new(key_path).exists() {
                    return Err(ProxyError::ConfigError(
                        format!("TLS key file not found: {}", key_path)
                    ))
                }
            }
            _ => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_server_config() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8388);
        let config = ServerConfig::new(server_addr, "12345678".to_string());
        assert_eq!(config.listen_addr.port(), 8388);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_password() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8388);
        let config = ServerConfig::new(addr, "short".to_string());
        assert!(config.validate().is_err());
    }
}
