use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use crate::error::types::ProxyError;
use crate::error::Result;

fn default_timeout() -> u64 { 60 }
fn default_tls_verify() -> bool { true }
fn default_buffer_size() -> usize { 8192 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Proxy server address
    pub server_addr: SocketAddr,

    /// Local SOCKS5 listen address
    pub socks_addr:  SocketAddr,

    /// Authentication password
    pub password: String,

    #[serde(default = "default_timeout")]
    pub timeout: u64,

    #[serde(default)]
    pub verbose: bool,

    #[serde(default)]
    pub udp_support: bool,

    /// TLS verification (set to false to skip certificate verification)
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,

    /// Buffer size for network operations
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl ClientConfig {
    pub fn new(server_addr: SocketAddr, socks_addr: SocketAddr, password: String) -> Self {
        Self {
            server_addr,
            socks_addr,
            password,
            verbose: true,
            udp_support: false,
            timeout: default_timeout(),
            tls_verify: default_tls_verify(),
            buffer_size: default_buffer_size(),
        }
    }

    pub fn with_udp_support(mut self) -> Self {
        self.udp_support = true;
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

        if self.timeout == 0 {
            return Err(ProxyError::ConfigError(
                "Timeout must be greater than 0".to_string()
            ))
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use super::*;

    #[test]
    fn test_client_config() {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8388);
        let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
        let config = ClientConfig::new(server_addr, socks_addr, String::from("password"));
        assert_eq!(config.server_addr.port(), 8388);
        assert_eq!(config.socks_addr.port(), 1080);
        assert!(config.validate().is_ok());
    }
}
