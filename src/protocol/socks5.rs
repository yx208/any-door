use std::fmt::format;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::{Address, Target};
use crate::error::{Result, ProxyError};

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTHENTICATION: u8 = 0x00;
const NO_ACCEPTABLE_METHODS: u8 = 0xFF;

/// SOCKS5 command types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

/// SOCKS5 address types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

/// SOCKS5 reply codes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

pub struct Socks5Handler<S> {
    stream: S,
}

impl<S> Socks5Handler<S> where S: AsyncRead + AsyncWrite + Unpin {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// 处理初始化 socks5 握手
    pub async fn handle_handshake(&mut self) -> Result<()> {
        // Read version
        let version = self.stream.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err(ProxyError::Socks5Error(format!("Unsupported SOCKS5 version: {}", version)));
        }

        // Read number of methods
        let nmethods = self.stream.read_u8().await?;
        let mut methods = vec![0u8; nmethods as usize];
        self.stream.read_exact(&mut methods).await?;

        // Check if no authentication method is supported
        if !methods.contains(&NO_AUTHENTICATION) {
            self.stream.write_all(&[SOCKS5_VERSION, NO_ACCEPTABLE_METHODS]).await?;
            return Err(ProxyError::Socks5Error("No acceptable authentication methods found".to_string()));
        }

        // Send no authentication required
        self.stream.write_all(&[SOCKS5_VERSION, NO_AUTHENTICATION]).await?;

        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<(Command, Target)> {
        let version = self.stream.read_u8().await?;
        if version != SOCKS5_VERSION {
            return Err(ProxyError::Socks5Error(
                "Invalid SOCKS5 version in request".to_string()
            ))
        }

        let cmd = self.stream.read_u8().await?;
        let command = match cmd {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => return Err(ProxyError::Socks5Error(format!("Unsupported command: {}", cmd)))
        };

        // Skip reserved byte
        self.stream.read_u8().await?;

        let atyp = self.stream.read_u8().await?;
        let address = match atyp {
            // Ipv4
            0x01 => {
                let mut addr = [0u8; 4];
                self.stream.read_exact(&mut addr).await?;
                Address::Ipv4(addr.into())
            }
            // Domain
            0x03 => {
                // 获取域名长度
                let len = self.stream.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                // 读取域名长度的大小
                self.stream.read_exact(&mut domain).await?;
                // 尝试转换
                let domain = String::from_utf8(domain)?;
                Address::Domain(domain)
            }
            // Ipv6
            0x04 => {
                let mut addr = [0u8; 16];
                self.stream.read_exact(&mut addr).await?;
                Address::Ipv6(addr.into())
            }
            _ => return Err(ProxyError::Socks5Error(
                format!("Unsupported address type: {}", atyp)
            ))
        };

        // 读取端口
        let port = self.stream.read_u16().await?;

        Ok((command, Target::new(address, port)))
    }

    /// 发送 SOCKS5 回复
    pub async fn send_reply(&mut self, reply: Reply, bind_addr: SocketAddr) -> Result<()> {
        let mut response = vec![
            SOCKS5_VERSION,
            reply as u8,
            0x00, // Reserved
        ];

        // 添加绑定地址
        match bind_addr.ip() {
            IpAddr::V4(addr) => {
                response.push(0x01);
                response.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                response.push(0x04);
                response.extend_from_slice(&addr.octets());
            }
        }

        // 添加绑定端口
        response.extend_from_slice(&bind_addr.port().to_be_bytes());

        self.stream.write_all(&response).await?;

        Ok(())
    }

    /// 发送错误回复
    pub async fn send_error(&mut self, reply: Reply) -> Result<()> {
        // 使用虚拟地址进行错误响应
        let dummy_addr = SocketAddr::new(IpAddr::V4("0.0.0.0".parse().unwrap()), 0);
        self.send_reply(reply, dummy_addr).await
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_socks5_handshake() {
        let (client, server) = duplex(64);
        let mut handler = Socks5Handler::new(server);

        // Simulate client handshake
        tokio::spawn(async move {
            let mut client = client;
            // Send handshake request
            client.write_all(&[
                SOCKS5_VERSION,
                1, // One method
                NO_AUTHENTICATION,
            ]).await.unwrap();

            // Read response
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [SOCKS5_VERSION, NO_AUTHENTICATION]);
        });

        // Handle server-side handshake
        assert!(handler.handle_handshake().await.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_connect_request() {
        let (client, server) = duplex(128);
        let mut handler = Socks5Handler::new(server);

        // Simulate client connect request
        tokio::spawn(async move {
            let mut client = client;
            // Send connect request for example.com:80
            let request = [
                SOCKS5_VERSION,
                Command::Connect as u8,
                0x00, // Reserved
                0x03, // Domain address type
                11,   // Domain length
                b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0x00, 0x50, // Port 80
            ];
            client.write_all(&request).await.unwrap();
        });

        // Handle server-side request
        let (command, target) = handler.handle_request().await.unwrap();
        assert_eq!(command, Command::Connect);
        match target.address {
            Address::Domain(domain) => assert_eq!(domain, "example.com"),
            _ => panic!("Expected domain address"),
        }
        assert_eq!(target.port, 80);
    }
}
