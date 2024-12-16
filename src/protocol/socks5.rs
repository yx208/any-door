use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::error::{Result, ProxyError};

const SOCKS5_VERSION: u8 = 0x5;
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

    pub async fn handle_request(&mut self) -> Result<(Command)> {
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

        // let address = match atyp {
        //     0x01 => {
        //         let mut addr = [0u8, 4];
        //         self.stream.read_exact(&mut addr).await?;
        //         Address::IPv4(addr.into())
        //     }
        // };

        Ok(command)
    }
}


