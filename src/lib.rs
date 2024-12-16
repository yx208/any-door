#![allow(warnings)]

pub mod error;
pub mod config;
pub mod protocol;
pub mod transport;
pub mod utils;

use std::net::{Ipv4Addr, Ipv6Addr};
use aes_gcm::aead::Buffer;
use crate::error::{ProxyError, Result};

/// 协议版本
pub const PROTOCOL_VERSION: u8 = 0x01;

/// 网络操作的默认缓冲区大小
pub const DEFAULT_BUFFER_SIZE: usize = 1024 * 8;

/// 最大数据包大小
pub const MAX_PACKET_SIZE: usize = 1024 * 16;

/// 身份验证标头大小（以字节为单位）
pub const AUTH_HEADER_SIZE: usize = 32;

/// 协议操作（连接用意）
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = ProxyError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(ProxyError::InvalidCommand(value)),
        }
    }
}

/// 协议支持的地址类型
///
/// 在 SOCKS5 协议中，这些标识符用于表示地址类型，这是协议规范定义的：
///
/// 1. `0x01` - IPv4 地址
///    - 后跟 4 字节的 IPv4 地址
///    - 例如: `01 C0 A8 01 01` 表示 192.168.1.1
///
/// 2. `0x03` - 域名
///    - 后跟 1 字节的域名长度 + 域名内容
///    - 例如: `03 05 hello` 表示长度为 5 的域名 "hello"
///
/// 3. `0x04` - IPv6 地址
///    - 后跟 16 字节的 IPv6 地址
///    - 例如: `04 20 01 0d b8 ... 00 00` 表示一个完整的 IPv6 地址
///
/// 一个典型的 SOCKS5 连接请求可能是这样的：
/// ```txt
/// VER  CMD  RSV  ATYP  DST.ADDR  DST.PORT
/// 05   01   00   01    ...       ...
/// ```
/// 其中：
/// - VER: SOCKS 版本（0x05）
/// - CMD: 命令（01=CONNECT, 02=BIND, 03=UDP）
/// - RSV: 保留字节（0x00）
/// - ATYP: 地址类型（就是我们刚才讨论的那些值）
/// - DST.ADDR: 目标地址（格式取决于 ATYP）
/// - DST.PORT: 目标端口（2 字节）
#[derive(Debug, Clone, PartialEq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Address::Ipv4(addr) => {
                let mut bytes = vec![0x01];
                // 返回组成该地址的四个八位整数，合并于 bytes
                bytes.extend(&addr.octets());
                bytes
            }
            Address::Ipv6(addr) => {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(&addr.octets());
                bytes
            }
            Address::Domain(domain) => {
                let mut bytes = vec![0x03];
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(&domain.as_bytes());
                bytes
            }
        }
    }
}

/// 连接目标信息
#[derive(Debug, Clone)]
pub struct Target {
    pub address: Address,
    pub port: u16,
}

impl Target {
    pub fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.address.to_bytes();
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(Command::try_from(0x01).unwrap(), Command::Connect);
        assert_eq!(Command::try_from(0x02).unwrap(), Command::Bind);
        assert_eq!(Command::try_from(0x03).unwrap(), Command::UdpAssociate);
        assert!(Command::try_from(0x04).is_err());
    }

    #[test]
    fn test_address_serialization() {
        let ipv4 = Address::Ipv4("127.0.0.1".parse().unwrap());
        let domain = Address::Domain("example.com".parse().unwrap());

        let ipv4_bytes = ipv4.to_bytes();
        assert_eq!(ipv4_bytes[0], 0x01);

        let domain_bytes = domain.to_bytes();
        assert_eq!(domain_bytes[0], 0x03);
        assert_eq!(domain_bytes[1], 11);
    }
}
