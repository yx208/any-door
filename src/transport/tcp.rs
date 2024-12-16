use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use crate::error::{Result, ProxyError};
use crate::{Address, Target};

pub struct TcpTransport {
    max_connections: usize,
    connection_semaphore: Arc<Semaphore>,
}

impl TcpTransport {
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
        }
    }

    /// Create a new TCP listener
    pub async fn create_listener(&self, addr: SocketAddr) -> Result<TcpListener> {
        TcpListener::bind(addr)
            .await
            .map_err(|err| ProxyError::ConnectionError(err.to_string()))
    }

    /// Accept a new connection with connection limiting
    pub async fn accept_connection(&self, listener: &TcpListener) -> Result<(TcpStream, SocketAddr)> {
        // Acquire connection permit
        let _permit = self.connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|err| ProxyError::ConnectionError(err.to_string()))?;

        // Accept connection
        let (stream, addr) = listener
            .accept()
            .await
            .map_err(|err| ProxyError::ConnectionError(err.to_string()))?;

        // 在此套接字上设置 TCP-NODELAY 选项的值
        // 此选项禁用 Nagle 算法。这意味着数据段总是尽快发送，即使只有少量的数据
        // 如果不设置，数据将被缓冲，直到有足够的数据量发送出去，从而避免频繁发送小数据包
        stream.set_nodelay(true)
            .map_err(|err| ProxyError::ConnectionError(err.to_string()))?;

        Ok((stream, addr))
    }

    /// 连接到目标地址
    pub async fn connect_to_target(&self, target: &Target) -> Result<TcpStream> {
        let addr = match &target.address {
            Address::Ipv4(addr) => SocketAddr::new((*addr).into(), target.port),
            Address::Ipv6(addr) => SocketAddr::new((*addr).into(), target.port),
            Address::Domain(domain) => {
                // 执行 DNS 解析
                let addrs = tokio::net::lookup_host((domain.as_str(), target.port))
                    .await
                    .map_err(|err| ProxyError::ConnectionError(
                        format!("DNS resolution failed: {}", err)
                    ))?;

                // 尝试每个地址，直到其中一个有效
                for addr in addrs {
                    if let Ok(stream) = TcpStream::connect(addr).await {
                        stream
                            .set_nodelay(true)
                            .map_err(|e| ProxyError::ConnectionError(e.to_string()))?;
                        return Ok(stream);
                    }
                }

                // 都不成功
                return Err(ProxyError::ConnectionError(format!("Failed to connect to {}", domain)));
            }
        };

        // ipv4 or ipv6
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|err| ProxyError::ConnectionError(err.to_string()))?;

        stream.set_nodelay(true).map_err(|e| ProxyError::ConnectionError(e.to_string()))?;

        Ok(stream)
    }
}

/// 管理双向流复制
pub struct StreamCopier {
    buffer_size: usize,
}

impl StreamCopier {
    pub fn new(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    pub async fn copy_bidirectional<S1, S2>(&self, client_stream: S1, server_stream: S2) -> Result<()>
        where S1: AsyncRead + AsyncWrite + Unpin + Send + 'static,
              S2: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // 将流分割成读写两部分
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut server_read, mut server_write) = tokio::io::split(server_stream);

        let buffer_size = self.buffer_size;

        // 当客户端读取到数据，写入到服务
        let client_to_server = tokio::spawn(async move {
            let mut buffer =  vec![0u8; buffer_size];
            loop {
                let n = match client_read.read(&mut buffer).await {
                    // 连接关闭
                    Ok(0) => break,
                    // 读取的字节数
                    Ok(n) => n,
                    Err(err) => return Err(ProxyError::ConnectionError(err.to_string()))
                };

                if let Err(err) = server_write.write_all(&buffer[..n]).await {
                    return Err(ProxyError::ConnectionError(err.to_string()));
                }
            }

            Ok(())
        });

        // 当服务读取到数据，写入回客户端
        let server_to_client = tokio::spawn(async move {
            let mut buffer = vec![0u8; buffer_size];
            loop {
                let n = match server_read.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(err) => return Err(ProxyError::ConnectionError(err.to_string()))
                };

                if let Err(err) = client_write.write_all(&buffer[..n]).await {
                    return Err(ProxyError::ConnectionError(err.to_string()));
                }
            }

            Ok(())
        });

        // Wait for either direction to complete or error
        tokio::select! {
            result = client_to_server => {
                result.map_err(|err| ProxyError::ConnectionError(err.to_string()))?;
            }
            result = server_to_client => {
                result.map_err(|err| ProxyError::ConnectionError(err.to_string()))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use crate::Address::Ipv4;
    use super::*;

    #[tokio::test]
    async fn test_connection_limit() {
        let transport = TcpTransport::new(2);
        let addr = "127.0.0.1:6640".parse().unwrap();
        let listener = transport.create_listener(addr).await.unwrap();

        // 尝试建立超过允许数量的连接
        let mut connection = Vec::new();
        for _ in 0..3 {
            let result = transport.connect_to_target(&Target {
                address: Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: addr.port()
            }).await;

            if let Ok(conn) = result {
                connection.push(conn);
            }
        }

        assert_eq!(connection.len(), 2);
    }

    #[tokio::test]
    async fn test_stream_copier() {
        let (client_stream, server_stream) = tokio::io::duplex(1024);
        let copier = StreamCopier::new(1024);

        let copy_task = tokio::spawn(async move {
            copier.copy_bidirectional(client_stream, server_stream).await.unwrap();
        });

        assert!(copy_task.await.is_ok());
    }
}
