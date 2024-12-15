use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use crate::error::{Result, types::ProxyError};

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
}
