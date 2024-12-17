use std::sync::Arc;
use tokio::net::TcpStream;
use proxy_rs::{
    config::ServerConfig,
    transport::stream::StreamManager,
    error::{Result, ProxyError},
    protocol::{
        authentication::Authenticator,
        crypto::CryptoStream,
    },
    utils::ConnectionLogger,
};

async fn handle_connection(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    stream_manager: Arc<StreamManager>
) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let stream_id = stream_manager.register_stream(peer_addr).await;
    let conn_logger = ConnectionLogger::new(stream_id, peer_addr);

    conn_logger.log_connection_established();

    // 创建加密流
    let mut crypto_stream = CryptoStream::new(stream, &config.password)?;

    // 处理认证
    let authenticator = Authenticator::new(config.password.clone());
    if let Err(e) = authenticator.authenticate_client(&mut crypto_stream).await {
        conn_logger.log_auth_attempt(false);
        return Err(e);
    }
    conn_logger.log_auth_attempt(true);

    // 读取目标地址
    let mut target_buf = [0u8; 1024];
    let n= crypto_stream.read_encrypted().await?.len();
    if n == 0 {
        return Err(ProxyError::ConnectionError("Empty target address".into()));
    }

    Ok(())
}

fn main() {}