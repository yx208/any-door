use std::sync::Arc;
use tokio::net::TcpStream;
use proxy_rs::{
    config::ServerConfig,
    transport::stream::StreamManager,
    error::{Result, ProxyError},
    protocol::authentication::Authenticator,
    protocol::crypto::CryptoStream,
    utils::ConnectionLogger,
};

async fn handle_connection(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    stream_manager: StreamManager
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

    Ok(())
}

fn main() {}