use std::sync::Arc;
use std::time::Duration;
use log::Level;
use tokio::net::TcpStream;
use proxy_rs::transport::{
    stream::StreamManager,
    tcp::{TcpTransport, StreamCopier}
};
use proxy_rs::protocol::{
    authentication::Authenticator,
    crypto::CryptoStream,
};
use proxy_rs::config::ServerConfig;
use proxy_rs::utils::{Logger, ConnectionLogger, MetricsLogger};
use proxy_rs::{Target, Address};
use proxy_rs::error::{Result, ProxyError};

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

    // 使用加密流读取目标地址
    let bytes = crypto_stream.read_encrypted().await?;
    if bytes.is_empty() {
        return Err(ProxyError::ConnectionError("Empty target address".into()));
    }

    // 假设目标信息作为 "host:port" 字符串发送
    let target_str = String::from_utf8(bytes.to_vec())?;
    let parts: Vec<&str> = target_str.split(':').collect();
    if parts.len() != 2 {
        return Err(ProxyError::ConnectionError("Invalid target format".into()));
    }

    let host = parts[0];
    let port: u16 = parts[1].parse().map_err(|_| ProxyError::ConnectionError("Invalid port".into()))?;

    let target = if let Ok(addr) = host.parse() {
        Target::new(Address::Ipv4(addr), port)
    } else {
        Target::new(Address::Domain(host.to_string()), port)
    };

    // 连接到目标
    let transport = TcpTransport::new(1);
    let target_stream = transport.connect_to_target(&target).await?;
    let target_addr = target_stream.peer_addr()?; // 返回此流所连接的远程地址

    conn_logger.log_target_connection(&target_str);

    // 更新流信息
    stream_manager
        .update_stream(stream_id, target_addr, 0)
        .await?;

    // 启动双向代理
    let copier = StreamCopier::new(config.buffer_size);
    if let Err(err) = copier.copy_bidirectional(crypto_stream, target_stream).await {
        conn_logger.log_error(&err.to_string());
        return Err(err);
    }

    // 记录连接关闭
    if let Some(info) = stream_manager.get_stream_info(stream_id).await {
        conn_logger.log_connection_closed(info.bytes_transferred);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    Logger::init(Level::Info);

    // 加载配置
    let config = Arc::new(ServerConfig::new(
        "0.0.0.0:8388".parse().unwrap(),
        "secure_password".to_string()
    ));

    // 创建传输和流管理器
    let transport = TcpTransport::new(config.max_connections);
    let stream_manager = Arc::new(StreamManager::new());

    // 开始指标记录
    let metrics_logger = MetricsLogger::new(Duration::from_secs(60));
    metrics_logger.start_logging(stream_manager.clone()).await;

    // 创建 listener
    let listener = transport.create_listener(config.listen_addr).await?;
    log::info!("Server listening on {}", config.listen_addr);

    while let Ok((stream, addr)) = transport.accept_connection(&listener).await {
        let config = config.clone();
        let stream_manager = stream_manager.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, stream_manager).await {
                log::error!("Connection error from {}: {}", addr, e);
            }
        });
    }

    Ok(())
}