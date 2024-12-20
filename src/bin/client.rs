use std::sync::Arc;
use std::time::Duration;
use log::Level;
use tokio::net::TcpStream;
use proxy_rs::config::ClientConfig;
use proxy_rs::error::{Result, ProxyError};
use proxy_rs::protocol::crypto::CryptoStream;
use proxy_rs::protocol::socks5::{Command, Reply, Socks5Handler};
use proxy_rs::{Address, Target};
use proxy_rs::protocol::authentication::Authenticator;
use proxy_rs::transport::stream::StreamManager;
use proxy_rs::transport::tcp::{StreamCopier, TcpTransport};
use proxy_rs::utils::{ConnectionLogger, Logger, MetricsLogger};

async fn handle_client_connection(
    mut local_stream: TcpStream,
    config: Arc<ClientConfig>,
    stream_manager: Arc<StreamManager>
) -> Result<()> {
    let peer_addr = local_stream.peer_addr()?;
    let stream_id = stream_manager.register_stream(peer_addr).await;
    let conn_logger = ConnectionLogger::new(stream_id, peer_addr);

    conn_logger.log_connection_established();

    // 处理 SOCKS5 握手
    let mut socks5 = Socks5Handler::new(local_stream);
    socks5.handle_handshake().await?;

    // 从 SOCKS5 请求获取目标地址
    let (command, target) = socks5.handle_request().await?;

    // 目前仅支持 CONNECT 命令
    if command != Command::Connect {
        socks5.send_error(Reply::CommandNotSupported).await?;
        return Err(ProxyError::UnsupportedFeature("Only CONNECT is supported".to_string()));
    }

    let transport = TcpTransport::new(1);
    let server_addr = match config.server_addr.ip() {
        std::net::IpAddr::V4(addr) => Target::new(Address::Ipv4(addr), config.server_addr.port()),
        std::net::IpAddr::V6(addr) => Target::new(Address::Ipv6(addr), config.server_addr.port())
    };
    let server_stream = transport.connect_to_target(&server_addr).await?;
    let mut crypto_stream = CryptoStream::new(server_stream, &config.password)?;

    // 使用服务器进行身份验证
    let authenticator = Authenticator::new(config.password.clone());
    if let Err(err) = authenticator.authenticate_to_server(&mut crypto_stream).await {
        conn_logger.log_auth_attempt(false);
        socks5.send_error(Reply::GeneralFailure).await?;
        return Err(err);
    }

    // 发送目标地址到服务器
    crypto_stream.write_encrypted(&target.to_bytes()).await?;

    // 向 SOCKS5 客户端发送成功响应
    socks5.send_reply(Reply::Succeeded, "0.0.0.0".parse().unwrap()).await?;

    conn_logger.log_target_connection(&format!("{:?}:{}", target.address, target.port));

    // 启动双向代理
    let local_stream = socks5.into_inner();
    let copier = StreamCopier::new(config.buffer_size);
    if let Err(err) = copier.copy_bidirectional(local_stream, crypto_stream).await {
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
    Logger::init(Level::Info);

    let config = Arc::new(ClientConfig::new(
        "https://example.com:9960".parse().unwrap(),
        "127.0.0.1:1080".parse().unwrap(),
        "secure_password".to_string()
    ));

    // 创建传输和流管理器
    let transport = TcpTransport::new(1000);
    let stream_manager = Arc::new(StreamManager::new());

    // 开始指标记录
    let metrics_logger = MetricsLogger::new(Duration::from_secs(60));
    metrics_logger.start_logging(stream_manager.clone()).await;

    // 创建本地 SOCKS5 服务
    let listener = transport.create_listener(config.socks_addr).await?;
    log::info!("SOCKS5 server listening on {}", config.socks_addr);

    // 接受连接
    while let Ok((stream, addr)) = transport.accept_connection(&listener).await {
        let config = config.clone();
        let stream_manager = stream_manager.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(stream, config, stream_manager).await {
                log::error!("Connection error from {}: {}", addr, err);
            }
        });
    }

    Ok(())
}