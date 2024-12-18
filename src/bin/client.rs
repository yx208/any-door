use std::sync::Arc;
use tokio::net::TcpStream;
use proxy_rs::config::ClientConfig;
use proxy_rs::error::{Result, ProxyError};
use proxy_rs::transport::stream::StreamManager;

async fn handle_client_connection(
    mut local_stream: TcpStream,
    config: Arc<ClientConfig>,
    stream_manager: Arc<StreamManager>
) -> Result<()> {


    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {


    Ok(())
}