use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();
    stream.write_all(b"Hello, World!").await.unwrap();

    let mut buffer = [0; 1024];
    let content_size = stream.read(&mut buffer).await.unwrap();
    println!("Received {} bytes", content_size);
    println!("收到响应: {}", String::from_utf8_lossy(&buffer));
}