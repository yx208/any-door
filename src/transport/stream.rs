use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::{Result};

/// Manages active stream connections
pub struct StreamManager {
    active_stream: Arc<Mutex<HashMap<Uuid, StreamInfo>>>
}

#[derive(Debug)]
pub struct StreamInfo {
    pub client_addr: SocketAddr,
    pub target_addr: Option<SocketAddr>,
    pub created_at: Instant,
    pub bytes_transferred: u64,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            active_stream: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    pub async fn register_stream(&self, client_addr: SocketAddr) -> Uuid {
        let stream_id = Uuid::new_v4();
        let info = StreamInfo {
            client_addr,
            target_addr: None,
            created_at: Instant::now(),
            bytes_transferred: 0,
        };

        self.active_stream.lock().await.insert(stream_id, info);
        stream_id
    }

    pub async fn update_stream(&self, id: Uuid, target_addr: SocketAddr, bytes: u64) -> Result<()> {
        if let Some(info) = self.active_stream.lock().await.get_mut(&id) {
            info.target_addr = Some(target_addr);
            info.bytes_transferred += bytes;
        }

        Ok(())
    }

    pub async fn remove_stream(&self, id: Uuid) {
        self.active_stream.lock().await.remove(&id);
    }

    pub async fn get_stream_info(&self, id: Uuid) -> Option<StreamInfo> {
        self.active_stream.lock().await.get(&id).cloned()
    }

    pub async fn get_active_streams(&self) -> Vec<(Uuid, StreamInfo)> {
        self.active_stream
            .lock()
            .await
            .iter()
            .map(|(id, info)| (*id, info.clone()))
            .collect()
    }

    pub async fn cleanup_old_streams(&self, max_age: Duration) {
        let now = Instant::now();
        self.active_stream.lock().await.retain(|_, info| {
            now.duration_since(info.created_at) < max_age
        });
    }
}

impl Clone for StreamInfo {
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            target_addr: self.target_addr,
            created_at: self.created_at,
            bytes_transferred: self.bytes_transferred,
        }
    }
}

mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stream_lifecycle() {
        let manager = StreamManager::new();
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let target_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        // Register new stream
        let stream_id = manager.register_stream(client_addr).await;

        // Update stream
        manager.update_stream(stream_id, target_addr, 100).await.unwrap();

        // Verify stream info
        let info = manager.get_stream_info(stream_id).await.unwrap();
        assert_eq!(info.client_addr, client_addr);
        assert_eq!(info.target_addr, Some(target_addr));
        assert_eq!(info.bytes_transferred, 100);

        // Remove stream
        manager.remove_stream(stream_id).await;
        assert!(manager.get_stream_info(stream_id).await.is_none());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let manager = StreamManager::new();
        let addr: SocketAddr = "127.0.0.1:12339".parse().unwrap();

        // Register stream
        manager.register_stream(addr).await;

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Clean up streams older than 50ms
        manager.cleanup_old_streams(Duration::from_millis(50)).await;

        // Should be empty now
        assert!(manager.get_active_streams().await.is_empty());
    }
}
