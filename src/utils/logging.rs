use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Instant;
use std::io::Write;
use chrono::Local;
use colored::Colorize;
use log::{Level, LevelFilter, Metadata, Record};
use uuid::Uuid;
use crate::transport::stream::StreamManager;

static INIT: Once = Once::new();

pub struct Logger {
    level: Level,
}

impl Logger {
    pub fn init(level: Level) {
        INIT.call_once(|| {
            log::set_boxed_logger(Box::new(Logger { level }))
                .map(|()| log::set_max_level(LevelFilter::Trace))
                .expect("Failed to initialize logger");
        });
    }

    fn format_record(&self, record: &Record) -> String {
        let level_str = match record.level() {
            Level::Error => record.level().to_string().red(),
            Level::Warn => record.level().to_string().yellow(),
            Level::Info => record.level().to_string().green(),
            Level::Debug => record.level().to_string().blue(),
            Level::Trace => record.level().to_string().cyan(),
        };

        format!(
            "{} [{:<5}] [{}:{}] {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            level_str,
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.args()
        )
    }
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let formatted = self.format_record(record);
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "{}", formatted).expect("Failed to write log");
        }
    }

    fn flush(&self) {}
}

#[derive(Debug)]
pub struct ConnectionLogger {
    stream_id: Uuid,
    client_addr: SocketAddr,
}

impl ConnectionLogger {
    pub fn new(stream_id: Uuid, client_addr: SocketAddr) -> Self {
        Self { stream_id, client_addr }
    }

    pub fn log_connection_established(&self) {
        log::info!(
            "Connection established - Stream: {}, Client: {}",
            self.stream_id,
            self.client_addr
        );
    }

    pub fn log_connection_closed(&self, bytes_transferred: u64) {
        log::info!(
            "Connection closed - Stream: {}, Client: {}, Bytes transferred: {}",
            self.stream_id,
            self.client_addr,
            bytes_transferred
        );
    }

    pub fn log_error(&self, error: &str) {
        log::error!(
            "Connection error - Stream: {}, Client: {}, Error: {}",
            self.stream_id,
            self.client_addr,
            error
        );
    }

    pub fn log_auth_attempt(&self, success: bool) {
        if success {
            log::info!(
                "Authentication successful - Stream: {}, Client: {}",
                self.stream_id,
                self.client_addr
            );
        } else {
            log::warn!(
                "Authentication failed - Stream: {}, Client: {}",
                self.stream_id,
                self.client_addr
            );
        }
    }

    pub fn log_target_connection(&self, target: &str) {
        log::info!(
            "Target connection established - Stream: {}, Client: {}, Target: {}",
            self.stream_id,
            self.client_addr,
            target
        );
    }
}

pub struct MetricsLogger {
    start_time: Instant,
    interval: std::time::Duration,
}

impl MetricsLogger {
    pub fn new(interval: std::time::Duration) -> Self {
        Self {
            start_time: Instant::now(),
            interval,
        }
    }

    pub async fn start_logging(&self, stream_manager: Arc<StreamManager>) {
        let interval = self.interval;
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;
                let uptime = Instant::now().duration_since(start_time);
                let active_streams = stream_manager.get_active_streams().await;

                let total_bytes: u64 = active_streams
                    .iter()
                    .map(|(_, info)| info.bytes_transferred)
                    .sum();

                log::info!(
                    "Metrics - Uptime: {:?}, Active connections: {}, Total bytes transferred: {}",
                    uptime,
                    active_streams.len(),
                    total_bytes
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_initialization() {
        Logger::init(Level::Debug);
        assert!(log::log_enabled!(Level::Debug));
        assert!(!log::log_enabled!(Level::Trace));
    }

    #[test]
    fn test_connection_logger() {
        Logger::init(Level::Info);
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let stream_id = Uuid::new_v4();
        let logger = ConnectionLogger::new(stream_id, addr);

        logger.log_connection_established();
        logger.log_auth_attempt(true);
        logger.log_target_connection("example.com:443");
        logger.log_connection_closed(1024);
        logger.log_error("Test error");
    }

    #[tokio::test]
    async fn test_metrics_logger() {
        use std::time::Duration;
        use crate::transport::stream::StreamManager;

        Logger::init(Level::Info);
        let manager = Arc::new(StreamManager::new());
        let metrics_logger = MetricsLogger::new(Duration::from_secs(1));

        // Add some test streams
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        manager.register_stream(addr).await;

        // Start metrics logging
        metrics_logger.start_logging(manager).await;

        // Wait for one logging interval
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
