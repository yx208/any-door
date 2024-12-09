use std::time::SystemTime;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore};
use rand::rngs::OsRng;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::error::{
    types::ProxyError,
    Result,
};

type HmacSha256 = Hmac<Sha256>;

const CHALLENGE_SIZE: usize = 32;
const TIMESTAMP_SIZE: usize = 8;
// 30 seconds
const AUTH_TIMEOUT: u64 = 30;

/// Handles authentication for both client and server
pub struct Authenticator {
    password: String,
}

/// 认证数据包
struct AuthenticationPacket {
    /// tls 握手的时候，产生的随机值（challenge）
    challenge: [u8; CHALLENGE_SIZE],
    timestamp: u64,
    hmac: [u8; 32],
}

impl Authenticator {
    pub fn new(password: String) -> Self {
        Self {
            password
        }
    }

    /// Server-side authentication handler
    pub async fn authenticate_client<S>(&self, stream: &mut S) -> Result<()>
        where S: AsyncRead + AsyncWrite + Unpin
    {
        // Read authentication packet
        let packet = self.read_auth_packet(stream).await?;

        // Verify timestamp to prevent replay attacks
        self.verify_timestamp(packet.timestamp)?;

        // Verify HMAC
        self.verify_hmac(&packet)?;

        // Send success response
        stream.write_u8(0x00).await?;

        Ok(())
    }

    /// Client-side authentication handler
    pub async fn authenticate_to_server<S>(&self, stream: &mut S) -> Result<()>
        where S: AsyncRead + AsyncWrite + Unpin
    {
        // Generate challenge
        let mut challenge = [0u8; CHALLENGE_SIZE];
        let mut rng = OsRng;
        rng.fill_bytes(&mut challenge);

        // Create authentication packet
        let packet = self.create_auth_packet(challenge).await?;

        // Send authentication packet
        self.write_auth_packet(stream, &packet).await?;

        // Read response
        let response = stream.read_u8().await?;
        if response != 0x00 {
            return Err(ProxyError::AuthenticationFailed("Server rejected authentication".to_string()));
        }

        Ok(())
    }

    async fn create_auth_packet(&self, challenge: [u8; CHALLENGE_SIZE]) -> Result<AuthenticationPacket> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| ProxyError::OSError(err.to_string()))?
            .as_secs();

        let mut mac = HmacSha256::new_from_slice(self.password.as_bytes())
            .map_err(|err| ProxyError::AuthenticationFailed(err.to_string()))?;

        mac.update(&challenge);
        mac.update(&timestamp.to_be_bytes());

        let hmac: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(AuthenticationPacket {
            challenge,
            timestamp,
            hmac
        })
    }

    async fn write_auth_packet<S>(&self, stream: &mut S, packet: &AuthenticationPacket) -> Result<()>
        where S: AsyncWrite + Unpin
    {
        stream.write_all(&packet.challenge).await?;
        stream.write_all(&packet.timestamp.to_be_bytes()).await?;
        stream.write_all(&packet.hmac).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn read_auth_packet<S>(&self, stream: &mut S) -> Result<AuthenticationPacket>
        where S: AsyncRead + Unpin
    {
        let mut challenge = [0u8; CHALLENGE_SIZE];
        stream.read_exact(&mut challenge).await?;

        let timestamp = stream.read_u64().await?;

        let mut hmac = [0u8; 32];
        stream.read_exact(&mut hmac).await?;

        Ok(AuthenticationPacket {
            challenge,
            timestamp,
            hmac
        })
    }

    fn verify_timestamp(&self, timestamp: u64) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| ProxyError::OSError(err.to_string()))?
            .as_secs();

        if current_time.saturating_sub(timestamp) > AUTH_TIMEOUT {
            return Err(ProxyError::AuthenticationFailed(
                "Authentication packet expired".to_string()
            ));
        }

        Ok(())
    }

    fn verify_hmac(&self, packet: &AuthenticationPacket) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(self.password.as_bytes())
            .map_err(|err| ProxyError::AuthenticationFailed(err.to_string()))?;

        mac.update(&packet.challenge);
        mac.update(&packet.timestamp.to_be_bytes());

        mac.verify_slice(&packet.hmac)
            .map_err(|_| ProxyError::AuthenticationFailed(
                "Invalid authentication credentials".to_string()
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_successful_authentication() {
        let password = "test_password".to_string();
        let (mut client, mut server) = duplex(64);

        let client_auth = Authenticator::new(password.clone());
        let server_auth = Authenticator::new(password);

        let client_task = tokio::spawn(async move {
            // 使用 client 往 server 写
            client_auth.authenticate_to_server(&mut client).await.unwrap()
        });

        let server_task = tokio::spawn(async move {
            server_auth.authenticate_client(&mut server).await.unwrap()
        });

        let (client_result, server_result) = tokio::join!(client_task, server_task);

        assert!(client_result.is_ok());
        assert!(server_result.is_ok());
    }
}
