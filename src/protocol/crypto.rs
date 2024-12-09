use aes_gcm::{aead::{Aead, KeyInit, OsRng}, AeadCore, Aes256Gcm, Key, Nonce};
use sha2::{Sha256, Digest};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, BufMut};
use crate::error::{Result, types::ProxyError};

const NONCE_SIZE: usize = 32;
const TAG_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const MAX_PAYLOAD_SIZE: usize = 32;

pub struct CryptoStream<S> {
    inner: S,
    cipher: Aes256Gcm,
    buffer: BytesMut,
}

impl<S> CryptoStream<S> where S: AsyncRead + AsyncWrite + Unpin {
    /// 根据密码创建一个新的加密流
    pub fn new(steam: S, password: &str) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let finalized = hasher.finalize();
        let key = Key::<Aes256Gcm>::from_slice(&finalized);

        let cipher = Aes256Gcm::new(&key);

        Ok(Self {
            inner: steam,
            cipher,
            buffer: BytesMut::with_capacity(MAX_PAYLOAD_SIZE),
        })
    }

    /// 将加密数据写入底层流
    pub async fn write_encrypted(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_PAYLOAD_SIZE {
            return Err(ProxyError::EncryptionError(
                "Payload size exceeds maximum".to_string()
            ))
        }

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the data
        let ciphertext = self.cipher
            .encrypt(&nonce, data)
            .map_err(|err| ProxyError::EncryptionError(err.to_string()))?;

        let total_len = NONCE_SIZE + ciphertext.len();
        self.inner.write_u16(total_len as u16).await?;
        self.inner.write_all(&nonce).await?;
        self.inner.write_all(&ciphertext).await?;
        self.inner.flush().await?;

        Ok(())
    }

    /// 从底层流中读取并解密数据
    pub async fn read_encrypted(&mut self) -> Result<BytesMut> {
        // 读取帧长度
        let frame_len = self.inner.read_u16().await? as usize;
        if frame_len < NONCE_SIZE || frame_len > MAX_PAYLOAD_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(ProxyError::EncryptionError("Invalid frame length".to_string()));
        }

        // Read nonce
        let mut nonce = [0u8; NONCE_SIZE];
        self.inner.read_exact(&mut nonce).await?;
        let nonce = Nonce::from_slice(&nonce);

        // Read ciphertext
        let ciphertext_len = frame_len - NONCE_SIZE;
        self.buffer.clear();
        self.buffer.resize(ciphertext_len, 0);
        self.inner.read_exact(&mut self.buffer).await?;

        // Decrypt the data
        let plaintext = self.cipher
            .decrypt(nonce, &self.buffer)
            .map_err(|err| ProxyError::EncryptionError(err.to_string()))?;

        Ok(BytesMut::from(&plaintext))
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// 用于密钥派生和管理的辅助函数
pub mod key_utils {
    use super::*;
    use rand::Rng;

    /// Generate a secure random key
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill(&mut key);
        key
    }

    /// 使用 PBKDF2 从密码派生密钥
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
        use pbkdf2::{pbkdf2_hmac};

        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 1000, &mut key);

        Ok(key)
    }
}

/// 数据报协议的加密数据包
pub struct EncryptedPacket {
    nonce: [u8; NONCE_SIZE],
    payload: Vec<u8>,
}

impl EncryptedPacket {
    pub fn new(cipher: &Aes256Gcm, data: &[u8]) -> Result<Self> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = cipher
            .encrypt(&nonce, data)
            .map_err(|err| ProxyError::EncryptionError(err.to_string()))?;

        Ok(Self {
            nonce: nonce.into(),
            payload
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::OsRng;
    use aes_gcm::Aes256Gcm;

    #[test]
    fn test() {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        println!("{:?}", nonce);
    }

}

