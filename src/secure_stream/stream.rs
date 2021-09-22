use crate::secure_stream::crypto::context::{DecryptContext, EncryptContext};
use crate::secure_stream::crypto::error::{DecryptionError, EncryptionError};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::error::Error;
use std::ops::{Deref, DerefMut};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("error while decrypting message {0}")]
    Decryption(#[from] DecryptionError),

    #[error("error while reading from inner stream: {0}")]
    InnerStreamError(#[from] Box<dyn Error + Send + Sync>),

    #[error("message smaller than included length indicates")]
    TooSmall,
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("error while encrypting message {0}")]
    Encryption(#[from] EncryptionError),

    #[error("error while writing message to inner stream: {0}")]
    InnerStreamError(#[from] Box<dyn Error + Send + Sync>),

    #[error("message too large to send")]
    TooLarge,
}

pub struct SecureStream<Inner> {
    i: Inner,
    enc_context: EncryptContext,
    dec_context: DecryptContext,
}

impl<Inner> Deref for SecureStream<Inner> {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<Inner> DerefMut for SecureStream<Inner> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner_mut()
    }
}

impl<Inner> SecureStream<Inner> {
    /// Create a SecureStream object with default encryption/decryption context
    pub fn wrap(i: Inner) -> Self {
        Self::wrap_with_context(i, Default::default(), Default::default())
    }

    /// Create a SecureStream object with default decryption context but given encryption context
    pub fn wrap_with_enc_context(i: Inner, enc_context: EncryptContext) -> Self {
        Self::wrap_with_context(i, enc_context, Default::default())
    }

    /// Create a SecureStream object with default encryption context but given decryption context
    pub fn wrap_with_dec_context(i: Inner, dec_context: DecryptContext) -> Self {
        Self::wrap_with_context(i, Default::default(), dec_context)
    }

    /// Create a SecureStream object with given encryption and decryption context
    pub fn wrap_with_context(
        i: Inner,
        enc_context: EncryptContext,
        dec_context: DecryptContext,
    ) -> Self {
        Self {
            i,
            enc_context,
            dec_context,
        }
    }

    /// Get a reference to the inner read/writer
    pub fn inner(&self) -> &Inner {
        &self.i
    }

    /// Get a mutable reference to the inner read/writer
    pub fn inner_mut(&mut self) -> &mut Inner {
        &mut self.i
    }

    /// Get an owned inner read/writer
    pub fn into_inner(self) -> Inner {
        self.i
    }
}

impl<Inner: RecvBytes + Unpin> SecureStream<Inner> {
    fn decrypt_msg<T: Serialize + DeserializeOwned>(&self, msg: &[u8]) -> Result<T, ReceiveError> {
        let size_length = self.dec_context.encrypted_size_len();

        let (size, rest) = msg.split_at(size_length);

        let size: u32 = self.dec_context.decrypt(size)?;

        if size as usize > rest.len() {
            return Err(ReceiveError::TooSmall);
        }

        let value = self.dec_context.decrypt(&rest[..size as usize])?;

        Ok(value)
    }

    /// Asynchronously wait to receive a message from this stream (with the given decryption context).
    pub async fn recv<T: Serialize + DeserializeOwned>(&mut self) -> Result<T, ReceiveError> {
        let msg = self.i.recv().await?;
        self.decrypt_msg(&msg)
    }

    /// Asynchronously wait to receive a message from this stream (with the given decryption context).
    pub async fn recv_extra<T: Serialize + DeserializeOwned>(
        &mut self,
    ) -> Result<(T, <Inner as RecvBytes>::RecvExtra), ReceiveError> {
        let (msg, extra) = self.i.recv_extra().await?;
        Ok((self.decrypt_msg(&msg)?, extra))
    }
}

impl<Inner: SendBytes + Unpin> SecureStream<Inner> {
    fn encrypt_msg<T: Serialize + DeserializeOwned>(&self, value: T) -> Result<Vec<u8>, SendError> {
        let encrypted_data = self.enc_context.encrypt(&value)?;
        if let Some(max_size) = Inner::max_size() {
            if encrypted_data.len() > max_size {
                return Err(SendError::TooLarge);
            }
        }

        let encrypted_len = self.enc_context.encrypt(&(encrypted_data.len() as u32))?;

        let mut message = Vec::new();
        message.extend(encrypted_len);
        message.extend(encrypted_data);

        Ok(message)
    }

    pub async fn send_extra<T: Serialize + DeserializeOwned>(
        &mut self,
        value: T,
        extra: <Inner as SendBytes>::SendExtra,
    ) -> Result<(), SendError> {
        let msg = self.encrypt_msg(value)?;
        let res = self.i.send_extra(&msg, extra).await?;
        if res != msg.len() {
            return Err(SendError::TooLarge);
        }
        Ok(())
    }

    /// Asynchronously send a message over the channel (with the given encryption context)
    pub async fn send<T: Serialize + DeserializeOwned>(
        &mut self,
        value: T,
    ) -> Result<(), SendError> {
        let msg = self.encrypt_msg(value)?;
        let res = self.i.send(&msg).await?;
        if res != msg.len() {
            return Err(SendError::TooLarge);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait RecvBytes {
    async fn recv(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>>;

    type RecvExtra;
    async fn recv_extra(
        &mut self,
    ) -> Result<(Vec<u8>, Self::RecvExtra), Box<dyn Error + Send + Sync>>;

    fn max_size() -> Option<usize>
    where
        Self: Sized;
}

#[async_trait::async_trait]
pub trait SendBytes {
    async fn send(&mut self, message: &[u8]) -> Result<usize, Box<dyn Error + Send + Sync>>;

    type SendExtra;

    async fn send_extra(
        &mut self,
        message: &[u8],
        extra: Self::SendExtra,
    ) -> Result<usize, Box<dyn Error + Send + Sync>>;

    fn max_size() -> Option<usize>
    where
        Self: Sized;
}

#[async_trait::async_trait]
impl<T: AsyncWriteExt + Unpin + Send + Sync> SendBytes for T {
    async fn send(&mut self, message: &[u8]) -> Result<usize, Box<dyn Error + Send + Sync>> {
        self.write_all(message).await?;
        Ok(message.len())
    }

    type SendExtra = ();

    async fn send_extra(
        &mut self,
        message: &[u8],
        _extra: Self::SendExtra,
    ) -> Result<usize, Box<dyn Error + Send + Sync>> {
        self.send(message).await
    }

    fn max_size() -> Option<usize>
    where
        Self: Sized,
    {
        None
    }
}

#[async_trait::async_trait]
impl<T: AsyncReadExt + Unpin + Send + Sync> RecvBytes for T {
    async fn recv(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut res = Vec::new();
        self.read_to_end(&mut res).await?;
        Ok(res)
    }

    type RecvExtra = ();

    async fn recv_extra(
        &mut self,
    ) -> Result<(Vec<u8>, Self::RecvExtra), Box<dyn Error + Send + Sync>> {
        Ok((self.recv().await?, ()))
    }

    fn max_size() -> Option<usize>
    where
        Self: Sized,
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_stream::crypto::context::{DecryptContext, EncryptContext};
    use crate::secure_stream::crypto::{generate_random_bytes, KeyPair};
    use crate::secure_stream::stream::SecureStream;
    use futures::io::Cursor;

    #[tokio::test]
    async fn data_read_write_different_lengths() {
        for i in (0..65536).step_by(512) {
            let ec = EncryptContext::no_encryption();
            let dc = DecryptContext::no_encryption();

            let data = generate_random_bytes(i);

            let mut backing = Vec::<u8>::with_capacity(i * 2);

            {
                let writer = Cursor::new(&mut backing);
                let mut stream = SecureStream::wrap_with_enc_context(writer, ec);
                stream.send(data.clone()).await.unwrap();
            }

            assert!(backing.len() > 0);

            {
                let reader = Cursor::new(&mut backing);
                let mut stream = SecureStream::wrap_with_dec_context(reader, dc);
                let res: Vec<u8> = stream.recv().await.unwrap();

                assert_eq!(res, data);
            }
        }
    }

    #[tokio::test]
    async fn data_read_write() {
        let ec = EncryptContext::no_encryption();
        let dc = DecryptContext::no_encryption();

        let data = "message123".to_string();

        let mut backing = Vec::<u8>::with_capacity(40);

        {
            let writer = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_enc_context(writer, ec);
            stream.send(data.clone()).await.unwrap();
        }

        assert!(backing.len() > 0);

        {
            let reader = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_dec_context(reader, dc);
            let res: String = stream.recv().await.unwrap();

            assert_eq!(res, data);
        }
    }

    #[tokio::test]
    async fn data_read_write_with_encryption_extra_bytes() {
        let (pk1, sk1) = KeyPair::gen().split();
        let (pk2, sk2) = KeyPair::gen().split();

        let enc_key1 = sk1.shared_secret(&pk2);
        let enc_key2 = sk2.shared_secret(&pk1);

        let ec = EncryptContext::authenticated(enc_key1);
        let dc = DecryptContext::authenticated(enc_key2);

        let data = "message123".to_string();

        let mut backing = Vec::<u8>::with_capacity(40);

        {
            let writer = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_enc_context(writer, ec);
            stream.send(data.clone()).await.unwrap();
        }

        assert!(backing.len() > 0);

        backing.extend(vec![0xf0; 100]);

        {
            let reader = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_dec_context(reader, dc);
            let res: String = stream.recv().await.unwrap();

            assert_eq!(res, data);
        }
    }

    #[tokio::test]
    async fn data_read_write_with_encryption() {
        let (pk1, sk1) = KeyPair::gen().split();
        let (pk2, sk2) = KeyPair::gen().split();

        let enc_key1 = sk1.shared_secret(&pk2);
        let enc_key2 = sk2.shared_secret(&pk1);

        let ec = EncryptContext::authenticated(enc_key1);
        let dc = DecryptContext::authenticated(enc_key2);

        let data = "message123".to_string();

        let mut backing = Vec::<u8>::with_capacity(40);

        {
            let writer = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_enc_context(writer, ec);
            stream.send(data.clone()).await.unwrap();
        }

        assert!(backing.len() > 0);

        {
            let reader = Cursor::new(&mut backing);
            let mut stream = SecureStream::wrap_with_dec_context(reader, dc);
            let res: String = stream.recv().await.unwrap();

            assert_eq!(res, data);
        }
    }
}
