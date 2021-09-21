use crate::secure_stream::crypto::context::{EncryptContext, DecryptContext};
use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use crate::secure_stream::crypto::error::{EncryptionError, DecryptionError};

#[derive(Debug, Error)]
enum ReceiveError {
    #[error("error while decrypting message {0}")]
    Decryption(#[from] DecryptionError),

    #[error("error while reading from inner stream: {0}")]
    InnerStreamError(#[from] futures::io::Error),
}

#[derive(Debug, Error)]
enum SendError {
    #[error("error while encrypting message {0}")]
    Encryption(#[from] EncryptionError),

    #[error("error while writing message to inner stream: {0}")]
    InnerStreamError(#[from] futures::io::Error),
}

struct SecureStream<Inner> {
    i: Inner,
    enc_context: EncryptContext,
    dec_context: DecryptContext,
}

impl<Inner> SecureStream<Inner> {
    /// Create a SecureStream object with default encryption/decryption context
    fn wrap(i: Inner) -> Self {
        Self::wrap_with_context(i, Default::default(), Default::default())
    }

    /// Create a SecureStream object with default decryption context but given encryption context
    fn wrap_with_enc_context(i: Inner, enc_context: EncryptContext) -> Self {
        Self::wrap_with_context(i, enc_context, Default::default())
    }

    /// Create a SecureStream object with default encryption context but given decryption context
    fn wrap_with_dec_context(i: Inner, dec_context: DecryptContext) -> Self {
        Self::wrap_with_context(i, Default::default(), dec_context)
    }

    /// Create a SecureStream object with given encryption and decryption context
    fn wrap_with_context(i: Inner, enc_context: EncryptContext, dec_context: DecryptContext) -> Self {
        Self {
            i,
            enc_context,
            dec_context
        }
    }

    /// Get a reference to the inner read/writer
    fn inner(&self) -> &Inner {
        &self.i
    }

    /// Get a mutable reference to the inner read/writer
    fn inner_mut(&mut self) -> &mut Inner {
        &mut self.i
    }

    /// Get an owned inner read/writer
    fn into_inner(self) -> Inner {
        self.i
    }
}

impl<Inner: AsyncRead + Unpin> SecureStream<Inner> {
    /// Asynchronously wait to receive a message from this stream (with the given decryption context).
    pub async fn recv<T: Serialize + DeserializeOwned>(&mut self) -> Result<T, ReceiveError> {
        let size_length = self.dec_context.encrypted_size_len();
        let mut read_buffer = vec![0u8; size_length];


        // TODO: cancellation safety
        self.i.read_exact(&mut read_buffer).await?;

        let size: u32 = self.dec_context.decrypt(&read_buffer)?;

        let mut read_buffer = vec![0u8; size as usize];
        self.i.read_exact(&mut read_buffer).await?;

        let value = self.dec_context.decrypt(&read_buffer)?;

        Ok(value)
    }
}

impl<Inner: AsyncWrite + Unpin> SecureStream<Inner> {

    /// Asynchronously send a message over the channel (with the given encryption context)
    pub async fn send<T: Serialize + DeserializeOwned>(&mut self, value: T) -> Result<(), SendError> {
        let encrypted_data = self.enc_context.encrypt(&value)?;
        assert!(encrypted_data.len() < u32::MAX as usize);

        let encrypted_len = self.enc_context.encrypt(&(encrypted_data.len() as u32))?;

        self.i.write_all(&encrypted_len).await?;
        self.i.write_all(&encrypted_data).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::secure_stream::crypto::{gen_encrypt_keypair, generate_random_bytes};
    use crate::secure_stream::crypto::context::{DecryptContext, EncryptContext};
    use futures::io::Cursor;
    use crate::secure_stream::stream::SecureStream;


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
        let (pk1, sk1) = gen_encrypt_keypair();
        let (pk2, sk2) = gen_encrypt_keypair();

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
        let (pk1, sk1) = gen_encrypt_keypair();
        let (pk2, sk2) = gen_encrypt_keypair();

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