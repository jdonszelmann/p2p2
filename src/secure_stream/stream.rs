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
    fn wrap(i: Inner) -> Self {
        Self::wrap_with_context(i, Default::default(), Default::default())
    }

    fn wrap_with_enc_context(i: Inner, enc_context: EncryptContext) -> Self {
        Self::wrap_with_context(i, enc_context, Default::default())
    }

    fn wrap_with_dec_context(i: Inner, dec_context: DecryptContext) -> Self {
        Self::wrap_with_context(i, Default::default(), dec_context)
    }

    fn wrap_with_context(i: Inner, enc_context: EncryptContext, dec_context: DecryptContext) -> Self {
        Self {
            i,
            enc_context,
            dec_context
        }
    }
}

impl<Inner: AsyncRead + Unpin> SecureStream<Inner> {
    pub async fn recv<T: Serialize + DeserializeOwned>(&mut self) -> Result<T, ReceiveError> {
        let size_length = self.dec_context.encrypted_size_len();
        let mut read_buffer = vec![0u8; size_length];

        self.i.read_exact(&mut read_buffer).await?;

        let size: u32 = self.dec_context.decrypt(&read_buffer)?;

        let mut read_buffer = vec![0u8; size as usize];
        self.i.read_exact(&mut read_buffer).await?;

        let value = self.dec_context.decrypt(&read_buffer)?;

        Ok(value)
    }
}

impl<Inner: AsyncWrite + Unpin> SecureStream<Inner> {
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
    use crate::secure_stream::crypto::gen_encrypt_keypair;
    use crate::secure_stream::crypto::context::{DecryptContext, EncryptContext};
    use futures::io::Cursor;
    use crate::secure_stream::stream::SecureStream;

    // use super::*;
    // use crate::DEFAULT_MAX_PAYLOAD_SIZE;
    // use hamcrest2::prelude::*;
    // use maidsafe_utilities::serialisation::serialise;
    // use safe_crypto::gen_encrypt_keypair;
    //
    // mod serialize_with_len {
    //     use super::*;
    //
    //     proptest! {
    //         #[test]
    //         fn it_writes_encrypted_data_length(data_len in (0..65000)) {
    //             let data_len = data_len as usize;
    //             let exp_serialised = unwrap!(serialise(&vec![1u8; data_len]));
    //             let crypto_ctx = EncryptContext::null();
    //
    //             let buf = unwrap!(serialize_with_len(vec![1u8; data_len], &crypto_ctx));
    //
    //             assert_that!(buf.len(), eq(exp_serialised.len() + crypto_ctx.encrypted_size_len()));
    //         }
    //     }
    // }
    //
    // mod len_delimited_reader {
    //     use super::*;
    //
    //     mod try_read {
    //         use super::*;
    //
    //         #[test]
    //         fn it_deserializes_data_from_bytes() {
    //             let mut reader = LenDelimitedReader::new(2 * 1024 * 1024);
    //             let buf = unwrap!(serialize_with_len(vec![1, 2, 3], &EncryptContext::null()));
    //             reader.put_buf(&buf);
    //
    //             let data = unwrap!(reader.try_read());
    //
    //             assert_eq!(data, Some(vec![1, 2, 3]));
    //         }
    //
    //         #[test]
    //         fn it_deserializes_data_from_bytes_when_there_is_extra_bytes_buffered() {
    //             let mut reader = LenDelimitedReader::new(2 * 1024 * 1024);
    //             let buf = unwrap!(serialize_with_len(vec![1, 2, 3], &EncryptContext::null()));
    //             reader.put_buf(&buf);
    //             let buf = unwrap!(serialize_with_len(vec![4], &EncryptContext::null()));
    //             reader.put_buf(&buf);
    //
    //             let data = unwrap!(reader.try_read());
    //
    //             assert_eq!(data, Some(vec![1, 2, 3]));
    //         }
    //
    //         #[test]
    //         fn when_data_len_is_0_it_returns_none() {
    //             let mut reader = LenDelimitedReader::new(2 * 1024 * 1024);
    //             reader.put_buf(&[0, 0, 0, 0]);
    //
    //             let data: Option<Vec<u8>> = unwrap!(reader.try_read());
    //
    //             assert_eq!(data, None);
    //         }
    //     }
    //
    //     mod try_read_header {
    //         use super::*;
    //
    //         #[test]
    //         fn when_data_len_is_0_it_returns_false() {
    //             let mut reader = LenDelimitedReader::new(2 * 1024 * 1024);
    //             reader.put_buf(&[0, 0, 0, 0]);
    //
    //             let res = unwrap!(reader.try_read_header());
    //
    //             assert_eq!(res, false);
    //             assert_eq!(reader.read_len, 0);
    //         }
    //     }
    // }
    //

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