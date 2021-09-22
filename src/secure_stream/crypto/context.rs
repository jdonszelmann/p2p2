//! This is a highly modified version of
//! https://github.com/maidsafe-archive/socket-collection/blob/master/src/crypto.rs
//! which is licensed under the MIT license (2018; MaidSafe.net limited).

use crate::secure_stream::crypto::error::{DecryptionError, EncryptionError};
use crate::secure_stream::crypto::public::PublicEncryptKey;
use crate::secure_stream::crypto::secret::SecretEncryptKey;
use crate::secure_stream::crypto::shared::SharedSecretKey;
use crate::secure_stream::serialize::{deserialize, serialize};
use serde::de::DeserializeOwned;
use serde::Serialize;

// safe_crypto always serializes 32 bit number into 52 byte array
const ENCRYPTED_U32_LEN: usize = 52;
// bincode serializes 32 bit number into 4 byte array
const SERIALIZED_U32_LEN: usize = 4;

/// Simplifies encryption by holding the necessary context - encryption keys.
/// Allows "null" encryption where data is only serialized. See: null object pattern.
#[derive(Clone, Debug)]
pub enum EncryptContext {
    /// No encryption.
    NoEncryption,
    /// Encryption + authentication
    Authenticated { shared_key: SharedSecretKey },
    /// No message authentication. Only encrypt operation is allowed.
    AnonymousEncrypt {
        /// Their public key.
        their_pk: PublicEncryptKey,
    },
}

impl Default for EncryptContext {
    /// Default is "null" encryption.
    fn default() -> Self {
        Self::no_encryption()
    }
}

impl EncryptContext {
    /// Constructs "no_encryption" encryption context which actually does no encryption.
    /// In this case data is simply serialized but not encrypted.
    pub fn no_encryption() -> Self {
        EncryptContext::NoEncryption
    }

    /// Construct crypto context that encrypts and authenticate messages.
    pub fn authenticated(shared_key: SharedSecretKey) -> Self {
        EncryptContext::Authenticated { shared_key }
    }

    /// Constructs crypto context that is only meant for unauthenticated encryption.
    pub fn anonymous_encrypt(their_pk: PublicEncryptKey) -> Self {
        EncryptContext::AnonymousEncrypt { their_pk }
    }

    /// Serialize given structure and encrypt it.
    pub fn encrypt<T: Serialize>(&self, msg: &T) -> Result<Vec<u8>, EncryptionError> {
        Ok(match *self {
            EncryptContext::NoEncryption => serialize(msg)?,
            EncryptContext::Authenticated { ref shared_key } => shared_key.encrypt(msg)?,
            EncryptContext::AnonymousEncrypt { ref their_pk } => {
                their_pk.anonymously_encrypt(msg)?
            }
        })
    }

    /// Our data size is 32 bit number. When we encrypt this number with `safe_crypto`, we get a
    /// constant size byte array. This size depends on encryption variation though.
    pub fn encrypted_size_len(&self) -> usize {
        match *self {
            EncryptContext::NoEncryption => SERIALIZED_U32_LEN,
            EncryptContext::Authenticated { .. } => ENCRYPTED_U32_LEN,
            EncryptContext::AnonymousEncrypt { .. } => ENCRYPTED_U32_LEN,
        }
    }
}

/// Simplifies decryption by holding the necessary context - keys to decrypt data.
/// Allows "null" decryption where data is only deserialized. See: null object pattern.
#[derive(Clone, Debug)]
pub enum DecryptContext {
    /// No encryption.
    NoEncryption,
    /// Encryption + authentication
    Authenticated { shared_key: SharedSecretKey },
    /// No message authentication. Only decrypt operation is allowed.
    AnonymousDecrypt {
        /// Our private key.
        our_pk: PublicEncryptKey,
        /// Our secret key.
        our_sk: SecretEncryptKey,
    },
}

impl Default for DecryptContext {
    /// Default is "null" encryption.
    fn default() -> Self {
        Self::no_encryption()
    }
}

impl DecryptContext {
    /// Contructs "null" encryption context which actually does no encryption.
    /// In this case data is simply serialized but not encrypted.
    pub fn no_encryption() -> Self {
        DecryptContext::NoEncryption
    }

    /// Construct crypto context that encrypts and authenticate messages.
    pub fn authenticated(shared_key: SharedSecretKey) -> Self {
        DecryptContext::Authenticated { shared_key }
    }

    /// Constructs crypto context that is only meant for unauthenticated decryption.
    pub fn anonymous_decrypt(our_pk: PublicEncryptKey, our_sk: SecretEncryptKey) -> Self {
        DecryptContext::AnonymousDecrypt { our_pk, our_sk }
    }

    /// Decrypt given buffer and deserialize into structure.
    pub fn decrypt<T>(&self, msg: &[u8]) -> Result<T, DecryptionError>
    where
        T: Serialize + DeserializeOwned,
    {
        Ok(match *self {
            DecryptContext::NoEncryption => deserialize(msg)?,
            DecryptContext::Authenticated { ref shared_key } => shared_key.decrypt(msg)?,
            DecryptContext::AnonymousDecrypt {
                ref our_pk,
                ref our_sk,
            } => our_sk.anonymously_decrypt(msg, our_pk)?,
        })
    }

    /// The length of encrypted size variable. The returned value must match
    /// `EncryptContext::encrypted_size_len()`, so that we could be able to decrypt it.
    pub fn encrypted_size_len(&self) -> usize {
        match *self {
            DecryptContext::NoEncryption => SERIALIZED_U32_LEN,
            DecryptContext::Authenticated { .. } => ENCRYPTED_U32_LEN,
            DecryptContext::AnonymousDecrypt { .. } => ENCRYPTED_U32_LEN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_stream::crypto::gen_encrypt_keypair;

    // TODO: make changable?
    const DEFAULT_MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

    mod encrypt_context {
        use super::*;
        use crate::secure_stream::crypto::gen_encrypt_keypair;

        #[test]
        fn encrypt_always_returns_constant_length_byte_array_for_4_byte_input_with_anonymous_encryption(
        ) {
            let (pk, _sk) = gen_encrypt_keypair();
            let enc_ctx = EncryptContext::anonymous_encrypt(pk);

            for size in &[0u32, 25000, DEFAULT_MAX_PAYLOAD_SIZE as u32, u32::MAX] {
                let encrypted = enc_ctx.encrypt(&size).unwrap();
                assert_eq!(encrypted.len(), ENCRYPTED_U32_LEN);
            }
        }

        #[test]
        fn encrypt_always_returns_constant_length_byte_array_for_4_byte_input_with_authenticated_encryption(
        ) {
            let (_, sk1) = gen_encrypt_keypair();
            let (pk2, _) = gen_encrypt_keypair();
            let enc_ctx = EncryptContext::authenticated(sk1.shared_secret(&pk2));

            for size in &[0u32, 25000, DEFAULT_MAX_PAYLOAD_SIZE as u32, u32::MAX] {
                let encrypted = enc_ctx.encrypt(&size).unwrap();
                assert_eq!(encrypted.len(), ENCRYPTED_U32_LEN);
            }
        }
    }

    #[test]
    fn null_encryption_serializes_and_deserializes_data() {
        let enc_ctx = EncryptContext::no_encryption();
        let dec_ctx = DecryptContext::no_encryption();

        let encrypted = enc_ctx.encrypt(b"test123").unwrap();
        let decrypted: [u8; 7] = dec_ctx.decrypt(&encrypted[..]).unwrap();

        assert_eq!(&decrypted, b"test123");
    }

    #[test]
    fn authenticated_encryption_encrypts_and_decrypts_data() {
        let (pk1, sk1) = gen_encrypt_keypair();
        let (pk2, sk2) = gen_encrypt_keypair();
        let enc_ctx = EncryptContext::authenticated(sk1.shared_secret(&pk2));
        let dec_ctx = DecryptContext::authenticated(sk2.shared_secret(&pk1));

        let encrypted = enc_ctx.encrypt(b"test123").unwrap();
        let decrypted: [u8; 7] = dec_ctx.decrypt(&encrypted[..]).unwrap();

        assert_eq!(&decrypted, b"test123");
    }

    #[test]
    fn anonymous_encryption() {
        let (pk1, sk1) = gen_encrypt_keypair();
        let enc_ctx = EncryptContext::anonymous_encrypt(pk1.clone());
        let dec_ctx = DecryptContext::anonymous_decrypt(pk1, sk1);

        let encrypted = enc_ctx.encrypt(b"test123").unwrap();
        let decrypted: [u8; 7] = dec_ctx.decrypt(&encrypted[..]).unwrap();

        assert_eq!(&decrypted, b"test123");
    }

    #[test]
    fn encrypted_size() {
        let (pk1, sk1) = gen_encrypt_keypair();
        let (pk2, _) = gen_encrypt_keypair();

        let enc_ctx_1 = EncryptContext::anonymous_encrypt(pk1.clone());
        let enc_ctx_2 = EncryptContext::authenticated(sk1.shared_secret(&pk2));
        let enc_ctx_3 = EncryptContext::no_encryption();

        let data = 1u32;

        let encrypted1 = enc_ctx_1.encrypt(&data).unwrap();
        assert_eq!(enc_ctx_1.encrypted_size_len(), encrypted1.len());

        let encrypted2 = enc_ctx_2.encrypt(&data).unwrap();
        assert_eq!(enc_ctx_2.encrypted_size_len(), encrypted2.len());

        let encrypted3 = enc_ctx_3.encrypt(&data).unwrap();
        assert_eq!(enc_ctx_3.encrypted_size_len(), encrypted3.len());
    }
}
