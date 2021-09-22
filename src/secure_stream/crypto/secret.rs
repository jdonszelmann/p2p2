use std::sync::Arc;
use sodiumoxide::crypto::box_::{SecretKey, SECRETKEYBYTES};
use sodiumoxide::crypto::{box_, sealedbox};
use crate::secure_stream::crypto::PublicEncryptKey;
use crate::secure_stream::crypto::shared::SharedSecretKey;
use serde::{Serialize};
use crate::secure_stream::crypto::error::DecryptionError;
use crate::secure_stream::serialize::deserialize;
use serde::de::DeserializeOwned;

/// Reference counted secret encryption key used to decrypt data previously encrypted with
/// `PublicEncryptKey`.
/// Use `gen_encrypt_keypair()` to generate a public and secret key pair.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretEncryptKey {
    pub(super) inner: Arc<SecretEncryptKeyInner>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SecretEncryptKeyInner {
    pub(super) encrypt: SecretKey,
}

impl SecretEncryptKey {
    /// Construct secret key from given bytes. Useful when secret key was serialized before.
    pub fn from_bytes(secret_key: [u8; SECRETKEYBYTES]) -> Self {
        Self {
            inner: Arc::new(SecretEncryptKeyInner {
                encrypt: SecretKey(secret_key),
            }),
        }
    }

    /// Computes a shared secret from our secret key and the recipient's public key.
    pub fn shared_secret(&self, their_pk: &PublicEncryptKey) -> SharedSecretKey {
        let precomputed = Arc::new(box_::precompute(&their_pk.inner, &self.inner.encrypt));
        SharedSecretKey { precomputed }
    }

    /// Get the inner secret key representation.
    pub fn into_bytes(self) -> [u8; SECRETKEYBYTES] {
        self.inner.encrypt.0
    }

    /// Decrypts serialized `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns deserialized type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext is
    /// not valid, or if it can not be decrypted.
    pub fn anonymously_decrypt<T>(
        &self,
        ciphertext: &[u8],
        my_pk: &PublicEncryptKey,
    ) -> Result<T, DecryptionError>
        where
            T: Serialize + DeserializeOwned,
    {
        Ok(deserialize(
            &self.anonymously_decrypt_bytes(ciphertext, my_pk)?,
        )?)
    }

    /// Decrypts bytestring `ciphertext` encrypted using anonymous encryption.
    ///
    /// With anonymous encryption we won't be able to verify the sender and
    /// tell who sent the ciphertext.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` if the ciphertext is not valid or if it can not be decrypted.
    pub fn anonymously_decrypt_bytes(
        &self,
        ciphertext: &[u8],
        my_pk: &PublicEncryptKey,
    ) -> Result<Vec<u8>, DecryptionError> {
        Ok(sealedbox::open(
            ciphertext,
            &my_pk.inner,
            &self.inner.encrypt,
        ).map_err(DecryptionError::GenericDecryptionError)?)
    }
}
