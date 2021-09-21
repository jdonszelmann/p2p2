use serde::{Serialize};
use sodiumoxide::crypto::box_;
use std::sync::Arc;
use serde::de::DeserializeOwned;
use crate::secure_stream::crypto::error::{EncryptionError, DecryptionError};
use crate::secure_stream::serialize::{serialize, deserialize};
use crate::secure_stream::crypto::ciphertext::CipherText;

/// Precomputed shared secret key.
///
/// Can be created from a pair of our secret key and the recipient's public key.
/// As a result, we'll get the same key as the recipient with their secret key and
/// our public key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SharedSecretKey {
    pub(super) precomputed: Arc<box_::PrecomputedKey>,
}

impl SharedSecretKey {
    /// Construct shared secret key from bytes. Useful when it was serialized before.
    pub fn from_bytes(key: [u8; box_::PRECOMPUTEDKEYBYTES]) -> Self {
        Self {
            precomputed: Arc::new(box_::PrecomputedKey(key)),
        }
    }

    /// Convert the `SharedSecretKey` into the raw underlying bytes.
    /// For anyone who wants to store the shared secret key.
    pub fn into_bytes(self) -> [u8; box_::PRECOMPUTEDKEYBYTES] {
        self.precomputed.0
    }

    /// Encrypts bytestring `plaintext` using authenticated encryption.
    ///
    /// With authenticated encryption the recipient will be able to verify the authenticity
    /// of the sender using a sender's public key.
    /// If you want to use anonymous encryption, use the functions provided by `PublicKeys`
    /// and `SecretKeys`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &self.precomputed);
        Ok(serialize(&CipherText {
            nonce: nonce.0,
            ciphertext,
        })?)
    }

    /// Encrypts serialisable `plaintext` using authenticated encryption.
    ///
    /// With authenticated encryption the recipient will be able to verify the authenticity
    /// of the sender using a sender's public key.
    /// If you wish to encrypt bytestring plaintext, use `encrypt_bytes`.
    /// If you want to use anonymous encryption, use the functions provided by `PublicKeys`
    /// and `SecretKeys`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError>
        where
            T: Serialize,
    {
        self.encrypt_bytes(&serialize(plaintext)?)
    }

    /// Decrypts bytestring `encoded` encrypted using authenticated encryption.
    ///
    /// With authenticated encryption we will be able to verify the authenticity
    /// of the sender using a sender's public key.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt_bytes(&self, encoded: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let CipherText { nonce, ciphertext } = deserialize(encoded)?;
        Ok(box_::open_precomputed(
            &ciphertext,
            &box_::Nonce(nonce),
            &self.precomputed,
        ).map_err(DecryptionError::GenericDecryptionError)?)
    }

    /// Decrypts serialized `ciphertext` encrypted using authenticated encryption.
    ///
    /// With authenticated encryption we will be able to verify the authenticity
    /// of the sender using a sender's public key.
    ///
    /// Returns deserialized type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> Result<T, DecryptionError>
        where
            T: Serialize + DeserializeOwned,
    {
        Ok(deserialize(&self.decrypt_bytes(ciphertext)?)?)
    }
}
