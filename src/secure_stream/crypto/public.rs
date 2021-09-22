
use sodiumoxide::crypto::box_::{PublicKey, PUBLICKEYBYTES};
use sodiumoxide::crypto::{sealedbox};
use serde::{Serialize, Deserialize};
use crate::secure_stream::serialize::{serialize};



use crate::secure_stream::crypto::error::EncryptionError;
use std::fmt;


/// The public key used encrypt data that can only be decrypted by the corresponding secret key,
/// which is represented by `SecretEncryptKey`.
/// Use `gen_encrypt_keypair()` to generate a public and secret key pair.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct PublicEncryptKey {
    pub(crate) inner: PublicKey
}

impl PublicEncryptKey {
    /// Construct public key from bytes. Useful when it was serialized before.
    pub fn from_bytes(public_key: [u8; PUBLICKEYBYTES]) -> Self {
        Self {
            inner: PublicKey(public_key),
        }
    }

    /// Convert the `PublicEncryptKey` into the raw underlying bytes.
    /// For anyone who wants to store the public key.
    pub fn into_bytes(self) -> [u8; PUBLICKEYBYTES] {
        self.inner.0
    }

    /// Encrypts serializable `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// If you wish to encrypt bytestring plaintext, use `anonymously_encrypt_bytes`.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn anonymously_encrypt<T: Serialize>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError> {
        Ok(self.anonymously_encrypt_bytes(&serialize(plaintext)?))
    }

    /// Encrypts bytestring `plaintext` using anonymous encryption.
    ///
    /// Anonymous encryption will use an ephemeral public key, so the recipient won't
    /// be able to tell who sent the ciphertext.
    /// To use authenticated encryption, use `SharedSecretKey`.
    ///
    /// Returns ciphertext in case of success.
    pub fn anonymously_encrypt_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.inner)
    }
}

impl fmt::Display for PublicEncryptKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            &self.inner.0[0], &self.inner.0[1], &self.inner.0[2]
        )
    }
}
