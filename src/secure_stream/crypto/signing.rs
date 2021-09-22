use crate::secure_stream::crypto::ciphertext::CipherText;
use crate::secure_stream::crypto::error::{DecryptionError, EncryptionError};
use crate::secure_stream::serialize::{deserialize, serialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::PUBLICKEYBYTES;
use sodiumoxide::crypto::{secretbox, sign};
use std::fmt;
use std::sync::Arc;

/// Public signing key used to verify that the signature appended to a message was actually issued
/// by the creator of the public key.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone, Copy)]
pub struct PublicSignKey {
    pub(super) sign: sign::PublicKey,
}

impl PublicSignKey {
    /// Verifies the detached `signature`.
    ///
    /// Returns `true` if the signature is valid the `data` is verified.
    pub fn verify_detached(&self, signature: &Signature, data: &[u8]) -> bool {
        sign::verify_detached(&signature.signature(), data, &self.sign)
    }

    /// Construct from bytes. Useful when it was serialized before.
    pub fn from_bytes(public_key: [u8; PUBLICKEYBYTES]) -> Self {
        Self {
            sign: sign::PublicKey(public_key),
        }
    }

    /// Convert the `PublicSignKey` into the raw underlying bytes.
    /// For anyone who wants to store the public signing key.
    pub fn into_bytes(self) -> [u8; PUBLICKEYBYTES] {
        self.sign.0
    }
}

/// Reference counted secret signing key used to verify signatures previously signed with
/// `PublicSignKey`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretSignKey {
    pub(super) inner: Arc<SecretSignKeyInner>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SecretSignKeyInner {
    pub(super) sign: sign::SecretKey,
}

impl SecretSignKey {
    /// Construct from bytes. Useful when it was serialized before.
    pub fn from_bytes(secret_key: [u8; sign::SECRETKEYBYTES]) -> Self {
        Self {
            inner: Arc::new(SecretSignKeyInner {
                sign: sign::SecretKey(secret_key),
            }),
        }
    }

    /// Get the inner secret key representation.
    pub fn into_bytes(self) -> [u8; sign::SECRETKEYBYTES] {
        self.inner.sign.0
    }

    /// Produces the detached signature from the `data`.
    ///
    /// Afterwards the returned `Signature` can be used to verify the authenticity of `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature::new(sign::sign_detached(data, &self.inner.sign))
    }
}

/// Construct random public and secret signing key pair.
pub fn gen_sign_keypair() -> (PublicSignKey, SecretSignKey) {
    let (sign_pk, sign_sk) = sign::gen_keypair();
    let pub_sign_key = PublicSignKey { sign: sign_pk };
    let sec_sign_key = SecretSignKey {
        inner: Arc::new(SecretSignKeyInner { sign: sign_sk }),
    };
    (pub_sign_key, sec_sign_key)
}

/// Detached signature.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Signature {
    signature: [u8; 64],
}

impl Signature {
    fn new(s: sign::Signature) -> Signature {
        Self {
            signature: s.to_bytes(),
        }
    }

    /// Construct the signature from bytes. Useful when it was serialized before.
    // TODO: previously: SIGNATURE_LENGTH (but is private)
    pub fn from_bytes(key: [u8; 64]) -> Self {
        Self { signature: key }
    }

    pub(crate) fn signature(&self) -> sign::Signature {
        sign::Signature::new(self.signature)
    }

    /// Return the signature as an array of bytes
    pub fn into_bytes(self) -> [u8; 64] {
        self.signature
    }
}

/// Secret key for authenticated symmetric encryption.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SymmetricKey {
    encrypt: Arc<secretbox::Key>,
}

impl SymmetricKey {
    /// Generates a new symmetric key.
    pub fn new() -> Self {
        let sk = secretbox::gen_key();
        Self {
            encrypt: Arc::new(sk),
        }
    }

    /// Create a symmetric key from bytes. Useful when it has been serialized.
    pub fn from_bytes(key: [u8; secretbox::KEYBYTES]) -> Self {
        Self {
            encrypt: Arc::new(secretbox::Key(key)),
        }
    }

    /// Convert the `SharedSecretKey` into the raw underlying bytes.
    /// For anyone who wants to store the symmetric key
    pub fn into_bytes(self) -> [u8; secretbox::KEYBYTES] {
        self.encrypt.0
    }

    /// Encrypts serialisable `plaintext` using authenticated symmetric encryption.
    ///
    /// With authenticated encryption the recipient will be able to confirm that the message
    /// is untampered with.
    /// If you wish to encrypt bytestring plaintext, use `encrypt_bytes`.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt<T: Serialize>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_bytes(&serialize(plaintext)?)
    }

    /// Encrypts serialisable `plaintext` using authenticated symmetric encryption, with a nonce.
    ///
    /// See `encrypt`.
    pub fn encrypt_with_nonce<T: Serialize>(
        &self,
        plaintext: &T,
        nonce: &Nonce,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_bytes_with_nonce(&serialize(plaintext)?, nonce)
    }

    /// Encrypts bytestring `plaintext` using authenticated symmetric encryption, with a nonce.
    ///
    /// See `encrypt_bytes`.
    pub fn encrypt_bytes_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &Nonce,
    ) -> Result<Vec<u8>, EncryptionError> {
        let ciphertext = secretbox::seal(plaintext, &nonce.nonce, &self.encrypt);
        Ok(serialize(&CipherText {
            nonce: nonce.nonce.0,
            ciphertext,
        })?)
    }

    /// Encrypts bytestring `plaintext` using authenticated symmetric encryption.
    ///
    /// With authenticated encryption the recipient will be able to confirm that the message
    /// is untampered with.
    ///
    /// Returns ciphertext in case of success.
    /// Can return an `Error` in case of a serialisation error.
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = secretbox::gen_nonce();
        self.encrypt_bytes_with_nonce(plaintext, &Nonce { nonce })
    }

    /// Decrypts serialized `ciphertext` encrypted using authenticated symmetric encryption.
    ///
    /// With authenticated encryption we will be able to tell that the message hasn't been
    /// tampered with.
    ///
    /// Returns deserialized type `T` in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> Result<T, DecryptionError>
    where
        T: DeserializeOwned + Serialize,
    {
        Ok(deserialize(&self.decrypt_bytes(ciphertext)?)?)
    }

    /// Decrypts bytestring `ciphertext` encrypted using authenticated symmetric encryption.
    ///
    /// With authenticated encryption we will be able to tell that the message hasn't been
    /// tampered with.
    ///
    /// Returns plaintext in case of success.
    /// Can return `Error` in case of a deserialisation error, if the ciphertext
    /// is not valid, or if it can not be decrypted.
    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let CipherText { nonce, ciphertext } = deserialize(ciphertext)?;
        secretbox::open(&ciphertext, &secretbox::Nonce(nonce), &self.encrypt)
            .map_err(DecryptionError::GenericDecryptionError)
    }
}

impl Default for SymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Nonce structure used for authenticated symmetric encryption.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Nonce {
    nonce: secretbox::Nonce,
}

impl Nonce {
    /// Generates a new nonce.
    pub fn new() -> Self {
        Self {
            nonce: secretbox::gen_nonce(),
        }
    }

    /// Create a nonce from bytes. Useful when it has been serialized.
    pub fn from_bytes(nonce: [u8; secretbox::NONCEBYTES]) -> Self {
        Self {
            nonce: secretbox::Nonce(nonce),
        }
    }

    /// Convert the `Nonce` into the raw underlying bytes.
    /// For anyone who wants to store the nonce.
    pub fn into_bytes(self) -> [u8; secretbox::NONCEBYTES] {
        self.nonce.0
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PublicSignKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            &self.sign.0[0], &self.sign.0[1], &self.sign.0[2]
        )
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}{:02x}..",
            self.signature[0], self.signature[1], self.signature[2]
        )
    }
}
