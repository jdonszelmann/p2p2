//! This is a highly modified version of
//! https://github.com/maidsafe-archive/safe_crypto/blob/master/src/lib.rs
//! which is licensed under the MIT license (2018; MaidSafe.net limited).

use crate::secure_stream::crypto::public::PublicEncryptKey;
use crate::secure_stream::crypto::secret::{SecretEncryptKey, SecretEncryptKeyInner};
use crate::secure_stream::crypto::seed::Seed;
use crate::secure_stream::crypto::signing::{PublicSignKey, SecretSignKey, SecretSignKeyInner};
use rand::rngs::OsRng;
use rand::Rng;
use sodiumoxide::crypto::{box_, sign};
use std::sync::Arc;

pub mod ciphertext;
pub mod context;
pub mod error;
pub mod public;
pub mod secret;
pub mod seed;
pub mod shared;
pub mod signing;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyPair {
    pub public: PublicEncryptKey,
    pub secret: SecretEncryptKey,
}

impl KeyPair {
    pub fn gen() -> Self {
        gen_encrypt_keypair().into()
    }

    pub fn split(self) -> (PublicEncryptKey, SecretEncryptKey) {
        (self.public, self.secret)
    }
}

impl From<(PublicEncryptKey, SecretEncryptKey)> for KeyPair {
    fn from((public, secret): (PublicEncryptKey, SecretEncryptKey)) -> Self {
        Self { public, secret }
    }
}

impl From<(SecretEncryptKey, PublicEncryptKey)> for KeyPair {
    fn from((secret, public): (SecretEncryptKey, PublicEncryptKey)) -> Self {
        Self { public, secret }
    }
}

/// Randomly generates a secret key and a corresponding public key.
fn gen_encrypt_keypair() -> (PublicEncryptKey, SecretEncryptKey) {
    let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
    let pub_enc_key = PublicEncryptKey { inner: encrypt_pk };
    let sec_enc_key = SecretEncryptKey {
        inner: Arc::new(SecretEncryptKeyInner {
            encrypt: encrypt_sk,
        }),
    };
    (pub_enc_key, sec_enc_key)
}

/// Construct random public and secret signing key pair from a seed.
fn gen_sign_keypair_from_seed(seed: &Seed) -> (PublicSignKey, SecretSignKey) {
    let (sign_pk, sign_sk) = sign::keypair_from_seed(&seed.seed);
    let pub_sign_key = PublicSignKey { sign: sign_pk };
    let sec_sign_key = SecretSignKey {
        inner: Arc::new(SecretSignKeyInner { sign: sign_sk }),
    };
    (pub_sign_key, sec_sign_key)
}

/// Generate a random byte vector with given `length`.
pub(crate) fn generate_random_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|_| OsRng.gen())
        .filter(|b| *b != 0)
        .collect()
}
