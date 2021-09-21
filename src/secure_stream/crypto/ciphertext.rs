use sodiumoxide::crypto::secretbox;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub(super) struct CipherText {
    pub(super) nonce: [u8; secretbox::NONCEBYTES],
    pub(super) ciphertext: Vec<u8>,
}
