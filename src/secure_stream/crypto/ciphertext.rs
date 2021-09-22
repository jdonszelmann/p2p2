use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;

#[derive(Serialize, Deserialize)]
pub(super) struct CipherText {
    pub(super) nonce: [u8; secretbox::NONCEBYTES],
    pub(super) ciphertext: Vec<u8>,
}
