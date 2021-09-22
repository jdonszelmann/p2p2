use crate::secure_stream::crypto::generate_random_bytes;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign;

/// Seed structure used to generate sign and encrypt keypairs deterministically.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Seed {
    pub(super) seed: sign::Seed,
}

impl Seed {
    /// Generates a new seed.
    pub fn new() -> Self {
        let mut seed_bytes = [0; sign::SEEDBYTES];
        seed_bytes.copy_from_slice(&generate_random_bytes(sign::SEEDBYTES));

        Self {
            seed: sign::Seed(seed_bytes),
        }
    }

    /// Create a seed from bytes.
    pub fn from_bytes(seed: [u8; sign::SEEDBYTES]) -> Self {
        Self {
            seed: sign::Seed(seed),
        }
    }

    /// Convert the `Seed` into the raw underlying bytes.
    pub fn into_bytes(self) -> [u8; sign::SEEDBYTES] {
        self.seed.0
    }
}

impl Default for Seed {
    fn default() -> Self {
        Self::new()
    }
}
