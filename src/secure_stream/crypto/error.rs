use thiserror::Error;
use crate::secure_stream::serialize::{SerializationError, DeserializationError};


#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("serialization error: {0}")]
    Serialize(#[from] SerializationError)
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("deserialization error: {0}")]
    Serialize(#[from] DeserializationError),

    #[error("failed to decrypt message")]
    GenericDecryptionError(())
}

