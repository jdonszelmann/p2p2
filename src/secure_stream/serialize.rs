//! This is a highly modified version of
//! https://github.com/maidsafe/maidsafe-utilities/blob/master/src/serialisation.rs
//! which is licensed under the MIT license (2018; MaidSafe.net limited).


use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::io::{Cursor, Read, Write};
use thiserror::Error;
use bincode::Options;

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("bincode serialization error: {0}")]
    GenericBincode(#[from] bincode::Error)
}

impl PartialEq for SerializationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GenericBincode(_), Self::GenericBincode(_)) => true,
        }
    }
}

#[derive(Debug, Error)]
pub enum DeserializationError {
    #[error("not all bytes were consumed from the input while deserializing")]
    BytesLeftOver,

    #[error("bincode deserialization error: {0}")]
    GenericBincode(#[from] bincode::Error)
}

impl PartialEq for DeserializationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::GenericBincode(_), Self::GenericBincode(_)) => true,
            (Self::BytesLeftOver, Self::BytesLeftOver) => true,
            _ => false
        }
    }
}

/// serialize an `Serialize` type with no limit on the size of the serialized data.
pub fn serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, SerializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .serialize(data)
        .map_err(Into::into)
}

/// serialize an `Serialize` type with max limit specified.
pub fn serialize_with_limit<T: Serialize>(data: &T, size_limit: u64) -> Result<Vec<u8>, SerializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(size_limit)
        .serialize(data)
        .map_err(Into::into)
}

/// Deserialize a `Deserialize` type with no limit on the size of the serialized data.
pub fn deserialize<T>(data: &[u8]) -> Result<T, DeserializationError>
    where
        T: Serialize + DeserializeOwned,
{
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(data)?;
    if bincode::serialized_size(&value)? != data.len() as u64 {
        return Err(DeserializationError::BytesLeftOver);
    }
    Ok(value)
}

/// Deserialize a `Deserialize` type with max size limit specified.
pub fn deserialize_with_limit<T>(data: &[u8], size_limit: u64) -> Result<T, DeserializationError>
    where
        T: DeserializeOwned,
{
    let mut cursor = Cursor::new(data);

    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(size_limit)
        .deserialize_from(&mut cursor)?;

    if cursor.position() != data.len() as u64 {
        return Err(DeserializationError::BytesLeftOver);
    }
    Ok(value)
}

/// serialize an `Serialize` type directly into a `Write` with no limit on the size of the
/// serialized data.
pub fn serialize_into<T: Serialize, W: Write>(
    data: &T,
    write: &mut W,
) -> Result<(), SerializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .serialize_into(write, data)
        .map_err(Into::into)
}

/// serialize an `Serialize` type directly into a `Write` with max size limit specified.
pub fn serialize_into_with_limit<T: Serialize, W: Write>(
    data: &T,
    write: &mut W,
    size_limit: u64,
) -> Result<(), SerializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(size_limit)
        .serialize_into(write, data)
        .map_err(Into::into)
}

/// Deserialize a `Deserialize` type directly from a `Read` with no limit on the size of the
/// serialized data.
pub fn deserialize_from<R: Read, T: DeserializeOwned>(
    read: &mut R,
) -> Result<T, DeserializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize_from(read)
        .map_err(Into::into)
}

/// Deserialize a `Deserialize` type directly from a `Read` with max size limit specified.
pub fn deserialize_from_with_limit<R: Read, T: DeserializeOwned>(
    read: &mut R,
    size_limit: u64,
) -> Result<T, DeserializationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(size_limit)
        .deserialize_from(read)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    
    use serde::de::{self, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;
    use std::io::Cursor;

    #[test]
    fn serialize_deserialize() {
        let original_data = (
            vec![0u8, 1, 3, 9],
            vec![-1i64, 888, -8765],
            "SomeString".to_string(),
        );

        let serialized_data = serialize(&original_data).unwrap();
        let deserialized_data: (Vec<u8>, Vec<i64>, String) = deserialize(&serialized_data).unwrap();
        assert_eq!(original_data, deserialized_data);

        // Try to parse a `String` into a `u64` to check the unused bytes triggers an error.
        let serialized_string = serialize(&"Another string".to_string()).unwrap();
        assert_eq!(deserialize::<u64>(&serialized_string), Err(DeserializationError::BytesLeftOver));
    }

    #[test]
    fn serialize_into_deserialize_from() {
        let original_data = (
            vec![0u8, 1, 3, 9],
            vec![-1i64, 888, -8765],
            "SomeString".to_string(),
        );
        let mut serialized_data = vec![];
        serialize_into(&original_data, &mut serialized_data).unwrap();

        let mut serialized = Cursor::new(serialized_data);
        let deserialized_data: (Vec<u8>, Vec<i64>, String) =
            deserialize_from(&mut serialized).unwrap();
        assert_eq!(original_data, deserialized_data);
    }

    #[test]
    fn upper_limit() {
        let upper_limit = 64;
        // Test with data which is at limit
        let mut original_data = (1u64..8).collect::<Vec<_>>();
        let mut serialized_data = serialize_with_limit(&original_data, upper_limit).unwrap();
        let mut deserialized_data: Vec<u64> = deserialize(&serialized_data).unwrap();
        assert_eq!(original_data, deserialized_data);

        serialized_data.clear();
        serialize_into_with_limit(
            &original_data,
            &mut serialized_data,
            upper_limit,
        ).unwrap();
        let mut serialized = Cursor::new(serialized_data);
        deserialized_data = deserialize_from(&mut serialized).unwrap();
        assert_eq!(original_data, deserialized_data);

        // Try to serialize data above limit
        original_data.push(0);
        if let Err(SerializationError::GenericBincode(_)) = serialize_with_limit(&original_data, upper_limit) {} else {
            panic!("Expected size limit error.");
        }
        let mut buffer = vec![];
        if let Err(SerializationError::GenericBincode(_)) =
        serialize_into_with_limit(&original_data, &mut buffer, upper_limit) {} else {
            panic!("Expected size limit error.");
        }

        // Try to deserialize data above limit
        let excessive = serialize(&original_data).unwrap();
        if let Err(DeserializationError::GenericBincode(_)) = deserialize_with_limit::<Vec<u64>>(&excessive, upper_limit) {} else {
            panic!("Expected size limit error.");
        }
        serialized = Cursor::new(excessive);
        if let Err(DeserializationError::GenericBincode(_)) =
            deserialize_from_with_limit::<Cursor<_>, Vec<u64>>(&mut serialized, upper_limit) {} else {
            panic!("Expected size limit error.");
        }
    }

    #[test]
    fn sizes() {
        // todo!()
        // let data = (1u64..8).collect::<Vec<_>>();
        // assert_eq!(serialized_size(&data), 64);
        // assert_eq!(serialized_size_with_limit(&data, 100), Some(64));
        // assert_eq!(serialized_size_with_limit(&data, 64), Some(64));
        // assert!(serialized_size_with_limit(&data, 63).is_none());
    }

    #[derive(PartialEq, Eq, Debug)]
    struct Wrapper([u8; 1]);

    impl Serialize for Wrapper {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&self.0[..])
        }
    }

    impl<'de> Deserialize<'de> for Wrapper {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Wrapper, D::Error> {
            struct WrapperVisitor;
            impl<'de> Visitor<'de> for WrapperVisitor {
                type Value = Wrapper;
                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "Wrapper")
                }
                fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                    if value.len() != 1 {
                        return Err(de::Error::invalid_length(value.len(), &self));
                    }
                    Ok(Wrapper([value[0]]))
                }
            }
            deserializer.deserialize_bytes(WrapperVisitor)
        }
    }

    #[test]
    // The bincode implementation of `serialize_bytes` puts the number of bytes of raw data as the
    // first 8 bytes of the encoded data.  The corresponding `deserialize_bytes` uses these first 8
    // bytes to deduce the size of the buffer into which the raw bytes should then be copied.  If we
    // use bincode's `deserialize_from(.., Infinite)` to try and parse such data, size-checking is
    // disabled when allocating the buffer, and corrupted serialized data could cause an OOM crash.
    fn deserialize_bytes() {
        let wrapper = Wrapper([255]);
        let serialized_wrapper = serialize(&wrapper).unwrap();
        // If the following assertion fails, revisit how we're encoding data via `serialize_bytes`
        // to check that the following `tampered` array below is still trying to trigger an OOM
        // error.
        assert_eq!(serialized_wrapper, [1, 0, 0, 0, 0, 0, 0, 0, 255]);
        let deserialized_wrapper: Wrapper = deserialize(&serialized_wrapper).unwrap();
        assert_eq!(wrapper, deserialized_wrapper);

        // Try to trigger an OOM crash.
        let tampered = [255u8; 9];
        match deserialize::<Wrapper>(&tampered).unwrap_err() {
            DeserializationError::GenericBincode(_) => (),
            err => panic!("{:?}", err),
        }


        assert_eq!(
            deserialize::<Wrapper>(&[1, 0, 0, 0, 0, 0, 0, 0, 255, 255]),
            Err(DeserializationError::BytesLeftOver)
        );
    }
}




