//! (De)serialization utils.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{
    de::{Error as DeError, SeqAccess, Unexpected, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroizing;

use std::{fmt, marker::PhantomData};

use crate::{group::Group, PublicKey, SecretKey};

fn serialize_bytes<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(value))
    } else {
        serializer.serialize_bytes(value)
    }
}

fn deserialize_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64Visitor;

    impl Visitor<'_> for Base64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("base64url-encoded data")
        }

        fn visit_str<E: DeError>(self, value: &str) -> Result<Self::Value, E> {
            Base64UrlUnpadded::decode_vec(value)
                .map_err(|_| E::invalid_value(Unexpected::Str(value), &self))
        }

        fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(value)
        }
    }

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("byte buffer")
        }

        fn visit_bytes<E: DeError>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E: DeError>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(value)
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_str(Base64Visitor)
    } else {
        deserializer.deserialize_byte_buf(BytesVisitor)
    }
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(&self.bytes, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for PublicKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes(deserializer)?;
        Self::from_bytes(&bytes).map_err(D::Error::custom)
    }
}

impl<G: Group> Serialize for SecretKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Zeroizing::new(Vec::with_capacity(G::SCALAR_SIZE));
        G::serialize_scalar(&self.0, &mut bytes);
        serialize_bytes(&bytes, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for SecretKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Zeroizing::new(deserialize_bytes(deserializer)?);
        Self::from_bytes(&bytes).ok_or_else(|| D::Error::custom("bytes do not represent a scalar"))
    }
}

/// Helper type to deserialize scalars.
#[derive(Debug)]
pub struct ScalarHelper<G: Group>(G::Scalar);

impl<G: Group> ScalarHelper<G> {
    pub fn serialize<S>(scalar: &G::Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(G::SCALAR_SIZE);
        G::serialize_scalar(scalar, &mut bytes);
        serialize_bytes(&bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<G::Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes(deserializer)?;
        if bytes.len() == G::SCALAR_SIZE {
            G::deserialize_scalar(&bytes)
                .ok_or_else(|| D::Error::invalid_value(Unexpected::Bytes(&bytes), &"group scalar"))
        } else {
            let expected_len = G::SCALAR_SIZE.to_string();
            Err(D::Error::invalid_length(
                bytes.len(),
                &expected_len.as_str(),
            ))
        }
    }
}

impl<'de, G: Group> Deserialize<'de> for ScalarHelper<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(Self)
    }
}

/// Helper type to deserialize group elements.
#[derive(Debug)]
pub struct ElementHelper<G: Group>(G::Element);

impl<G: Group> ElementHelper<G> {
    pub fn serialize<S>(element: &G::Element, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(G::ELEMENT_SIZE);
        G::serialize_element(element, &mut bytes);
        serialize_bytes(&bytes, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<G::Element, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserialize_bytes(deserializer)?;
        if bytes.len() == G::ELEMENT_SIZE {
            G::deserialize_element(&bytes)
                .ok_or_else(|| D::Error::invalid_value(Unexpected::Bytes(&bytes), &"group element"))
        } else {
            let expected_len = G::ELEMENT_SIZE.to_string();
            Err(D::Error::invalid_length(
                bytes.len(),
                &expected_len.as_str(),
            ))
        }
    }
}

pub struct ScalarVec<G, const MIN: usize>(PhantomData<G>);

impl<G: Group, const MIN: usize> ScalarVec<G, MIN> {
    fn new() -> Self {
        Self(PhantomData)
    }

    pub fn serialize<S>(scalars: &[G::Scalar], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug_assert!(scalars.len() >= MIN);

        let is_human_readable = serializer.is_human_readable();
        let mut seq = serializer.serialize_seq(Some(scalars.len()))?;
        for scalar in scalars {
            let mut bytes = Vec::with_capacity(G::SCALAR_SIZE);
            G::serialize_scalar(scalar, &mut bytes);

            if is_human_readable {
                let string = Base64UrlUnpadded::encode_string(&bytes);
                seq.serialize_element(&string)?;
            } else {
                seq.serialize_element(&bytes)?;
            }
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<G::Scalar>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(Self::new())
    }
}

impl<'de, G: Group, const MIN: usize> Visitor<'de> for ScalarVec<G, MIN> {
    type Value = Vec<G::Scalar>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at least {} group scalars", MIN)
    }

    fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut scalars = if let Some(size) = access.size_hint() {
            if size < MIN {
                return Err(S::Error::invalid_length(size, &self));
            }
            Vec::with_capacity(size)
        } else {
            Vec::new()
        };

        while let Some(scalar) = access.next_element::<ScalarHelper<G>>()? {
            scalars.push(scalar.0);
        }
        if scalars.len() >= MIN {
            Ok(scalars)
        } else {
            Err(S::Error::invalid_length(scalars.len(), &self))
        }
    }
}
