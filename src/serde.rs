//! (De)serialization utils.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{
    de::{DeserializeOwned, Error as DeError, SeqAccess, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroizing;

use std::{fmt, marker::PhantomData};

use crate::{group::Group, Keypair, PublicKey, SecretKey};

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

impl<G: Group> Serialize for Keypair<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.secret().serialize(serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for Keypair<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SecretKey::<G>::deserialize(deserializer).map(From::from)
    }
}

/// Common functionality for serialization helpers.
pub(crate) trait Helper: Serialize + DeserializeOwned {
    const PLURAL_DESCRIPTION: &'static str;
    type Target;

    fn from_target(target: &Self::Target) -> Self;
    fn into_target(self) -> Self::Target;
}

/// Helper type to deserialize scalars.
///
/// **NB.** Scalars are assumed to be public! Secret scalars must be serialized via `SecretKey`.
#[derive(Debug)]
pub(crate) struct ScalarHelper<G: Group>(G::Scalar);

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

impl<G: Group> Serialize for ScalarHelper<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(&self.0, serializer)
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

impl<G: Group> Helper for ScalarHelper<G> {
    const PLURAL_DESCRIPTION: &'static str = "group scalars";
    type Target = G::Scalar;

    fn from_target(target: &Self::Target) -> Self {
        Self(*target)
    }

    fn into_target(self) -> Self::Target {
        self.0
    }
}

/// Helper type to deserialize group elements.
#[derive(Debug)]
pub(crate) struct ElementHelper<G: Group>(G::Element);

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

impl<G: Group> Serialize for ElementHelper<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::serialize(&self.0, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for ElementHelper<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::deserialize(deserializer).map(Self)
    }
}

impl<G: Group> Helper for ElementHelper<G> {
    const PLURAL_DESCRIPTION: &'static str = "group elements";
    type Target = G::Element;

    fn from_target(target: &Self::Target) -> Self {
        Self(*target)
    }

    fn into_target(self) -> Self::Target {
        self.0
    }
}

pub(crate) struct VecHelper<T, const MIN: usize>(PhantomData<T>);

impl<T: Helper, const MIN: usize> VecHelper<T, MIN> {
    fn new() -> Self {
        Self(PhantomData)
    }

    pub fn serialize<S>(values: &[T::Target], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug_assert!(values.len() >= MIN);
        serializer.collect_seq(values.iter().map(T::from_target))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<T::Target>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(Self::new())
    }
}

impl<'de, T: Helper, const MIN: usize> Visitor<'de> for VecHelper<T, MIN> {
    type Value = Vec<T::Target>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at least {} {}", MIN, T::PLURAL_DESCRIPTION)
    }

    fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut scalars: Vec<T::Target> = if let Some(size) = access.size_hint() {
            if size < MIN {
                return Err(S::Error::invalid_length(size, &self));
            }
            Vec::with_capacity(size)
        } else {
            Vec::new()
        };

        while let Some(value) = access.next_element::<T>()? {
            scalars.push(value.into_target());
        }
        if scalars.len() >= MIN {
            Ok(scalars)
        } else {
            Err(S::Error::invalid_length(scalars.len(), &self))
        }
    }
}
