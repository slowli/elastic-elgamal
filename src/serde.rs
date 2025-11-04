//! (De)serialization utils.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as DeError, SeqAccess, Unexpected, Visitor},
};
use zeroize::Zeroizing;

use core::{fmt, marker::PhantomData};

use crate::{
    Keypair, PublicKey, SecretKey,
    alloc::{ToString, Vec, vec},
    dkg::Opening,
    group::Group,
};

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

    impl Visitor<'_> for BytesVisitor {
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

impl Serialize for Opening {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(self.0.as_slice(), serializer)
    }
}

impl<'de> Deserialize<'de> for Opening {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Zeroizing::new(deserialize_bytes(deserializer)?);
        let mut opening = Opening(Zeroizing::new([0_u8; 32]));
        if bytes.len() == 32 {
            opening.0.copy_from_slice(&bytes);
            Ok(opening)
        } else {
            Err(D::Error::invalid_length(bytes.len(), &"32"))
        }
    }
}

impl<G: Group> Serialize for PublicKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(self.as_bytes(), serializer)
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
        let mut bytes = Zeroizing::new(vec![0_u8; G::SCALAR_SIZE]);
        G::serialize_scalar(self.expose_scalar(), &mut bytes);
        serialize_bytes(&bytes, serializer)
    }
}

impl<'de, G: Group> Deserialize<'de> for SecretKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Zeroizing::new(deserialize_bytes(deserializer)?);
        Self::from_bytes(&bytes)
            .ok_or_else(|| D::Error::custom("bytes do not represent a group scalar"))
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
        let mut bytes = vec![0_u8; G::SCALAR_SIZE];
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
                .ok_or_else(|| D::Error::custom("bytes do not represent a group scalar"))
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
        let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
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
                .ok_or_else(|| D::Error::custom("bytes do not represent a group element"))
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
        write!(formatter, "at least {MIN} {}", T::PLURAL_DESCRIPTION)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Ristretto;

    #[test]
    fn opening_roundtrip() {
        let opening = Opening(Zeroizing::new([6; 32]));
        let json = serde_json::to_value(&opening).unwrap();
        assert!(json.is_string(), "{json:?}");
        let opening_copy: Opening = serde_json::from_value(json).unwrap();
        assert_eq!(opening_copy.0, opening.0);
    }

    #[test]
    fn key_roundtrip() {
        let keypair = Keypair::<Ristretto>::generate(&mut rand::rng());
        let json = serde_json::to_value(&keypair).unwrap();
        assert!(json.is_string(), "{json:?}");
        let keypair_copy: Keypair<Ristretto> = serde_json::from_value(json).unwrap();
        assert_eq!(keypair_copy.public(), keypair.public());

        let json = serde_json::to_value(keypair.public()).unwrap();
        assert!(json.is_string(), "{json:?}");
        let public_key: PublicKey<Ristretto> = serde_json::from_value(json).unwrap();
        assert_eq!(public_key, *keypair.public());

        let json = serde_json::to_value(keypair.secret()).unwrap();
        assert!(json.is_string(), "{json:?}");
        let secret_key: SecretKey<Ristretto> = serde_json::from_value(json).unwrap();
        assert_eq!(secret_key.expose_scalar(), keypair.secret().expose_scalar());
    }

    #[test]
    fn public_key_deserialization_with_incorrect_length() {
        let err = serde_json::from_str::<PublicKey<Ristretto>>("\"dGVzdA\"").unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid size of the byte buffer"),
            "{err_string}"
        );
    }

    #[test]
    fn public_key_deserialization_of_non_element() {
        let err = serde_json::from_str::<PublicKey<Ristretto>>(
            "\"tNDkeYUVQWgh34d-RqaElOk7yFB8d2qCh5f4Vi2euT0\"",
        )
        .unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("does not represent a group element"),
            "{err_string}"
        );
    }

    #[test]
    fn secret_key_deserialization_with_incorrect_length() {
        let err = serde_json::from_str::<SecretKey<Ristretto>>("\"dGVzdA\"").unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group scalar"),
            "{err_string}"
        );
    }

    #[test]
    fn secret_key_deserialization_of_invalid_scalar() {
        // Last `_8` chars set the upper byte of the scalar bytes to 0xff, which is invalid
        // (all scalars are less than 2^253).
        let err = serde_json::from_str::<SecretKey<Ristretto>>(
            "\"nN3xf7lSOX0_zs6QPBwWHYi0Dkx2Ln_z1MPwnbzaM_8\"",
        )
        .unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group scalar"),
            "{err_string}"
        );
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(bound = "")]
    struct TestObject<G: Group> {
        #[serde(with = "ScalarHelper::<G>")]
        scalar: G::Scalar,
        #[serde(with = "ElementHelper::<G>")]
        element: G::Element,
        #[serde(with = "VecHelper::<ScalarHelper<G>, 2>")]
        more_scalars: Vec<G::Scalar>,
    }

    impl TestObject<Ristretto> {
        fn sample() -> Self {
            Self {
                scalar: 12345_u64.into(),
                element: Ristretto::mul_generator(&54321_u64.into()),
                more_scalars: vec![7_u64.into(), 890_u64.into()],
            }
        }
    }

    #[test]
    fn helpers_roundtrip() {
        let object = TestObject::sample();
        let json = serde_json::to_value(&object).unwrap();
        let object_copy: TestObject<Ristretto> = serde_json::from_value(json).unwrap();
        assert_eq!(object_copy, object);
    }

    #[test]
    fn scalar_helper_invalid_scalar() {
        let object = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("scalar".into(), "dGVzdA".into());

        let err = serde_json::from_value::<TestObject<Ristretto>>(json.clone()).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid length 4, expected 32"),
            "{err_string}"
        );

        json.as_object_mut().unwrap().insert(
            "scalar".into(),
            "nN3xf7lSOX0_zs6QPBwWHYi0Dkx2Ln_z1MPwnbzaM_8".into(),
        );
        let err = serde_json::from_value::<TestObject<Ristretto>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group scalar"),
            "{err_string}"
        );
    }

    #[test]
    fn element_helper_invalid_element() {
        let object = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("element".into(), "dGVzdA".into());

        let err = serde_json::from_value::<TestObject<Ristretto>>(json.clone()).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid length 4, expected 32"),
            "{err_string}"
        );

        json.as_object_mut().unwrap().insert(
            "element".into(),
            "nN3xf7lSOX0_zs6QPBwWHYi0Dkx2Ln_z1MPwnbzaM_8".into(),
        );
        let err = serde_json::from_value::<TestObject<Ristretto>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("bytes do not represent a group element"),
            "{err_string}"
        );
    }

    #[test]
    fn vec_helper_invalid_length() {
        let object = TestObject::sample();
        let mut json = serde_json::to_value(object).unwrap();
        let more_scalars = &mut json.as_object_mut().unwrap()["more_scalars"];
        more_scalars.as_array_mut().unwrap().pop();

        let err = serde_json::from_value::<TestObject<Ristretto>>(json).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("invalid length 1, expected at least 2 group scalars"),
            "{err_string}"
        );
    }
}
