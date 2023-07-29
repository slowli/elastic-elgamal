use rand_core::{CryptoRng, RngCore};

use core::convert::TryInto;

use crate::curve25519::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use crate::group::{ElementOps, Group, RandomBytesProvider, ScalarOps};

/// [Ristretto](https://ristretto.group/) transform of Curve25519, also known as ristretto255.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "curve25519-dalek", feature = "curve25519-dalek-ng")))
)]
pub struct Ristretto(());

impl ScalarOps for Ristretto {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
        let mut scalar_bytes = [0_u8; 64];
        rng.fill_bytes(&mut scalar_bytes[..]);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    fn scalar_from_random_bytes(source: RandomBytesProvider<'_>) -> Self::Scalar {
        let mut scalar_bytes = [0_u8; 64];
        source.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn invert_scalars(scalars: &mut [Self::Scalar]) {
        Scalar::batch_invert(scalars);
    }

    fn serialize_scalar(scalar: &Self::Scalar, buffer: &mut [u8]) {
        buffer.copy_from_slice(&scalar.to_bytes());
    }

    #[cfg(feature = "curve25519-dalek")]
    fn deserialize_scalar(buffer: &[u8]) -> Option<Self::Scalar> {
        let bytes: &[u8; 32] = buffer.try_into().expect("input has incorrect byte size");
        Scalar::from_canonical_bytes(*bytes).into()
    }

    #[cfg(feature = "curve25519-dalek-ng")]
    fn deserialize_scalar(buffer: &[u8]) -> Option<Self::Scalar> {
        let bytes: &[u8; 32] = buffer.try_into().expect("input has incorrect byte size");
        Scalar::from_canonical_bytes(*bytes)
    }
}

impl ElementOps for Ristretto {
    type Element = RistrettoPoint;

    const ELEMENT_SIZE: usize = 32;

    fn identity() -> Self::Element {
        RistrettoPoint::identity()
    }

    fn is_identity(element: &Self::Element) -> bool {
        element.is_identity()
    }

    fn generator() -> Self::Element {
        RISTRETTO_BASEPOINT_POINT
    }

    fn serialize_element(element: &Self::Element, buffer: &mut [u8]) {
        buffer.copy_from_slice(&element.compress().to_bytes());
    }

    #[cfg(feature = "curve25519-dalek")]
    fn deserialize_element(buffer: &[u8]) -> Option<Self::Element> {
        CompressedRistretto::from_slice(buffer).ok()?.decompress()
    }

    #[cfg(feature = "curve25519-dalek-ng")]
    fn deserialize_element(buffer: &[u8]) -> Option<Self::Element> {
        CompressedRistretto::from_slice(buffer).decompress()
    }
}

impl Group for Ristretto {
    #[cfg(feature = "curve25519-dalek")]
    fn mul_generator(k: &Scalar) -> Self::Element {
        k * RISTRETTO_BASEPOINT_TABLE
    }

    #[cfg(feature = "curve25519-dalek-ng")]
    fn mul_generator(k: &Scalar) -> Self::Element {
        k * &RISTRETTO_BASEPOINT_TABLE
    }

    fn vartime_mul_generator(k: &Scalar) -> Self::Element {
        #[cfg(feature = "curve25519-dalek")]
        let zero = Scalar::ZERO;
        #[cfg(feature = "curve25519-dalek-ng")]
        let zero = Scalar::zero();

        RistrettoPoint::vartime_double_scalar_mul_basepoint(&zero, &RistrettoPoint::identity(), k)
    }

    fn multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        RistrettoPoint::multiscalar_mul(scalars, elements)
    }

    fn vartime_double_mul_generator(
        k: &Scalar,
        k_element: Self::Element,
        r: &Scalar,
    ) -> Self::Element {
        RistrettoPoint::vartime_double_scalar_mul_basepoint(k, &k_element, r)
    }

    fn vartime_multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        RistrettoPoint::vartime_multiscalar_mul(scalars, elements)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{
        app::{ChoiceParams, EncryptedChoice},
        group::Curve25519Subgroup,
        DiscreteLogTable,
    };

    type SecretKey = crate::SecretKey<Ristretto>;
    type Keypair = crate::Keypair<Ristretto>;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let value = Ristretto::generate_scalar(&mut rng);
        let encrypted = keypair.public().encrypt(value, &mut rng);
        let decryption = keypair.secret().decrypt_to_element(encrypted);
        assert_eq!(decryption, Ristretto::vartime_mul_generator(&value));
    }

    #[test]
    fn encrypt_choice() {
        let mut rng = thread_rng();
        let (pk, sk) = Keypair::generate(&mut rng).into_tuple();
        let choice_params = ChoiceParams::single(pk, 5);
        let encrypted = EncryptedChoice::single(&choice_params, 3, &mut rng);
        let choices = encrypted.verify(&choice_params).unwrap();

        let lookup_table = DiscreteLogTable::new(0..=1);
        for (i, &choice) in choices.iter().enumerate() {
            let decryption = sk.decrypt(choice, &lookup_table);
            assert_eq!(decryption.unwrap(), u64::from(i == 3));
        }
    }

    #[test]
    fn edwards_and_ristretto_public_keys_differ() {
        type SubgroupSecretKey = crate::SecretKey<Curve25519Subgroup>;
        type SubgroupKeypair = crate::Keypair<Curve25519Subgroup>;

        for _ in 0..1_000 {
            let secret_key = SecretKey::generate(&mut thread_rng());
            let keypair = Keypair::from(secret_key.clone());
            let secret_key = SubgroupSecretKey::new(*secret_key.expose_scalar());
            let ed_keypair = SubgroupKeypair::from(secret_key);
            assert_ne!(keypair.public().as_bytes(), ed_keypair.public().as_bytes());
        }
    }
}
