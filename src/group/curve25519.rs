use rand_core::{CryptoRng, RngCore};

use core::convert::TryInto;

use crate::curve25519::{
    constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use crate::group::{ElementOps, Group, RandomBytesProvider, ScalarOps};

/// Prime-order subgroup of Curve25519 without any transforms performed for EC points.
///
/// Since the curve has cofactor 8, [`ElementOps::deserialize_element()`] implementation
/// explicitly checks on deserializing each EC point that the point is torsion-free
/// (belongs to the prime-order subgroup), which is moderately slow (takes ~0.1ms on
/// a laptop).
///
/// Prefer using [`Ristretto`] if compatibility with other Curve25519 applications is not a concern.
/// (If it *is* a concern, beware of [cofactor pitfalls]!)
///
/// [`Ristretto`]: crate::group::Ristretto
/// [cofactor pitfalls]: https://ristretto.group/why_ristretto.html#pitfalls-of-a-cofactor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "curve25519-dalek", feature = "curve25519-dalek-ng")))
)]
pub struct Curve25519Subgroup(());

impl ScalarOps for Curve25519Subgroup {
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

impl ElementOps for Curve25519Subgroup {
    type Element = EdwardsPoint;

    const ELEMENT_SIZE: usize = 32;

    fn identity() -> Self::Element {
        EdwardsPoint::identity()
    }

    fn is_identity(element: &Self::Element) -> bool {
        element.is_identity()
    }

    fn generator() -> Self::Element {
        ED25519_BASEPOINT_POINT
    }

    fn serialize_element(element: &Self::Element, buffer: &mut [u8]) {
        buffer.copy_from_slice(&element.compress().to_bytes());
    }

    #[cfg(feature = "curve25519-dalek")]
    fn deserialize_element(buffer: &[u8]) -> Option<Self::Element> {
        CompressedEdwardsY::from_slice(buffer)
            .ok()?
            .decompress()
            .filter(EdwardsPoint::is_torsion_free)
    }

    #[cfg(feature = "curve25519-dalek-ng")]
    fn deserialize_element(buffer: &[u8]) -> Option<Self::Element> {
        CompressedEdwardsY::from_slice(buffer)
            .decompress()
            .filter(EdwardsPoint::is_torsion_free)
    }
}

impl Group for Curve25519Subgroup {
    #[cfg(feature = "curve25519-dalek")]
    fn mul_generator(k: &Scalar) -> Self::Element {
        k * ED25519_BASEPOINT_TABLE
    }

    #[cfg(feature = "curve25519-dalek-ng")]
    fn mul_generator(k: &Scalar) -> Self::Element {
        k * &ED25519_BASEPOINT_TABLE
    }

    fn vartime_mul_generator(k: &Scalar) -> Self::Element {
        #[cfg(feature = "curve25519-dalek")]
        let zero = Scalar::ZERO;
        #[cfg(feature = "curve25519-dalek-ng")]
        let zero = Scalar::zero();

        EdwardsPoint::vartime_double_scalar_mul_basepoint(&zero, &EdwardsPoint::identity(), k)
    }

    fn multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        EdwardsPoint::multiscalar_mul(scalars, elements)
    }

    fn vartime_double_mul_generator(
        k: &Scalar,
        k_element: Self::Element,
        r: &Scalar,
    ) -> Self::Element {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(k, &k_element, r)
    }

    fn vartime_multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        EdwardsPoint::vartime_multiscalar_mul(scalars, elements)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{
        curve25519::{constants::EIGHT_TORSION, scalar::Scalar, traits::Identity},
        PublicKeyConversionError,
    };

    type PublicKey = crate::PublicKey<Curve25519Subgroup>;

    #[test]
    fn mangled_point_is_invalid_public_key() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let mut point =
                Curve25519Subgroup::mul_generator(&Curve25519Subgroup::generate_scalar(&mut rng));
            point += EIGHT_TORSION[1];
            assert!(!point.is_torsion_free());
            let bytes = point.compress().to_bytes();
            assert!(matches!(
                PublicKey::from_bytes(&bytes).unwrap_err(),
                PublicKeyConversionError::InvalidGroupElement
            ));
        }
    }

    #[test]
    fn small_order_points_are_invalid_public_keys() {
        let small_order = Scalar::from(8_u32);
        // First element of `EIGHT_TORSION` is the point at infinity; since it
        // would be processed differently, we skip it.
        for point in EIGHT_TORSION.iter().skip(1) {
            assert_eq!(point * small_order, EdwardsPoint::identity());
            let bytes = point.compress().to_bytes();
            assert!(matches!(
                PublicKey::from_bytes(&bytes).unwrap_err(),
                PublicKeyConversionError::InvalidGroupElement
            ));
        }
    }
}
