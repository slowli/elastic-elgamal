use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{MultiscalarMul, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};

use crate::group::{Group, PointOps, ScalarOps, SECRET_KEY_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Edwards {}

impl ScalarOps for Edwards {
    type Scalar = Scalar;

    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn scalar_from_random_bytes(bytes: [u8; 2 * SECRET_KEY_SIZE]) -> Self::Scalar {
        Scalar::from_bytes_mod_order_wide(&bytes)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn invert_scalars(scalars: &mut [Self::Scalar]) {
        Scalar::batch_invert(scalars);
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> [u8; SECRET_KEY_SIZE] {
        scalar.to_bytes()
    }

    fn deserialize_scalar(bytes: [u8; SECRET_KEY_SIZE]) -> Option<Self::Scalar> {
        Scalar::from_canonical_bytes(bytes)
    }
}

impl PointOps for Edwards {
    type Point = EdwardsPoint;

    const POINT_SIZE: usize = 32;

    fn base_point() -> Self::Point {
        ED25519_BASEPOINT_POINT
    }

    fn serialize_point(point: &Self::Point, output: &mut [u8]) {
        output.copy_from_slice(&point.compress().to_bytes())
    }

    fn deserialize_point(input: &[u8]) -> Option<Self::Point> {
        CompressedEdwardsY::from_slice(input)
            .decompress()
            .filter(EdwardsPoint::is_torsion_free)
    }
}

impl Group for Edwards {
    fn scalar_mul_basepoint(k: &Scalar) -> Self::Point {
        k * &ED25519_BASEPOINT_TABLE
    }

    fn multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        EdwardsPoint::multiscalar_mul(scalars, points)
    }

    fn vartime_double_scalar_mul_basepoint(
        k: Scalar,
        k_point: Self::Point,
        r: Scalar,
    ) -> Self::Point {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &k_point, &r)
    }

    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        EdwardsPoint::vartime_multiscalar_mul(scalars, points)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::EIGHT_TORSION, scalar::Scalar, traits::Identity};
    use rand::thread_rng;

    use super::*;
    use crate::group;

    type PublicKey = group::PublicKey<Edwards>;

    #[test]
    fn mangled_point_is_invalid_public_key() {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let mut point = Edwards::scalar_mul_basepoint(&Scalar::random(&mut rng));
            point += EIGHT_TORSION[1];
            assert!(!point.is_torsion_free());
            let bytes = point.compress().to_bytes();
            assert!(PublicKey::from_bytes(&bytes).is_none());
        }
    }

    #[test]
    fn small_order_points_are_invalid_public_keys() {
        let small_order = Scalar::from(8_u32);
        for point in &EIGHT_TORSION {
            assert_eq!(point * small_order, EdwardsPoint::identity());
            let bytes = point.compress().to_bytes();
            assert!(PublicKey::from_bytes(&bytes).is_none());
        }
    }
}
