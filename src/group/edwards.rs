use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};

use std::{convert::TryInto, io::Read};

use crate::group::{Group, PointOps, ScalarOps};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Edwards {}

impl ScalarOps for Edwards {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
        let mut scalar_bytes = [0_u8; 64];
        rng.fill_bytes(&mut scalar_bytes[..]);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    fn scalar_from_random_bytes<R: Read>(mut source: R) -> Self::Scalar {
        let mut scalar_bytes = [0_u8; 64];
        source.read_exact(&mut scalar_bytes).unwrap();
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn invert_scalars(scalars: &mut [Self::Scalar]) {
        Scalar::batch_invert(scalars);
    }

    fn serialize_scalar(scalar: &Self::Scalar, output: &mut Vec<u8>) {
        output.extend_from_slice(&scalar.to_bytes())
    }

    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        let bytes: &[u8; 32] = bytes.try_into().expect("input has incorrect byte size");
        Scalar::from_canonical_bytes(*bytes)
    }
}

impl PointOps for Edwards {
    type Point = EdwardsPoint;

    const POINT_SIZE: usize = 32;

    fn identity() -> Self::Point {
        EdwardsPoint::identity()
    }

    fn is_identity(point: &Self::Point) -> bool {
        point.is_identity()
    }

    fn base_point() -> Self::Point {
        ED25519_BASEPOINT_POINT
    }

    fn serialize_point(point: &Self::Point, output: &mut Vec<u8>) {
        output.extend_from_slice(&point.compress().to_bytes())
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

    fn vartime_scalar_mul_basepoint(k: &Scalar) -> Self::Point {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &Scalar::zero(),
            &EdwardsPoint::identity(),
            k,
        )
    }

    fn multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        EdwardsPoint::multiscalar_mul(scalars, points)
    }

    fn vartime_double_scalar_mul_basepoint(
        k: &Scalar,
        k_point: Self::Point,
        r: &Scalar,
    ) -> Self::Point {
        EdwardsPoint::vartime_double_scalar_mul_basepoint(k, &k_point, r)
    }

    fn vartime_multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
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
            let mut point = Edwards::scalar_mul_basepoint(&Edwards::generate_scalar(&mut rng));
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
