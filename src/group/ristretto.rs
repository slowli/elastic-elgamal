use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};

use std::{convert::TryInto, io::Read};

use crate::group::{Group, PointOps, ScalarOps};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ristretto {}

impl ScalarOps for Ristretto {
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

impl PointOps for Ristretto {
    type Point = RistrettoPoint;

    const POINT_SIZE: usize = 32;

    fn identity() -> Self::Point {
        RistrettoPoint::identity()
    }

    fn is_identity(point: &Self::Point) -> bool {
        point.is_identity()
    }

    fn base_point() -> Self::Point {
        RISTRETTO_BASEPOINT_POINT
    }

    fn serialize_point(point: &Self::Point, output: &mut Vec<u8>) {
        output.extend_from_slice(&point.compress().to_bytes());
    }

    fn deserialize_point(input: &[u8]) -> Option<Self::Point> {
        CompressedRistretto::from_slice(input).decompress()
    }
}

impl Group for Ristretto {
    fn scalar_mul_basepoint(k: &Scalar) -> Self::Point {
        k * &RISTRETTO_BASEPOINT_TABLE
    }

    fn multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        RistrettoPoint::multiscalar_mul(scalars, points)
    }

    fn vartime_double_scalar_mul_basepoint(
        k: Scalar,
        k_point: Self::Point,
        r: Scalar,
    ) -> Self::Point {
        RistrettoPoint::vartime_double_scalar_mul_basepoint(&k, &k_point, &r)
    }

    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        RistrettoPoint::vartime_multiscalar_mul(scalars, points)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{group, DecryptionLookupTable, Edwards, EncryptedChoice, Encryption};

    type SecretKey = group::SecretKey<Ristretto>;
    type Keypair = group::Keypair<Ristretto>;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let value = Ristretto::scalar_mul_basepoint(&Ristretto::generate_scalar(&mut rng));
        let encrypted = Encryption::new(value, keypair.public(), &mut rng);
        let decryption = keypair.secret().decrypt(encrypted);
        assert_eq!(decryption, value);
    }

    #[test]
    fn encrypt_choice() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let encrypted_choice: EncryptedChoice<Ristretto> =
            EncryptedChoice::new(5, 3, keypair.public(), &mut rng);
        assert!(encrypted_choice.verify(keypair.public()).is_some());

        let lookup_table = DecryptionLookupTable::<Ristretto>::new(0..=1);
        for (i, &variant) in encrypted_choice.variants_unchecked().iter().enumerate() {
            let decryption = keypair.secret().decrypt(variant);
            assert_eq!(lookup_table.get(&decryption).unwrap(), (i == 3) as u64);
        }
    }

    #[test]
    fn edwards_and_ristretto_public_keys_differ() {
        type EdKeypair = group::Keypair<Edwards>;

        for _ in 0..1_000 {
            let secret_key = SecretKey::generate(&mut thread_rng());
            let keypair = Keypair::from_secret(secret_key.clone());
            let ed_keypair = EdKeypair::from_secret(group::SecretKey::<Edwards>(secret_key.0));
            assert_ne!(keypair.public().as_bytes(), ed_keypair.public().as_bytes());
        }
    }
}
