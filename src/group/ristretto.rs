use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{MultiscalarMul, VartimeMultiscalarMul},
};
use rand_core::{CryptoRng, RngCore};

use crate::group::{Group, PointOps, ScalarOps, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ristretto {}

impl ScalarOps for Ristretto {
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

impl PointOps for Ristretto {
    type Point = RistrettoPoint;
    type CompressedPoint = CompressedRistretto;

    const BASE_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

    fn compress(point: &Self::Point) -> Self::CompressedPoint {
        point.compress()
    }

    fn serialize_point(compressed: &Self::CompressedPoint) -> [u8; PUBLIC_KEY_SIZE] {
        compressed.to_bytes()
    }

    fn deserialize_point(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self::CompressedPoint {
        CompressedRistretto(bytes)
    }

    fn decompress(compressed: &Self::CompressedPoint) -> Option<Self::Point> {
        compressed.decompress()
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
        let value = Ristretto::scalar_mul_basepoint(&Scalar::random(&mut rng));
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
            assert_eq!(lookup_table.get(decryption).unwrap(), (i == 3) as u64);
        }
    }

    #[test]
    fn edwards_and_ristretto_public_keys_differ() {
        type EdKeypair = group::Keypair<Edwards>;

        for _ in 0..1_000 {
            let secret_key = SecretKey::generate(&mut thread_rng());
            let keypair = Keypair::from_secret(secret_key.clone());
            let ed_keypair = EdKeypair::from_bytes(keypair.to_bytes()).unwrap();
            assert_ne!(keypair.public().to_bytes(), ed_keypair.public().to_bytes());
        }
    }
}
