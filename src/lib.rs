// Implementation note: we use `SecretKey`s for sensitive scalars.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use std::{collections::HashMap, marker::PhantomData, ops};

mod group;
mod proofs;
pub mod sharing;

pub use crate::group::{
    Edwards, Group, Keypair, PublicKey, Ristretto, SecretKey, HASH_SIZE, PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
};
pub use crate::proofs::{
    LogEqualityProof, ProofOfPossession, RingProof, RingProofBuilder, LOG_EQ_PROOF_SIZE,
};

/// ElGamal ciphertext.
///
/// Ciphertexts are partially homomorphic: they can be added together or multiplied by a scalar
/// value.
#[derive(Debug, Clone, Copy)]
pub struct Encryption<G: Group> {
    random_point: G::Point,
    blinded_point: G::Point,
}

impl<G: Group> Encryption<G> {
    /// Encrypts a value given as an EC point for the specified `receiver`.
    pub fn new<R: CryptoRng + RngCore>(
        value: G::Point,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        EncryptionWithLog::new(value, receiver, rng).encryption
    }

    pub fn zero() -> Self {
        Self {
            random_point: G::identity(),
            blinded_point: G::identity(),
        }
    }

    /// Serializes this encryption as two compressed EC points (the random point,
    /// then the blinded value).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0; 2 * G::POINT_SIZE];
        G::serialize_point(&self.random_point, &mut bytes[..G::POINT_SIZE]);
        G::serialize_point(&self.blinded_point, &mut bytes[G::POINT_SIZE..]);
        bytes
    }

    /// Encrypts zero value and provides a zero-knowledge proof of encryption correctness.
    pub fn encrypt_zero<R>(receiver: &PublicKey<G>, rng: &mut R) -> (Self, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_point = G::scalar_mul_basepoint(&random_scalar.0);
        let blinded_point = receiver.full * &random_scalar.0;
        let encryption = Self {
            random_point,
            blinded_point,
        };

        let proof = LogEqualityProof::new(
            receiver,
            (random_point, blinded_point),
            &random_scalar.0,
            &mut Transcript::new(b"zero_encryption"),
            rng,
        );

        (encryption, proof)
    }

    /// Verifies that this is an encryption of a zero value.
    pub fn verify_zero(&self, receiver: &PublicKey<G>, proof: &LogEqualityProof<G>) -> bool {
        proof.verify(
            receiver,
            (self.random_point, self.blinded_point),
            &mut Transcript::new(b"zero_encryption"),
        )
    }

    /// Encrypts a boolean value (0 or 1) and provides a zero-knowledge proof of encryption
    /// correctness.
    pub fn encrypt_bool<R>(
        value: bool,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> (Self, RingProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let mut transcript = Transcript::new(b"bool_encryption");
        let admissible_values = [G::identity(), G::base_point()];
        let mut builder = RingProofBuilder::new(&receiver, &mut transcript, rng);
        let encryption = builder.add_value(&admissible_values, value as usize);
        (encryption.unwrap(), builder.build())
    }

    pub fn verify_bool(&self, receiver: &PublicKey<G>, proof: &RingProof<G>) -> bool {
        let admissible_values = [G::identity(), G::base_point()];
        proof.verify(
            receiver,
            &[&admissible_values],
            &[*self],
            &mut Transcript::new(b"bool_encryption"),
        )
    }
}

impl<G: Group> ops::Add for Encryption<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            random_point: self.random_point + rhs.random_point,
            blinded_point: self.blinded_point + rhs.blinded_point,
        }
    }
}

impl<G: Group> ops::AddAssign for Encryption<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<G: Group> ops::Sub for Encryption<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            random_point: self.random_point - rhs.random_point,
            blinded_point: self.blinded_point - rhs.blinded_point,
        }
    }
}

impl<'a, G: Group> ops::Mul<&'a G::Scalar> for Encryption<G> {
    type Output = Self;

    fn mul(self, rhs: &'a G::Scalar) -> Self {
        Self {
            random_point: self.random_point * rhs,
            blinded_point: self.blinded_point * rhs,
        }
    }
}

impl<G: Group> SecretKey<G> {
    /// Decrypts the provided ciphertext and returns the produced EC point.
    ///
    /// As the ciphertext does not include a MAC or another way to assert integrity,
    /// this operation cannot fail. If the ciphertext is not produced properly (e.g., it targets
    /// another receiver), the returned point will be garbage.
    pub fn decrypt(&self, encrypted: Encryption<G>) -> G::Point {
        let dh_point = encrypted.random_point * &self.0;
        encrypted.blinded_point - dh_point
    }
}

#[derive(Debug, Clone)]
pub struct DecryptionLookupTable<G: Group> {
    inner: HashMap<[u8; 8], u64>,
    _t: PhantomData<G>,
}

impl<G: Group> DecryptionLookupTable<G> {
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let zero = G::Scalar::from(0);
        let lookup_table = values
            .into_iter()
            .map(|i| {
                let point = G::vartime_double_scalar_mul_basepoint(
                    zero,
                    G::base_point(),
                    G::Scalar::from(i),
                );
                let mut bytes = vec![0_u8; G::POINT_SIZE];
                G::serialize_point(&point, &mut bytes);
                let mut initial_bytes = [0_u8; 8];
                initial_bytes.copy_from_slice(&bytes[..8]);
                (initial_bytes, i)
            })
            .collect();

        Self {
            inner: lookup_table,
            _t: PhantomData,
        }
    }

    pub fn get(&self, decrypted_point: G::Point) -> Option<u64> {
        let mut bytes = vec![0_u8; G::POINT_SIZE];
        G::serialize_point(&decrypted_point, &mut bytes);
        let mut initial_bytes = [0_u8; 8];
        initial_bytes.copy_from_slice(&bytes[..8]);
        self.inner.get(&initial_bytes).cloned()
    }
}

#[derive(Clone)]
pub struct EncryptionWithLog<G: Group> {
    encryption: Encryption<G>,
    discrete_log: SecretKey<G>,
}

impl<G: Group> EncryptionWithLog<G> {
    pub fn new<R: CryptoRng + RngCore>(
        value: G::Point,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_point = G::scalar_mul_basepoint(&random_scalar.0);
        let dh_point = receiver.full * &random_scalar.0;
        let biased_point = value + dh_point;

        Self {
            encryption: Encryption {
                random_point,
                blinded_point: biased_point,
            },
            discrete_log: random_scalar,
        }
    }

    fn unwrap(self) -> Encryption<G> {
        self.encryption
    }
}

#[derive(Clone)]
pub struct EncryptedChoice<G: Group> {
    variants: Vec<Encryption<G>>,
    range_proofs: RingProof<G>,
    sum_proof: LogEqualityProof<G>,
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group> EncryptedChoice<G> {
    pub fn new<R>(
        number_of_variants: usize,
        choice: usize,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        assert!(number_of_variants > 0);
        assert!(choice < number_of_variants);

        let admissible_values = [G::identity(), G::base_point()];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(receiver, &mut transcript, rng);

        let variants: Vec<_> = (0..number_of_variants)
            .map(|i| proof_builder.add_value(&admissible_values, (i == choice) as usize))
            .collect();
        let range_proofs = proof_builder.build();

        let mut sum_log = variants[0].discrete_log.clone();
        let mut sum_encryption = variants[0].encryption;
        for variant in variants.iter().skip(1) {
            sum_log += variant.discrete_log.clone();
            sum_encryption += variant.encryption;
        }

        let sum_proof = LogEqualityProof::new(
            receiver,
            (
                sum_encryption.random_point,
                sum_encryption.blinded_point - G::base_point(),
            ),
            &sum_log.0,
            &mut Transcript::new(b"choice_encryption_sum"),
            rng,
        );

        Self {
            variants: variants
                .into_iter()
                .map(|variant| variant.encryption)
                .collect(),
            range_proofs,
            sum_proof,
        }
    }

    pub fn len(&self) -> usize {
        self.variants.len()
    }

    pub fn variants_unchecked(&self) -> &[Encryption<G>] {
        &self.variants
    }

    pub fn range_proofs(&self) -> &RingProof<G> {
        &self.range_proofs
    }

    pub fn sum_proof(&self) -> &LogEqualityProof<G> {
        &self.sum_proof
    }

    pub fn verify(&self, receiver: &PublicKey<G>) -> Option<&[Encryption<G>]> {
        // Some sanity checks.
        if self.len() == 0 || self.range_proofs.total_rings_size() != 2 * self.variants.len() {
            return None;
        }

        let mut sum_encryption = self.variants[0];
        for &variant in self.variants.iter().skip(1) {
            sum_encryption += variant;
        }

        let powers = (
            sum_encryption.random_point,
            sum_encryption.blinded_point - G::base_point(),
        );
        if !self.sum_proof.verify(
            receiver,
            powers,
            &mut Transcript::new(b"choice_encryption_sum"),
        ) {
            return None;
        }

        let admissible_values = [G::identity(), G::base_point()];
        let admissible_values = vec![&admissible_values as &[_]; self.variants.len()];
        if self.range_proofs.verify(
            receiver,
            &admissible_values,
            &self.variants,
            &mut Transcript::new(b"encrypted_choice_ranges"),
        ) {
            Some(&self.variants)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;
    use rand::{thread_rng, Rng};

    use std::collections::HashMap;

    use super::*;
    use crate::{
        group::{self, PointOps},
        Edwards,
    };

    type Keypair = group::Keypair<Edwards>;

    #[test]
    fn encryption_roundtrip() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let message = Edwards::scalar_mul_basepoint(&Scalar25519::from(12345_u32));
        let encrypted = Encryption::new(message, keypair.public(), &mut rng);
        let decryption = keypair.secret().decrypt(encrypted);
        assert_eq!(decryption, message);
    }

    #[test]
    fn zero_encryption_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let (zero_encryption, proof) = Encryption::encrypt_zero(keypair.public(), &mut rng);
        assert!(zero_encryption.verify_zero(keypair.public(), &proof));
        let decrypted = keypair.secret().decrypt(zero_encryption);
        assert_eq!(
            decrypted,
            Edwards::scalar_mul_basepoint(&Scalar25519::zero())
        );

        // The proof should not verify for non-zero messages.
        let message = Edwards::scalar_mul_basepoint(&Scalar25519::from(123_u32));
        let encryption = Encryption::new(message, keypair.public(), &mut rng);
        assert!(!encryption.verify_zero(keypair.public(), &proof));

        // ...or for another receiver key
        let other_keypair = Keypair::generate(&mut rng);
        assert!(!encryption.verify_zero(other_keypair.public(), &proof));

        // ...or for another secret scalar used.
        let (other_zero_encryption, other_proof) =
            Encryption::encrypt_zero(keypair.public(), &mut rng);
        assert!(!other_zero_encryption.verify_zero(keypair.public(), &proof));
        assert!(!zero_encryption.verify_zero(keypair.public(), &other_proof));

        let combined_encryption = other_zero_encryption + zero_encryption;
        assert!(!combined_encryption.verify_zero(keypair.public(), &proof));
        assert!(!combined_encryption.verify_zero(keypair.public(), &other_proof));
    }

    #[test]
    fn zero_proof_serialization() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let mut encryptions = HashMap::new();

        for _ in 0..100 {
            let (zero_encryption, proof) = Encryption::encrypt_zero(keypair.public(), &mut rng);
            let bytes = proof.to_bytes();
            encryptions.insert(bytes.to_vec(), zero_encryption);
        }
        assert_eq!(encryptions.len(), 100);
        for (byte_vec, encryption) in encryptions {
            let mut bytes = [0_u8; LOG_EQ_PROOF_SIZE];
            bytes.copy_from_slice(&byte_vec);
            let proof = LogEqualityProof::from_bytes(bytes).unwrap();
            assert!(encryption.verify_zero(keypair.public(), &proof));
        }
    }

    #[test]
    fn bool_encryption_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        let (encryption, proof) = Encryption::encrypt_bool(false, keypair.public(), &mut rng);
        assert_eq!(keypair.secret().decrypt(encryption), Edwards::identity());
        assert!(encryption.verify_bool(keypair.public(), &proof));

        let (other_encryption, other_proof) =
            Encryption::encrypt_bool(true, keypair.public(), &mut rng);
        assert_eq!(
            keypair.secret().decrypt(other_encryption),
            Edwards::base_point()
        );
        assert!(other_encryption.verify_bool(keypair.public(), &other_proof));

        // The proofs should not verify for another encryption.
        assert!(!other_encryption.verify_bool(keypair.public(), &proof));
        assert!(!encryption.verify_bool(keypair.public(), &other_proof));

        // ...even if the encryption is obtained from the "correct" value.
        let combined_encryption = encryption + other_encryption;
        assert_eq!(
            keypair.secret().decrypt(combined_encryption),
            Edwards::base_point()
        );
        assert!(!combined_encryption.verify_bool(keypair.public(), &proof));
    }

    #[test]
    fn bool_proof_serialization() {
        const BOOL_ENC_PROOF_SIZE: usize = 3 * SECRET_KEY_SIZE;

        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let mut encryptions = HashMap::new();

        for _ in 0..100 {
            let (bool_encryption, proof) =
                Encryption::encrypt_bool(rng.gen_bool(0.5), keypair.public(), &mut rng);
            let bytes = proof.to_bytes();
            assert_eq!(bytes.len(), BOOL_ENC_PROOF_SIZE);
            encryptions.insert(bytes, bool_encryption);
        }
        assert_eq!(encryptions.len(), 100);
        for (bytes, encryption) in encryptions {
            let proof = RingProof::from_slice(&bytes).unwrap();
            assert!(encryption.verify_bool(keypair.public(), &proof));
        }
    }

    #[test]
    fn encrypted_choice_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        let choice = EncryptedChoice::new(5, 2, keypair.public(), &mut rng);
        assert!(choice.verify(keypair.public()).is_some());
        assert_eq!(choice.variants.len(), 5);
        for (i, &variant) in choice.variants.iter().enumerate() {
            let expected_plaintext = if i == 2 {
                Edwards::base_point()
            } else {
                Edwards::identity()
            };
            assert_eq!(keypair.secret().decrypt(variant), expected_plaintext);
        }
    }

    #[test]
    fn bogus_encrypted_choice_does_not_work() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        let mut choice = EncryptedChoice::new(5, 2, keypair.public(), &mut rng);
        let (encrypted_one, _) = Encryption::encrypt_bool(true, keypair.public(), &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(choice.verify(keypair.public()).is_none());

        let mut choice = EncryptedChoice::new(5, 4, keypair.public(), &mut rng);
        let (encrypted_zero, _) = Encryption::encrypt_bool(false, keypair.public(), &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(choice.verify(keypair.public()).is_none());

        let mut choice = EncryptedChoice::new(5, 4, keypair.public(), &mut rng);
        choice.variants[4].blinded_point +=
            Edwards::scalar_mul_basepoint(&Scalar25519::from(10_u32));
        choice.variants[3].blinded_point -=
            Edwards::scalar_mul_basepoint(&Scalar25519::from(10_u32));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(choice.verify(keypair.public()).is_none());
    }
}
