//! `Encryption` and closely related types.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use std::{collections::HashMap, fmt, marker::PhantomData, ops};

use crate::{
    group::Group,
    proofs::{LogEqualityProof, RingProof, RingProofBuilder},
    PublicKey, SecretKey,
};

/// ElGamal asymmetric encryption.
///
/// Ciphertexts are partially homomorphic: they can be added together or multiplied by a scalar
/// value.
#[derive(Clone, Copy)]
pub struct Encryption<G: Group> {
    pub(crate) random_point: G::Point,
    pub(crate) blinded_point: G::Point,
}

impl<G: Group> fmt::Debug for Encryption<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Encryption")
            .field("random_point", &self.random_point)
            .field("blinded_point", &self.blinded_point)
            .finish()
    }
}

impl<G: Group> Encryption<G> {
    /// Encrypts a value given as an EC point for the specified `receiver`.
    pub fn new<R: CryptoRng + RngCore>(
        value: G::Point,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        EncryptionWithLog::new(value, receiver, rng).inner
    }

    /// Represents encryption of zero value without the blinding factor.
    pub fn zero() -> Self {
        Self {
            random_point: G::identity(),
            blinded_point: G::identity(),
        }
    }

    /// Serializes this encryption as two compressed EC points (the random point,
    /// then the blinded value).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * G::POINT_SIZE);
        G::serialize_point(&self.random_point, &mut bytes);
        G::serialize_point(&self.blinded_point, &mut bytes);
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
        (encryption.inner, builder.build())
    }

    /// Verifies a proof of encryption correctness of a boolean value, which was presumably
    /// obtained via [`Self::encrypt_bool()`].
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

impl<G: Group> ops::Mul<&G::Scalar> for Encryption<G> {
    type Output = Self;

    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            random_point: self.random_point * rhs,
            blinded_point: self.blinded_point * rhs,
        }
    }
}

/// Lookup table for discrete logarithms.
///
/// FIXME: explain why it's necessary.
#[derive(Debug, Clone)]
pub struct DiscreteLogLookupTable<G: Group> {
    inner: HashMap<[u8; 8], u64>,
    _t: PhantomData<G>,
}

impl<G: Group> DiscreteLogLookupTable<G> {
    /// Creates a lookup table for the specified `values`.
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let lookup_table = values
            .into_iter()
            .filter(|&value| value != 0)
            .map(|i| {
                let point = G::vartime_scalar_mul_basepoint(&G::Scalar::from(i));
                let mut bytes = Vec::with_capacity(G::POINT_SIZE);
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

    /// Gets the discrete log of `decrypted_point`, or `None` if it is not present among `values`
    /// supplied when constructing this table.
    pub fn get(&self, decrypted_point: &G::Point) -> Option<u64> {
        if G::is_identity(decrypted_point) {
            // The identity point may have a special serialization (e.g., in SEC standard),
            // so we check it separately.
            Some(0)
        } else {
            let mut bytes = Vec::with_capacity(G::POINT_SIZE);
            G::serialize_point(decrypted_point, &mut bytes);
            let mut initial_bytes = [0_u8; 8];
            initial_bytes.copy_from_slice(&bytes[..8]);
            self.inner.get(&initial_bytes).copied()
        }
    }
}

/// [`Encryption`] together with the random scalar used to create it.
#[derive(Debug, Clone)]
#[doc(hidden)] // only public for benchmarking
pub struct EncryptionWithLog<G: Group> {
    pub inner: Encryption<G>,
    pub random_scalar: SecretKey<G>,
}

impl<G: Group> EncryptionWithLog<G> {
    /// Creates an encryption of `value` for the specified `receiver`.
    pub fn new<R: CryptoRng + RngCore>(
        value: G::Point,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_point = G::scalar_mul_basepoint(&random_scalar.0);
        let dh_point = receiver.full * &random_scalar.0;
        let blinded_point = value + dh_point;

        Self {
            inner: Encryption {
                random_point,
                blinded_point,
            },
            random_scalar,
        }
    }
}

/// Encrypted choice of a value in a range `0..n` for certain integer `n > 1` together with
/// validity zero-knowledge proofs.
///
/// # Construction
///
/// The choice is represented as a vector of `n` *variant encryptions* of Boolean values (0 or 1),
/// where the chosen variant is an encryption of 1 and other variants are encryptions of 0.
/// This ensures that multiple [`EncryptedChoice`]s can be added (e.g., within a voting protocol).
/// These encryptions can be obtained via [`Self::verify()`].
///
/// Zero-knowledge proofs are:
///
/// - A [`RingProof`] attesting that all `n` encryptions are indeed encryptions of Boolean
///   values. This proof can be obtained via [`Self::range_proof()`].
/// - A [`LogEqualityProof`] attesting that the encrypted values sum up to 1. Combined with
///   the range proof, this means that exactly one of encryptions is 1, and all others are 0.
///   This proof can be obtained via [`Self::sum_proof()`].
#[derive(Debug, Clone)]
pub struct EncryptedChoice<G: Group> {
    variants: Vec<Encryption<G>>,
    range_proof: RingProof<G>,
    sum_proof: LogEqualityProof<G>,
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group> EncryptedChoice<G> {
    /// Creates an encrypted choice.
    ///
    /// # Panics
    ///
    /// Panics if `number_of_variants` is zero, or if `choice` is not in `0..number_of_variants`.
    pub fn new<R>(
        number_of_variants: usize,
        choice: usize,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        assert!(
            number_of_variants > 0,
            "`number_of_variants` must be positive"
        );
        assert!(
            choice < number_of_variants,
            "invalid choice {}; expected a value in 0..{}",
            choice,
            number_of_variants
        );

        let admissible_values = [G::identity(), G::base_point()];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(receiver, &mut transcript, rng);

        let variants: Vec<_> = (0..number_of_variants)
            .map(|i| proof_builder.add_value(&admissible_values, (i == choice) as usize))
            .collect();
        let range_proofs = proof_builder.build();

        let mut sum_log = variants[0].random_scalar.clone();
        let mut sum_encryption = variants[0].inner;
        for variant in variants.iter().skip(1) {
            sum_log += variant.random_scalar.clone();
            sum_encryption += variant.inner;
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
            variants: variants.into_iter().map(|variant| variant.inner).collect(),
            range_proof: range_proofs,
            sum_proof,
        }
    }

    /// Returns the number of variants in this choice.
    pub fn len(&self) -> usize {
        self.variants.len()
    }

    /// Returns variant encryptions **without** checking their validity.
    pub fn variants_unchecked(&self) -> &[Encryption<G>] {
        &self.variants
    }

    /// Returns the range proof for the variant encryptions.
    pub fn range_proof(&self) -> &RingProof<G> {
        &self.range_proof
    }

    /// Returns the sum proof for the variant encryptions.
    pub fn sum_proof(&self) -> &LogEqualityProof<G> {
        &self.sum_proof
    }

    /// Verifies the range and sum proofs in this choice and returns variant encryptions
    /// if they check out. Otherwise, returns `None`.
    pub fn verify(&self, receiver: &PublicKey<G>) -> Option<&[Encryption<G>]> {
        // Some sanity checks.
        if self.len() == 0 || self.range_proof.total_rings_size() != 2 * self.variants.len() {
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
        if self.range_proof.verify(
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
    use rand::thread_rng;

    use super::*;
    use crate::{
        group::{Generic, Ristretto},
        Keypair,
    };

    fn test_bogus_encrypted_choice_does_not_work<G: Group>() {
        let mut rng = thread_rng();
        let keypair = Keypair::<G>::generate(&mut rng);

        let mut choice = EncryptedChoice::new(5, 2, keypair.public(), &mut rng);
        let (encrypted_one, _) = Encryption::encrypt_bool(true, keypair.public(), &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(choice.verify(keypair.public()).is_none());

        let mut choice = EncryptedChoice::new(5, 4, keypair.public(), &mut rng);
        let (encrypted_zero, _) = Encryption::encrypt_bool(false, keypair.public(), &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(choice.verify(keypair.public()).is_none());

        let mut choice = EncryptedChoice::new(5, 4, keypair.public(), &mut rng);
        choice.variants[4].blinded_point =
            choice.variants[4].blinded_point + G::scalar_mul_basepoint(&G::Scalar::from(10));
        choice.variants[3].blinded_point =
            choice.variants[3].blinded_point - G::scalar_mul_basepoint(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(choice.verify(keypair.public()).is_none());
    }

    #[test]
    fn bogus_encrypted_choice_does_not_work_for_edwards() {
        test_bogus_encrypted_choice_does_not_work::<Ristretto>();
    }

    #[test]
    fn bogus_encrypted_choice_does_not_work_for_k256() {
        test_bogus_encrypted_choice_does_not_work::<Generic<k256::Secp256k1>>();
    }
}
