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
/// Encryptions are partially homomorphic: they can be added together or multiplied by a scalar
/// value.
///
/// # Examples
///
/// Basic usage and arithmetic for encryptions:
///
/// ```
/// # use elgamal_with_sharing::{group::Ristretto, DiscreteLogTable, Encryption, Keypair};
/// # use rand::thread_rng;
/// // Generate a keypair for the ciphertext recipient.
/// let mut rng = thread_rng();
/// let recipient = Keypair::<Ristretto>::generate(&mut rng);
/// // Create a couple of ciphertexts.
/// let mut enc = Encryption::new(2_u64, recipient.public(), &mut rng);
/// enc += Encryption::new(3_u64, recipient.public(), &mut rng) * 4;
/// // Check that the ciphertext decrypts to 2 + 3 * 4 = 14.
/// let lookup_table = DiscreteLogTable::new(0..20);
/// let decrypted = recipient.secret().decrypt(enc, &lookup_table);
/// assert_eq!(decrypted, Some(14));
/// ```
///
/// Creating an encryption of a boolean value together with a proof:
///
/// ```
/// # use elgamal_with_sharing::{group::Ristretto, Encryption, Keypair};
/// # use rand::thread_rng;
/// // Generate a keypair for the ciphertext recipient.
/// let mut rng = thread_rng();
/// let recipient = Keypair::<Ristretto>::generate(&mut rng);
/// // Create and verify a boolean encryption.
/// let (enc, proof) =
///     Encryption::encrypt_bool(false, recipient.public(), &mut rng);
/// assert!(enc.verify_bool(recipient.public(), &proof));
/// ```
#[derive(Clone, Copy)]
pub struct Encryption<G: Group> {
    pub(crate) random_element: G::Element,
    pub(crate) blinded_element: G::Element,
}

impl<G: Group> fmt::Debug for Encryption<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Encryption")
            .field("random_element", &self.random_element)
            .field("blinded_element", &self.blinded_element)
            .finish()
    }
}

impl<G: Group> Encryption<G> {
    /// Encrypts a value for the specified `receiver`.
    pub fn new<T, R: CryptoRng + RngCore>(value: T, receiver: &PublicKey<G>, rng: &mut R) -> Self
    where
        G::Scalar: From<T>,
    {
        let scalar = G::Scalar::from(value);
        let element = G::mul_generator(&scalar);
        EncryptionWithLog::new(element, receiver, rng).inner
    }

    /// Represents encryption of zero value without the blinding factor.
    pub fn zero() -> Self {
        Self {
            random_element: G::identity(),
            blinded_element: G::identity(),
        }
    }

    /// Serializes this encryption as two group elements (the random element,
    /// then the blinded value).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * G::ELEMENT_SIZE);
        G::serialize_element(&self.random_element, &mut bytes);
        G::serialize_element(&self.blinded_element, &mut bytes);
        bytes
    }

    /// Encrypts zero value and provides a zero-knowledge proof of encryption correctness.
    pub fn encrypt_zero<R>(receiver: &PublicKey<G>, rng: &mut R) -> (Self, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let blinded_element = receiver.full * &random_scalar.0;
        let encryption = Self {
            random_element,
            blinded_element,
        };

        let proof = LogEqualityProof::new(
            receiver,
            &random_scalar,
            (random_element, blinded_element),
            &mut Transcript::new(b"zero_encryption"),
            rng,
        );

        (encryption, proof)
    }

    /// Verifies that this is an encryption of a zero value.
    pub fn verify_zero(&self, receiver: &PublicKey<G>, proof: &LogEqualityProof<G>) -> bool {
        proof.verify(
            receiver,
            (self.random_element, self.blinded_element),
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
        let admissible_values = [G::identity(), G::generator()];
        let mut builder = RingProofBuilder::new(&receiver, &mut transcript, rng);
        let encryption = builder.add_value(&admissible_values, value as usize);
        (encryption.inner, builder.build())
    }

    /// Verifies a proof of encryption correctness of a boolean value, which was presumably
    /// obtained via [`Self::encrypt_bool()`].
    pub fn verify_bool(&self, receiver: &PublicKey<G>, proof: &RingProof<G>) -> bool {
        let admissible_values = [G::identity(), G::generator()];
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
            random_element: self.random_element + rhs.random_element,
            blinded_element: self.blinded_element + rhs.blinded_element,
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
            random_element: self.random_element - rhs.random_element,
            blinded_element: self.blinded_element - rhs.blinded_element,
        }
    }
}

impl<G: Group> ops::SubAssign for Encryption<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for Encryption<G> {
    type Output = Self;

    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            random_element: self.random_element * rhs,
            blinded_element: self.blinded_element * rhs,
        }
    }
}

impl<G: Group> ops::Mul<u64> for Encryption<G> {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        let scalar = G::Scalar::from(rhs);
        self * &scalar
    }
}

/// Lookup table for discrete logarithms.
///
/// For ElGamal [`Encryption`] to be partially homomorphic, the encrypted values must be
/// group scalars linearly mapped to group elements: `x -> [x]G`, where `G` is the group
/// generator. After decryption it is necessary to map the decrypted group element back to a scalar
/// (i.e., get its discrete logarithm with base `G`). By definition of the group,
/// this task is computationally infeasible in the general case; however, if the possible range
/// of encrypted values is small, it is possible to "cheat" by precomputing mapping `[x]G -> x`
/// for all allowed `x` ahead of time. This is exactly what `DiscreteLogTable` does.
///
/// # Examples
///
/// ```
/// # use elgamal_with_sharing::{group::Ristretto, DiscreteLogTable, Encryption, Keypair};
/// # use rand::thread_rng;
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let encryptions = (0_u64..16)
///     .map(|i| Encryption::new(i, receiver.public(), &mut rng));
/// // Assume that we know that the encryption in range 0..16,
/// // e.g., via a zero-knowledge proof.
/// let lookup_table = DiscreteLogTable::new(0..16);
/// // Then, we can use the lookup table to decrypt values.
/// // A single table may be shared for multiple decryptions
/// // (i.e., it may be constructed ahead of time).
/// for (i, enc) in encryptions.enumerate() {
///     assert_eq!(
///         receiver.secret().decrypt(enc, &lookup_table),
///         Some(i as u64)
///     );
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DiscreteLogTable<G: Group> {
    inner: HashMap<Vec<u8>, u64>,
    _t: PhantomData<G>,
}

impl<G: Group> DiscreteLogTable<G> {
    /// Creates a lookup table for the specified `values`.
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let lookup_table = values
            .into_iter()
            .filter(|&value| value != 0)
            .map(|i| {
                let element = G::vartime_mul_generator(&G::Scalar::from(i));
                let mut bytes = Vec::with_capacity(G::ELEMENT_SIZE);
                G::serialize_element(&element, &mut bytes);
                (bytes, i)
            })
            .collect();

        Self {
            inner: lookup_table,
            _t: PhantomData,
        }
    }

    /// Gets the discrete log of `decrypted_element`, or `None` if it is not present among `values`
    /// stored in this table.
    pub fn get(&self, decrypted_element: &G::Element) -> Option<u64> {
        if G::is_identity(decrypted_element) {
            // The identity element may have a special serialization (e.g., in SEC standard
            // for elliptic curves), so we check it separately.
            Some(0)
        } else {
            let mut bytes = Vec::with_capacity(G::ELEMENT_SIZE);
            G::serialize_element(decrypted_element, &mut bytes);
            self.inner.get(&bytes).copied()
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
        value: G::Element,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let dh_element = receiver.full * &random_scalar.0;
        let blinded_element = value + dh_element;

        Self {
            inner: Encryption {
                random_element,
                blinded_element,
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
///
/// # Examples
///
/// ```
/// # use elgamal_with_sharing::{group::Ristretto, DiscreteLogTable, EncryptedChoice, Keypair};
/// # use rand::thread_rng;
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let choice = 2;
/// let enc = EncryptedChoice::new(5, choice, receiver.public(), &mut rng);
/// let variants = enc.verify(receiver.public()).unwrap();
///
/// // `variants` is a slice of 5 Boolean value encryptions
/// assert_eq!(variants.len(), 5);
/// let lookup_table = DiscreteLogTable::new(0..=1);
/// for (idx, &v) in variants.iter().enumerate() {
///     assert_eq!(
///         receiver.secret().decrypt(v, &lookup_table),
///         Some((idx == choice) as u64)
///     );
/// }
/// ```
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

        let admissible_values = [G::identity(), G::generator()];
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
            &sum_log,
            (
                sum_encryption.random_element,
                sum_encryption.blinded_element - G::generator(),
            ),
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
            sum_encryption.random_element,
            sum_encryption.blinded_element - G::generator(),
        );
        if !self.sum_proof.verify(
            receiver,
            powers,
            &mut Transcript::new(b"choice_encryption_sum"),
        ) {
            return None;
        }

        let admissible_values = [G::identity(), G::generator()];
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
        choice.variants[4].blinded_element =
            choice.variants[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.variants[3].blinded_element =
            choice.variants[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
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
