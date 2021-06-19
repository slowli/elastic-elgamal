//! `Ciphertext` and closely related types.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::{collections::HashMap, fmt, marker::PhantomData, ops};

use crate::{
    group::Group,
    proofs::{LogEqualityProof, RingProof, RingProofBuilder},
    PublicKey, SecretKey,
};
#[cfg(feature = "serde")]
use crate::serde::ElementHelper;

/// Ciphertext for ElGamal encryption.
///
/// Ciphertexts are partially homomorphic: they can be added together or multiplied by a scalar
/// value.
///
/// # Examples
///
/// Basic usage and arithmetic for ciphertexts:
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// // Generate a keypair for the ciphertext recipient.
/// let mut rng = thread_rng();
/// let recipient = Keypair::<Ristretto>::generate(&mut rng);
/// // Create a couple of ciphertexts.
/// let mut enc = recipient.public().encrypt(2_u64, &mut rng);
/// enc += recipient.public().encrypt(3_u64, &mut rng) * 4;
/// // Check that the ciphertext decrypts to 2 + 3 * 4 = 14.
/// let lookup_table = DiscreteLogTable::new(0..20);
/// let decrypted = recipient.secret().decrypt(enc, &lookup_table);
/// assert_eq!(decrypted, Some(14));
/// ```
///
/// Creating a ciphertext of a boolean value together with a proof:
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// // Generate a keypair for the ciphertext recipient.
/// let mut rng = thread_rng();
/// let recipient = Keypair::<Ristretto>::generate(&mut rng);
/// // Create and verify a boolean encryption.
/// let (enc, proof) =
///     recipient.public().encrypt_bool(false, &mut rng);
/// assert!(recipient.public().verify_bool(enc, &proof));
/// ```
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    pub(crate) random_element: G::Element,
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    pub(crate) blinded_element: G::Element,
}

impl<G: Group> fmt::Debug for Ciphertext<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext")
            .field("random_element", &self.random_element)
            .field("blinded_element", &self.blinded_element)
            .finish()
    }
}

impl<G: Group> Ciphertext<G> {
    /// Represents encryption of zero value without the blinding factor.
    pub fn zero() -> Self {
        Self {
            random_element: G::identity(),
            blinded_element: G::identity(),
        }
    }

    /// Serializes this ciphertext as two group elements (the random element,
    /// then the blinded value).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * G::ELEMENT_SIZE);
        G::serialize_element(&self.random_element, &mut bytes);
        G::serialize_element(&self.blinded_element, &mut bytes);
        bytes
    }
}

impl<G: Group> PublicKey<G> {
    /// Encrypts a value for this key.
    pub fn encrypt<T, R: CryptoRng + RngCore>(&self, value: T, rng: &mut R) -> Ciphertext<G>
    where
        G::Scalar: From<T>,
    {
        let scalar = G::Scalar::from(value);
        let element = G::mul_generator(&scalar);
        ExtendedCiphertext::new(element, self, rng).inner
    }

    /// Encrypts zero value and provides a zero-knowledge proof of encryption correctness.
    pub fn encrypt_zero<R>(&self, rng: &mut R) -> (Ciphertext<G>, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let blinded_element = self.element * &random_scalar.0;
        let ciphertext = Ciphertext {
            random_element,
            blinded_element,
        };

        let proof = LogEqualityProof::new(
            self,
            &random_scalar,
            (random_element, blinded_element),
            &mut Transcript::new(b"zero_encryption"),
            rng,
        );

        (ciphertext, proof)
    }

    /// Verifies that this is an encryption of a zero value.
    pub fn verify_zero(&self, ciphertext: Ciphertext<G>, proof: &LogEqualityProof<G>) -> bool {
        proof.verify(
            self,
            (ciphertext.random_element, ciphertext.blinded_element),
            &mut Transcript::new(b"zero_encryption"),
        )
    }

    /// Encrypts a boolean value (0 or 1) and provides a zero-knowledge proof of encryption
    /// correctness.
    ///
    /// # Examples
    ///
    /// See [`Ciphertext`] docs for an example of usage.
    pub fn encrypt_bool<R: CryptoRng + RngCore>(
        &self,
        value: bool,
        rng: &mut R,
    ) -> (Ciphertext<G>, RingProof<G>) {
        let mut transcript = Transcript::new(b"bool_encryption");
        let admissible_values = [G::identity(), G::generator()];
        let mut builder = RingProofBuilder::new(self, &mut transcript, rng);
        let ciphertext = builder.add_value(&admissible_values, value as usize);
        (ciphertext.inner, builder.build())
    }

    /// Verifies a proof of encryption correctness of a boolean value, which was presumably
    /// obtained via [`Self::encrypt_bool()`].
    ///
    /// # Examples
    ///
    /// See [`Ciphertext`] docs for an example of usage.
    pub fn verify_bool(&self, ciphertext: Ciphertext<G>, proof: &RingProof<G>) -> bool {
        let admissible_values = [G::identity(), G::generator()];
        proof.verify(
            self,
            &[&admissible_values],
            &[ciphertext],
            &mut Transcript::new(b"bool_encryption"),
        )
    }

    /// Creates an [`EncryptedChoice`].
    ///
    /// # Panics
    ///
    /// Panics if `number_of_variants` is zero, or if `choice` is not in `0..number_of_variants`.
    pub fn encrypt_choice<R: CryptoRng + RngCore>(
        &self,
        number_of_variants: usize,
        choice: usize,
        rng: &mut R,
    ) -> EncryptedChoice<G> {
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
        let mut proof_builder = RingProofBuilder::new(self, &mut transcript, rng);

        let variants: Vec<_> = (0..number_of_variants)
            .map(|i| proof_builder.add_value(&admissible_values, (i == choice) as usize))
            .collect();
        let range_proofs = proof_builder.build();

        let mut sum_log = variants[0].random_scalar.clone();
        let mut sum_ciphertext = variants[0].inner;
        for variant in variants.iter().skip(1) {
            sum_log += variant.random_scalar.clone();
            sum_ciphertext += variant.inner;
        }

        let sum_proof = LogEqualityProof::new(
            self,
            &sum_log,
            (
                sum_ciphertext.random_element,
                sum_ciphertext.blinded_element - G::generator(),
            ),
            &mut Transcript::new(b"choice_encryption_sum"),
            rng,
        );

        EncryptedChoice {
            variants: variants.into_iter().map(|variant| variant.inner).collect(),
            range_proof: range_proofs,
            sum_proof,
        }
    }

    /// Verifies the zero-knowledge proofs in an [`EncryptedChoice`] and returns variant ciphertexts
    /// if they check out. Otherwise, returns `None`.
    pub fn verify_choice<'a>(&self, choice: &'a EncryptedChoice<G>) -> Option<&'a [Ciphertext<G>]> {
        // Some sanity checks.
        if choice.len() == 0 || choice.range_proof.total_rings_size() != 2 * choice.variants.len() {
            return None;
        }

        let mut sum_ciphertexts = choice.variants[0];
        for &variant in choice.variants.iter().skip(1) {
            sum_ciphertexts += variant;
        }

        let powers = (
            sum_ciphertexts.random_element,
            sum_ciphertexts.blinded_element - G::generator(),
        );
        if !choice
            .sum_proof
            .verify(self, powers, &mut Transcript::new(b"choice_encryption_sum"))
        {
            return None;
        }

        let admissible_values = [G::identity(), G::generator()];
        let admissible_values = vec![&admissible_values as &[_]; choice.variants.len()];
        if choice.range_proof.verify(
            self,
            &admissible_values,
            &choice.variants,
            &mut Transcript::new(b"encrypted_choice_ranges"),
        ) {
            Some(&choice.variants)
        } else {
            None
        }
    }
}

impl<G: Group> SecretKey<G> {
    /// Decrypts the provided ciphertext and returns the produced group element.
    ///
    /// As the ciphertext does not include a MAC or another way to assert integrity,
    /// this operation cannot fail. If the ciphertext is not produced properly (e.g., it targets
    /// another receiver), the returned group element will be garbage.
    pub fn decrypt_to_element(&self, encrypted: Ciphertext<G>) -> G::Element {
        let dh_element = encrypted.random_element * &self.0;
        encrypted.blinded_element - dh_element
    }

    /// Decrypts the provided ciphertext and returns the original encrypted value.
    ///
    /// `lookup_table` is used to find encrypted values based on the original decrypted
    /// group element. That is, it must contain all valid plaintext values. If the value
    /// is not in the table, this method will return `None`.
    pub fn decrypt(
        &self,
        encrypted: Ciphertext<G>,
        lookup_table: &DiscreteLogTable<G>,
    ) -> Option<u64> {
        lookup_table.get(&self.decrypt_to_element(encrypted))
    }
}

impl<G: Group> ops::Add for Ciphertext<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            random_element: self.random_element + rhs.random_element,
            blinded_element: self.blinded_element + rhs.blinded_element,
        }
    }
}

impl<G: Group> ops::AddAssign for Ciphertext<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<G: Group> ops::Sub for Ciphertext<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            random_element: self.random_element - rhs.random_element,
            blinded_element: self.blinded_element - rhs.blinded_element,
        }
    }
}

impl<G: Group> ops::SubAssign for Ciphertext<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for Ciphertext<G> {
    type Output = Self;

    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            random_element: self.random_element * rhs,
            blinded_element: self.blinded_element * rhs,
        }
    }
}

impl<G: Group> ops::Mul<u64> for Ciphertext<G> {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        let scalar = G::Scalar::from(rhs);
        self * &scalar
    }
}

/// Lookup table for discrete logarithms.
///
/// For [`Ciphertext`]s to be partially homomorphic, the encrypted values must be
/// group scalars linearly mapped to group elements: `x -> [x]G`, where `G` is the group
/// generator. After decryption it is necessary to map the decrypted group element back to a scalar
/// (i.e., get its discrete logarithm with base `G`). Because of discrete logarithm assumption,
/// this task is computationally infeasible in the general case; however, if the possible range
/// of encrypted values is small, it is possible to "cheat" by precomputing mapping `[x]G -> x`
/// for all allowed `x` ahead of time. This is exactly what `DiscreteLogTable` does.
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let ciphertexts = (0_u64..16)
///     .map(|i| receiver.public().encrypt(i, &mut rng));
/// // Assume that we know that the plaintext is in range 0..16,
/// // e.g., via a zero-knowledge proof.
/// let lookup_table = DiscreteLogTable::new(0..16);
/// // Then, we can use the lookup table to decrypt values.
/// // A single table may be shared for multiple decryption operations
/// // (i.e., it may be constructed ahead of time).
/// for (i, enc) in ciphertexts.enumerate() {
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

/// [`Ciphertext`] together with the random scalar used to create it.
#[derive(Debug, Clone)]
#[doc(hidden)] // only public for benchmarking
pub struct ExtendedCiphertext<G: Group> {
    pub inner: Ciphertext<G>,
    pub random_scalar: SecretKey<G>,
}

impl<G: Group> ExtendedCiphertext<G> {
    /// Creates a ciphertext of `value` for the specified `receiver`.
    pub fn new<R: CryptoRng + RngCore>(
        value: G::Element,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let dh_element = receiver.element * &random_scalar.0;
        let blinded_element = value + dh_element;

        Self {
            inner: Ciphertext {
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
/// The choice is represented as a vector of `n` *variant ciphertexts* of Boolean values (0 or 1),
/// where the chosen variant encrypts 1 and other variants encrypt 0.
/// This ensures that multiple [`EncryptedChoice`]s can be added (e.g., within a voting protocol).
/// These ciphertexts can be obtained via [`PublicKey::verify_choice()`].
///
/// Zero-knowledge proofs are:
///
/// - A [`RingProof`] attesting that all `n` ciphertexts encrypt 0 or 1.
///   This proof can be obtained via [`Self::range_proof()`].
/// - A [`LogEqualityProof`] attesting that the encrypted values sum up to 1. Combined with
///   the range proof, this means that exactly one of encrypted values is 1, and all others are 0.
///   This proof can be obtained via [`Self::sum_proof()`].
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, EncryptedChoice, Keypair};
/// # use rand::thread_rng;
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let choice = 2;
/// let enc = receiver.public().encrypt_choice(5, choice, &mut rng);
/// let variants = receiver.public().verify_choice(&enc).unwrap();
///
/// // `variants` is a slice of 5 Boolean value ciphertexts
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct EncryptedChoice<G: Group> {
    variants: Vec<Ciphertext<G>>,
    range_proof: RingProof<G>,
    sum_proof: LogEqualityProof<G>,
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group> EncryptedChoice<G> {
    /// Returns the number of variants in this choice.
    pub fn len(&self) -> usize {
        self.variants.len()
    }

    /// Returns variant ciphertexts **without** checking their validity.
    pub fn variants_unchecked(&self) -> &[Ciphertext<G>] {
        &self.variants
    }

    /// Returns the range proof for the variant ciphertexts.
    pub fn range_proof(&self) -> &RingProof<G> {
        &self.range_proof
    }

    /// Returns the sum proof for the variant ciphertexts.
    pub fn sum_proof(&self) -> &LogEqualityProof<G> {
        &self.sum_proof
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

        let mut choice = keypair.public().encrypt_choice(5, 2, &mut rng);
        let (encrypted_one, _) = keypair.public().encrypt_bool(true, &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(keypair.public().verify_choice(&choice).is_none());

        let mut choice = keypair.public().encrypt_choice(5, 4, &mut rng);
        let (encrypted_zero, _) = keypair.public().encrypt_bool(false, &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(keypair.public().verify_choice(&choice).is_none());

        let mut choice = keypair.public().encrypt_choice(5, 4, &mut rng);
        choice.variants[4].blinded_element =
            choice.variants[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.variants[3].blinded_element =
            choice.variants[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(keypair.public().verify_choice(&choice).is_none());
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
