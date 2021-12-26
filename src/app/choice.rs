//! Encrypted choice.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::{fmt, iter, ops};

use crate::{
    group::Group, Ciphertext, LogEqualityProof, PublicKey, RingProof, RingProofBuilder,
    VerificationError,
};

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
/// # use elastic_elgamal::{app::EncryptedChoice, group::Ristretto, DiscreteLogTable, Keypair};
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let choice = 2;
/// let enc = EncryptedChoice::new(5, choice, receiver.public(), &mut rng);
/// let variants = enc.verify(receiver.public())?;
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
/// # Ok(())
/// # }
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
    /// Creates a new encryptec choice.
    ///
    /// # Panics
    ///
    /// Panics if `number_of_variants` is zero, or if `choice` is not in `0..number_of_variants`.
    ///
    /// # Examples
    ///
    /// See [`EncryptedChoice`] docs for an example of usage.
    pub fn new<R: CryptoRng + RngCore>(
        number_of_variants: usize,
        choice: usize,
        receiver: &PublicKey<G>,
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
        let mut ring_responses = vec![G::Scalar::default(); 2 * number_of_variants];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(
            receiver,
            number_of_variants,
            &mut ring_responses,
            &mut transcript,
            rng,
        );

        let variants: Vec<_> = (0..number_of_variants)
            .map(|i| proof_builder.add_value(&admissible_values, (i == choice) as usize))
            .collect();
        let range_proof = RingProof::new(proof_builder.build(), ring_responses);

        let mut sum_log = variants[0].random_scalar.clone();
        let mut sum_ciphertext = variants[0].inner;
        for variant in variants.iter().skip(1) {
            sum_log += variant.random_scalar.clone();
            sum_ciphertext += variant.inner;
        }

        let sum_proof = LogEqualityProof::new(
            receiver,
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
            range_proof,
            sum_proof,
        }
    }

    /// Verifies the zero-knowledge proofs in an [`EncryptedChoice`] and returns variant ciphertexts
    /// if they check out.
    ///
    /// # Errors
    ///
    /// Returns an error if the `choice` is malformed or its proofs fail verification.
    pub fn verify(
        &self,
        receiver: &PublicKey<G>,
    ) -> Result<&[Ciphertext<G>], ChoiceVerificationError> {
        let sum_ciphertexts = self.variants.iter().copied().reduce(ops::Add::add);
        let sum_ciphertexts = sum_ciphertexts.ok_or(ChoiceVerificationError::Empty)?;

        let powers = (
            sum_ciphertexts.random_element,
            sum_ciphertexts.blinded_element - G::generator(),
        );
        self.sum_proof
            .verify(
                receiver,
                powers,
                &mut Transcript::new(b"choice_encryption_sum"),
            )
            .map_err(ChoiceVerificationError::Sum)?;

        let admissible_values = [G::identity(), G::generator()];
        self.range_proof
            .verify(
                receiver,
                iter::repeat(&admissible_values as &[_]).take(self.variants.len()),
                self.variants.iter().copied(),
                &mut Transcript::new(b"encrypted_choice_ranges"),
            )
            .map(|()| self.variants.as_slice())
            .map_err(ChoiceVerificationError::Range)
    }

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

/// Error verifying an [`EncryptedChoice`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ChoiceVerificationError {
    /// [`EncryptedChoice`] does not have variants.
    ///
    /// This error means that the `EncryptedChoice` is malformed (e.g., after deserializing it
    /// from an untrusted source).
    Empty,
    /// Error verifying [`EncryptedChoice::sum_proof()`].
    Sum(VerificationError),
    /// Error verifying [`EncryptedChoice::range_proof()`].
    Range(VerificationError),
}

impl fmt::Display for ChoiceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("encrypted choice does not have variants"),
            Self::Sum(err) => write!(formatter, "cannot verify sum proof: {}", err),
            Self::Range(err) => write!(formatter, "cannot verify range proofs: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChoiceVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sum(err) | Self::Range(err) => Some(err),
            _ => None,
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
        let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();

        let mut choice = EncryptedChoice::new(5, 2, &receiver, &mut rng);
        let (encrypted_one, _) = receiver.encrypt_bool(true, &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(choice.verify(&receiver).is_err());

        let mut choice = EncryptedChoice::new(5, 4, &receiver, &mut rng);
        let (encrypted_zero, _) = receiver.encrypt_bool(false, &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(choice.verify(&receiver).is_err());

        let mut choice = EncryptedChoice::new(5, 4, &receiver, &mut rng);
        choice.variants[4].blinded_element =
            choice.variants[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.variants[3].blinded_element =
            choice.variants[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(choice.verify(&receiver).is_err());
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
