//! Encrypted choice.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroizing;

use core::{fmt, iter, ops};

use crate::{
    encryption::ExtendedCiphertext, group::Group, Ciphertext, LogEqualityProof, PreparedRange,
    PublicKey, RangeProof, RingProof, RingProofBuilder, VerificationError,
};

/// Encapsulation of functionality for proving and verifying correctness of the sum of variant
/// ciphertexts in an [`EncryptedChoice`].
pub trait ProveSum<G: Group> {
    /// Produced / verified proofs.
    #[cfg(not(feature = "serde"))]
    type Proof: Sized;
    /// Produced / verified proofs.
    #[cfg(feature = "serde")]
    type Proof: Sized + Serialize + DeserializeOwned;

    #[doc(hidden)]
    fn prove<R: CryptoRng + RngCore>(
        &self,
        ciphertext: &ExtendedCiphertext<G>,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self::Proof;

    #[doc(hidden)]
    fn verify(
        &self,
        ciphertext: &Ciphertext<G>,
        proof: &Self::Proof,
        receiver: &PublicKey<G>,
    ) -> Result<(), ChoiceVerificationError>;
}

/// Single-choice polling.
#[derive(Debug)]
pub struct SingleChoice(());

impl<G: Group> ProveSum<G> for SingleChoice {
    type Proof = LogEqualityProof<G>;

    fn prove<R: CryptoRng + RngCore>(
        &self,
        ciphertext: &ExtendedCiphertext<G>,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self::Proof {
        LogEqualityProof::new(
            receiver,
            &ciphertext.random_scalar,
            (
                ciphertext.inner.random_element,
                ciphertext.inner.blinded_element - G::generator(),
            ),
            &mut Transcript::new(b"choice_encryption_sum"),
            rng,
        )
    }

    fn verify(
        &self,
        ciphertext: &Ciphertext<G>,
        proof: &Self::Proof,
        receiver: &PublicKey<G>,
    ) -> Result<(), ChoiceVerificationError> {
        let powers = (
            ciphertext.random_element,
            ciphertext.blinded_element - G::generator(),
        );
        proof
            .verify(
                receiver,
                powers,
                &mut Transcript::new(b"choice_encryption_sum"),
            )
            .map_err(ChoiceVerificationError::Sum)
    }
}

/// Multi-choice polling.
#[derive(Debug)]
pub struct MultiChoice(());

impl<G: Group> ProveSum<G> for MultiChoice {
    type Proof = ();

    fn prove<R: CryptoRng + RngCore>(
        &self,
        _ciphertext: &ExtendedCiphertext<G>,
        _receiver: &PublicKey<G>,
        _rng: &mut R,
    ) -> Self::Proof {
        // Do nothing.
    }

    fn verify(
        &self,
        _ciphertext: &Ciphertext<G>,
        _proof: &Self::Proof,
        _receiver: &PublicKey<G>,
    ) -> Result<(), ChoiceVerificationError> {
        Ok(()) // no failure conditions
    }
}

/// Multi-choice polling with an upper bound on the number of chosen variants.
#[derive(Debug)]
pub struct RestrictedMultiChoice<G: Group> {
    choices_range: PreparedRange<G>,
}

impl<G: Group> ProveSum<G> for RestrictedMultiChoice<G> {
    type Proof = RangeProof<G>;

    fn prove<R: CryptoRng + RngCore>(
        &self,
        _ciphertext: &ExtendedCiphertext<G>,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self::Proof {
        // FIXME: allow to pass in ciphertext when creating `RangeProof`
        RangeProof::new(
            receiver,
            &self.choices_range,
            0,
            &mut Transcript::new(b"choice_encryption_sum"),
            rng,
        )
        .1
    }

    fn verify(
        &self,
        ciphertext: &Ciphertext<G>,
        proof: &Self::Proof,
        receiver: &PublicKey<G>,
    ) -> Result<(), ChoiceVerificationError> {
        proof
            .verify(
                receiver,
                &self.choices_range,
                *ciphertext,
                &mut Transcript::new(b"choice_encryption_sum"),
            )
            .map_err(ChoiceVerificationError::Sum)
    }
}

/// Parameters of an [`EncryptedChoice`] polling.
#[derive(Debug)]
pub struct ChoiceParams<G: Group, S: ProveSum<G>> {
    variants_count: usize,
    sum_prover: S,
    receiver: PublicKey<G>,
}

impl<G: Group, S: ProveSum<G>> ChoiceParams<G, S> {
    fn check_variants_count(&self, actual_count: usize) -> Result<(), ChoiceVerificationError> {
        if self.variants_count == actual_count {
            Ok(())
        } else {
            Err(ChoiceVerificationError::VariantsLenMismatch {
                expected: self.variants_count,
                actual: actual_count,
            })
        }
    }
}

impl<G: Group> ChoiceParams<G, SingleChoice> {
    /// Creates parameters for a single-choice polling.
    ///
    /// # Panics
    ///
    /// Panics if provided `variants_count` is zero.
    pub fn single(receiver: PublicKey<G>, variants_count: usize) -> Self {
        assert!(variants_count > 0, "Number of variants must be positive");
        Self {
            variants_count,
            sum_prover: SingleChoice(()),
            receiver,
        }
    }
}

impl<G: Group> ChoiceParams<G, MultiChoice> {
    /// Creates parameters for a multi-choice polling.
    ///
    /// # Panics
    ///
    /// Panics if provided `variants_count` is zero.
    pub fn multi(receiver: PublicKey<G>, variants_count: usize) -> Self {
        assert!(variants_count > 0, "Number of variants must be positive");
        Self {
            variants_count,
            sum_prover: MultiChoice(()),
            receiver,
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
pub struct EncryptedChoice<G: Group, S: ProveSum<G>> {
    variants: Vec<Ciphertext<G>>,
    range_proof: RingProof<G>,
    sum_proof: S::Proof,
}

impl<G: Group> EncryptedChoice<G, SingleChoice> {
    /// Creates a new encrypted choice.
    ///
    /// # Panics
    ///
    /// Panics if `choice` exceeds the maximum index allowed by `params`.
    pub fn single<R: CryptoRng + RngCore>(
        choice: usize,
        params: &ChoiceParams<G, SingleChoice>,
        rng: &mut R,
    ) -> Self {
        assert!(
            choice < params.variants_count,
            "invalid choice {}; expected a value in 0..{}",
            choice,
            params.variants_count
        );
        let choices = Zeroizing::new(
            (0..params.variants_count)
                .map(|i| choice == i)
                .collect::<Vec<_>>(),
        );
        Self::new(&choices, params, rng)
    }
}

impl<G: Group> EncryptedChoice<G, RestrictedMultiChoice<G>> {
    /// Creates an encrypted multi-choice.
    ///
    /// # Panics
    ///
    /// Panics if the length of `choices` differs from the number of variants in `params`.
    pub fn multi<R: CryptoRng + RngCore>(
        choices: &[bool],
        params: &ChoiceParams<G, RestrictedMultiChoice<G>>,
        rng: &mut R,
    ) -> Self {
        // number of `choices` is verified in `Self::new()`.
        Self::new(choices, params, rng)
    }
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group, S: ProveSum<G>> EncryptedChoice<G, S> {
    fn new<R: CryptoRng + RngCore>(
        choices: &[bool],
        params: &ChoiceParams<G, S>,
        rng: &mut R,
    ) -> Self {
        assert!(!choices.is_empty(), "No choices provided");
        assert_eq!(
            choices.len(),
            params.variants_count,
            "Mismatch between expected and actual number of choices"
        );

        let admissible_values = [G::identity(), G::generator()];
        let mut ring_responses = vec![G::Scalar::default(); 2 * params.variants_count];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(
            &params.receiver,
            params.variants_count,
            &mut ring_responses,
            &mut transcript,
            rng,
        );

        let variants: Vec<_> = choices
            .iter()
            .map(|&flag| proof_builder.add_value(&admissible_values, flag as usize))
            .collect();
        let range_proof = RingProof::new(proof_builder.build(), ring_responses);

        let sum_ciphertext = variants.iter().cloned().reduce(ops::Add::add).unwrap();
        let sum_proof = params
            .sum_prover
            .prove(&sum_ciphertext, &params.receiver, rng);
        Self {
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
        params: &ChoiceParams<G, S>,
    ) -> Result<&[Ciphertext<G>], ChoiceVerificationError> {
        params.check_variants_count(self.len())?;
        let sum_of_ciphertexts = self.variants.iter().copied().reduce(ops::Add::add);
        let sum_of_ciphertexts = sum_of_ciphertexts.ok_or(ChoiceVerificationError::Empty)?;
        params
            .sum_prover
            .verify(&sum_of_ciphertexts, &self.sum_proof, &params.receiver)?;

        let admissible_values = [G::identity(), G::generator()];
        self.range_proof
            .verify(
                &params.receiver,
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
    pub fn sum_proof(&self) -> &S::Proof {
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
    /// Mismatch between expected and actual number of variants in the proof.
    VariantsLenMismatch {
        /// Expected number of variants.
        expected: usize,
        /// Actual number of variants.
        actual: usize,
    },
    /// Error verifying [`EncryptedChoice::sum_proof()`].
    Sum(VerificationError),
    /// Error verifying [`EncryptedChoice::range_proof()`].
    Range(VerificationError),
    /// Sum proof is absent when it must be present.
    NoSumProof,
    /// Sum proof is present when it must be absent.
    UnexpectedSumProof,
}

impl fmt::Display for ChoiceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("encrypted choice does not have variants"),
            Self::VariantsLenMismatch { expected, actual } => write!(
                formatter,
                "number of variants ({act}) differs from expected ({exp})",
                act = actual,
                exp = expected
            ),
            Self::Sum(err) => write!(formatter, "cannot verify sum proof: {}", err),
            Self::Range(err) => write!(formatter, "cannot verify range proofs: {}", err),
            Self::NoSumProof => formatter.write_str("sum proof is unexpectedly absent"),
            Self::UnexpectedSumProof => formatter.write_str("sum proof is unexpectedly present"),
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
        let params = ChoiceParams::single(receiver.clone(), 5);

        let mut choice = EncryptedChoice::single(2, &params, &mut rng);
        let (encrypted_one, _) = receiver.encrypt_bool(true, &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(choice.verify(&params).is_err());

        let mut choice = EncryptedChoice::single(4, &params, &mut rng);
        let (encrypted_zero, _) = receiver.encrypt_bool(false, &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(choice.verify(&params).is_err());

        let mut choice = EncryptedChoice::single(4, &params, &mut rng);
        choice.variants[4].blinded_element =
            choice.variants[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.variants[3].blinded_element =
            choice.variants[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(choice.verify(&params).is_err());
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
