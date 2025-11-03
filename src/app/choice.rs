//! Encrypted choice.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::Zeroizing;

use core::{fmt, iter, ops};

use crate::{
    alloc::{vec, Vec},
    group::Group,
    Ciphertext, CiphertextWithValue, LogEqualityProof, PublicKey, RingProof, RingProofBuilder,
    VerificationError,
};

/// Encapsulation of functionality for proving and verifying correctness of the sum of option
/// ciphertexts in an [`EncryptedChoice`].
///
/// This trait is not meant to be implemented for external types.
pub trait ProveSum<G: Group>: Clone + crate::sealed::Sealed {
    /// Produced / verified proofs.
    #[cfg(not(feature = "serde"))]
    type Proof: Sized;
    /// Produced / verified proofs.
    #[cfg(feature = "serde")]
    type Proof: Sized + Serialize + DeserializeOwned;

    #[doc(hidden)]
    fn prove<R: CryptoRng + RngCore>(
        &self,
        ciphertext: &CiphertextWithValue<G, u64>,
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

/// Single-choice setup for [`EncryptedChoice`], in which it can contain a single selected option.
///
/// # Examples
///
/// See [`EncryptedChoice`] docs for an example of usage.
#[derive(Debug, Clone, Copy)]
pub struct SingleChoice(());

impl crate::sealed::Sealed for SingleChoice {}

impl<G: Group> ProveSum<G> for SingleChoice {
    type Proof = LogEqualityProof<G>;

    fn prove<R: CryptoRng + RngCore>(
        &self,
        ciphertext: &CiphertextWithValue<G, u64>,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self::Proof {
        LogEqualityProof::new(
            receiver,
            ciphertext.randomness(),
            (
                ciphertext.inner().random_element,
                ciphertext.inner().blinded_element - G::generator(),
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

/// Multi-choice setup for [`EncryptedChoice`], in which it can contain any possible number
/// of selected options (`0..=n`, where `n` is the number of options).
///
/// # Examples
///
/// See [`EncryptedChoice`] docs for an example of usage.
#[derive(Debug, Clone, Copy)]
pub struct MultiChoice(());

impl crate::sealed::Sealed for MultiChoice {}

impl<G: Group> ProveSum<G> for MultiChoice {
    type Proof = ();

    fn prove<R: CryptoRng + RngCore>(
        &self,
        _ciphertext: &CiphertextWithValue<G, u64>,
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

/// Parameters of an [`EncryptedChoice`] polling.
#[derive(Debug)]
pub struct ChoiceParams<G: Group, S: ProveSum<G>> {
    options_count: usize,
    sum_prover: S,
    receiver: PublicKey<G>,
}

impl<G: Group, S: ProveSum<G>> Clone for ChoiceParams<G, S> {
    fn clone(&self) -> Self {
        Self {
            options_count: self.options_count,
            sum_prover: self.sum_prover.clone(),
            receiver: self.receiver.clone(),
        }
    }
}

impl<G: Group, S: ProveSum<G>> ChoiceParams<G, S> {
    fn check_options_count(&self, actual_count: usize) -> Result<(), ChoiceVerificationError> {
        if self.options_count == actual_count {
            Ok(())
        } else {
            Err(ChoiceVerificationError::OptionsLenMismatch {
                expected: self.options_count,
                actual: actual_count,
            })
        }
    }

    /// Returns the public key for which the [`EncryptedChoice`] are encrypted.
    pub fn receiver(&self) -> &PublicKey<G> {
        &self.receiver
    }

    /// Returns the number of options in these parameters.
    pub fn options_count(&self) -> usize {
        self.options_count
    }
}

impl<G: Group> ChoiceParams<G, SingleChoice> {
    /// Creates parameters for a single-choice polling.
    ///
    /// # Panics
    ///
    /// Panics if provided `options_count` is zero.
    pub fn single(receiver: PublicKey<G>, options_count: usize) -> Self {
        assert!(options_count > 0, "Number of options must be positive");
        Self {
            options_count,
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
    /// Panics if provided `options_count` is zero.
    pub fn multi(receiver: PublicKey<G>, options_count: usize) -> Self {
        assert!(options_count > 0, "Number of options must be positive");
        Self {
            options_count,
            sum_prover: MultiChoice(()),
            receiver,
        }
    }
}

/// Zero or more encrypted choices from `n` options (`n >= 1`) together with zero-knowledge
/// proofs of correctness.
///
/// # Construction
///
/// The choice is represented as a vector of `n` *choice ciphertexts* of Boolean values (0 or 1),
/// where the ciphertexts for the chosen options encrypt 1 and the other ciphertexts encrypt 0.
/// This ensures that multiple [`EncryptedChoice`]s can be added (e.g., within a voting protocol).
///
/// Zero-knowledge proofs are:
///
/// - A [`RingProof`] attesting that all `n` ciphertexts encrypt 0 or 1.
///   This proof can be obtained via [`Self::range_proof()`].
/// - A [`LogEqualityProof`] attesting that the encrypted values sum up to 1. Combined with
///   the range proof, this means that exactly one of encrypted values is 1, and all others are 0.
///   This proof can be obtained via [`Self::sum_proof()`]. This proof is absent for
///   a [`MultiChoice`] setup (`sum_proof()` just returns `()`).
///
/// # Examples
///
/// ## Single-choice setup
///
/// ```
/// # use elastic_elgamal::{
/// #     app::{ChoiceParams, EncryptedChoice}, group::Ristretto, DiscreteLogTable, Keypair,
/// # };
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::rng();
/// let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
/// let choice_params = ChoiceParams::single(pk, 5);
///
/// let choice = 2;
/// let enc = EncryptedChoice::single(&choice_params, choice, &mut rng);
/// let choices = enc.verify(&choice_params)?;
///
/// // `choices` is a slice of 5 Boolean value ciphertexts
/// assert_eq!(choices.len(), 5);
/// let lookup_table = DiscreteLogTable::new(0..=1);
/// for (idx, &v) in choices.iter().enumerate() {
///     assert_eq!(
///         sk.decrypt(v, &lookup_table),
///         Some((idx == choice) as u64)
///     );
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Multi-choice setup
///
/// ```
/// # use elastic_elgamal::{
/// #     app::{ChoiceParams, EncryptedChoice}, group::Ristretto, DiscreteLogTable, Keypair,
/// # };
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::rng();
/// let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
/// let choice_params = ChoiceParams::multi(pk, 5);
///
/// let choices = [true, false, true, true, false];
/// let enc = EncryptedChoice::new(&choice_params, &choices, &mut rng);
/// let recovered_choices = enc.verify(&choice_params)?;
///
/// let lookup_table = DiscreteLogTable::new(0..=1);
/// for (idx, &v) in recovered_choices.iter().enumerate() {
///     assert_eq!(sk.decrypt(v, &lookup_table), Some(choices[idx] as u64));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct EncryptedChoice<G: Group, S: ProveSum<G>> {
    choices: Vec<Ciphertext<G>>,
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
        params: &ChoiceParams<G, SingleChoice>,
        choice: usize,
        rng: &mut R,
    ) -> Self {
        assert!(
            choice < params.options_count,
            "invalid choice {choice}; expected a value in 0..{}",
            params.options_count
        );
        let choices: Vec<_> = (0..params.options_count).map(|i| choice == i).collect();
        Self::new(params, &Zeroizing::new(choices), rng)
    }
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group, S: ProveSum<G>> EncryptedChoice<G, S> {
    /// Creates an encrypted multi-choice.
    ///
    /// For a [`SingleChoice`] polling, it is caller's responsibility to ensure that `choices`
    /// contains exactly one `true` value; otherwise, the produced proof will not verify.
    ///
    /// # Panics
    ///
    /// Panics if the length of `choices` differs from the number of options specified in `params`.
    pub fn new<R: CryptoRng + RngCore>(
        params: &ChoiceParams<G, S>,
        choices: &[bool],
        rng: &mut R,
    ) -> Self {
        assert!(!choices.is_empty(), "No choices provided");
        assert_eq!(
            choices.len(),
            params.options_count,
            "Mismatch between expected and actual number of choices"
        );

        let admissible_values = [G::identity(), G::generator()];
        let mut ring_responses = vec![G::Scalar::default(); 2 * params.options_count];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(
            &params.receiver,
            params.options_count,
            &mut ring_responses,
            &mut transcript,
            rng,
        );

        let sum = choices.iter().map(|&flag| u64::from(flag)).sum::<u64>();
        let choices: Vec<_> = choices
            .iter()
            .map(|&flag| proof_builder.add_value(&admissible_values, usize::from(flag)))
            .collect();
        let range_proof = RingProof::new(proof_builder.build(), ring_responses);

        let sum_ciphertext = choices.iter().cloned().reduce(ops::Add::add).unwrap();
        let sum_ciphertext = sum_ciphertext.with_value(sum);
        let sum_proof = params
            .sum_prover
            .prove(&sum_ciphertext, &params.receiver, rng);
        Self {
            choices: choices.into_iter().map(|choice| choice.inner).collect(),
            range_proof,
            sum_proof,
        }
    }

    /// Verifies the zero-knowledge proofs in this choice and returns Boolean ciphertexts
    /// for all options.
    ///
    /// # Errors
    ///
    /// Returns an error if the `choice` is malformed or its proofs fail verification.
    #[allow(clippy::missing_panics_doc)]
    pub fn verify(
        &self,
        params: &ChoiceParams<G, S>,
    ) -> Result<&[Ciphertext<G>], ChoiceVerificationError> {
        params.check_options_count(self.choices.len())?;
        let sum_of_ciphertexts = self.choices.iter().copied().reduce(ops::Add::add);
        let sum_of_ciphertexts = sum_of_ciphertexts.unwrap();
        // ^ `unwrap()` is safe; `params` cannot have 0 options by construction
        params
            .sum_prover
            .verify(&sum_of_ciphertexts, &self.sum_proof, &params.receiver)?;

        let admissible_values = [G::identity(), G::generator()];
        self.range_proof
            .verify(
                &params.receiver,
                iter::repeat_n(&admissible_values as &[_], self.choices.len()),
                self.choices.iter().copied(),
                &mut Transcript::new(b"encrypted_choice_ranges"),
            )
            .map(|()| self.choices.as_slice())
            .map_err(ChoiceVerificationError::Range)
    }

    /// Returns the number of encrypted choices. This value is equal to
    /// [`ChoiceParams::options_count()`] with which the encryption was created.
    pub fn len(&self) -> usize {
        self.choices.len()
    }

    /// Returns ciphertexts for all options **without** checking the validity of this choice.
    pub fn choices_unchecked(&self) -> &[Ciphertext<G>] {
        &self.choices
    }

    /// Returns the range proof for the choice ciphertexts.
    pub fn range_proof(&self) -> &RingProof<G> {
        &self.range_proof
    }

    /// Returns the sum proof for the choice ciphertexts.
    pub fn sum_proof(&self) -> &S::Proof {
        &self.sum_proof
    }
}

/// Error verifying an [`EncryptedChoice`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ChoiceVerificationError {
    /// Mismatch between expected and actual number of options in the `EncryptedChoice`.
    OptionsLenMismatch {
        /// Expected number of options.
        expected: usize,
        /// Actual number of options.
        actual: usize,
    },
    /// Error verifying [`EncryptedChoice::sum_proof()`].
    Sum(VerificationError),
    /// Error verifying [`EncryptedChoice::range_proof()`].
    Range(VerificationError),
}

impl fmt::Display for ChoiceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptionsLenMismatch { expected, actual } => write!(
                formatter,
                "number of options in the ballot ({actual}) differs from expected ({expected})",
            ),
            Self::Sum(err) => write!(formatter, "cannot verify sum proof: {err}"),
            Self::Range(err) => write!(formatter, "cannot verify range proofs: {err}"),
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
    use super::*;
    use crate::{
        group::{Generic, Ristretto},
        Keypair,
    };

    fn test_bogus_encrypted_choice_does_not_work<G: Group>() {
        let mut rng = rand::rng();
        let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();
        let params = ChoiceParams::single(receiver.clone(), 5);

        let mut choice = EncryptedChoice::single(&params, 2, &mut rng);
        let (encrypted_one, _) = receiver.encrypt_bool(true, &mut rng);
        choice.choices[0] = encrypted_one;
        assert!(choice.verify(&params).is_err());

        let mut choice = EncryptedChoice::single(&params, 4, &mut rng);
        let (encrypted_zero, _) = receiver.encrypt_bool(false, &mut rng);
        choice.choices[4] = encrypted_zero;
        assert!(choice.verify(&params).is_err());

        let mut choice = EncryptedChoice::single(&params, 4, &mut rng);
        choice.choices[4].blinded_element =
            choice.choices[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.choices[3].blinded_element =
            choice.choices[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 choices should no longer verify.
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
