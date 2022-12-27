//! Quadratic voting application.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::fmt;

use crate::{
    alloc::Vec, group::Group, Ciphertext, PreparedRange, PublicKey, RangeDecomposition, RangeProof,
    SumOfSquaresProof, VerificationError,
};

/// [Quadratic voting] parameters prepared for a certain [`Group`].
///
/// The parameters are:
///
/// - [Receiver key](Self::receiver()) using which votes in [`QuadraticVotingBallot`]s
///   are encrypted
/// - [Number of options](Self::options_count()) in the ballot
/// - [Number of credits](Self::credits()) per ballot
/// - [Maximum number of votes](Self::max_votes()) per option
///
/// See [`QuadraticVotingBallot`] for a detailed description of parameters.
///
/// [Quadratic voting]: https://en.wikipedia.org/wiki/Quadratic_voting
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{app::QuadraticVotingParams, group::Ristretto, Keypair};
/// # use rand::thread_rng;
/// let (receiver, _) = Keypair::<Ristretto>::generate(&mut thread_rng())
///     .into_tuple();
/// let mut params = QuadraticVotingParams::new(receiver, 5, 20);
/// // 5 options, 20 credits.
/// assert_eq!(params.options_count(), 5);
/// assert_eq!(params.credits(), 20);
/// // By default, max votes per option are determined based on credits
/// assert_eq!(params.max_votes(), 4); // 4 < sqrt(20) < 5
///
/// // It is possible to reduce max votes per ballot.
/// params.set_max_votes(3);
/// assert_eq!(params.max_votes(), 3);
/// ```
#[derive(Debug, Clone)]
pub struct QuadraticVotingParams<G: Group> {
    vote_count_range: PreparedRange<G>,
    credit_range: PreparedRange<G>,
    options_count: usize,
    receiver: PublicKey<G>,
}

impl<G: Group> QuadraticVotingParams<G> {
    /// Creates new parameters for the specified number of `credits` allocated per voter.
    ///
    /// The maximum number of votes per option is automatically set as `floor(sqrt(credits))`;
    /// it can be changed via [`Self::set_max_votes()`].
    ///
    /// # Panics
    ///
    /// Panics if the number of options or credits is zero.
    pub fn new(receiver: PublicKey<G>, options: usize, credits: u64) -> Self {
        assert!(options > 0, "Number of options must be positive");
        assert!(credits > 0, "Number of credits must be positive");

        let max_votes = isqrt(credits);
        let vote_count_range = RangeDecomposition::optimal(max_votes + 1);
        let credit_range = RangeDecomposition::optimal(credits + 1);
        Self {
            vote_count_range: vote_count_range.into(),
            credit_range: credit_range.into(),
            options_count: options,
            receiver,
        }
    }

    /// Returns the public key for which the [`QuadraticVotingBallot`]s are encrypted.
    pub fn receiver(&self) -> &PublicKey<G> {
        &self.receiver
    }

    /// Returns the number of options.
    pub fn options_count(&self) -> usize {
        self.options_count
    }

    /// Returns the number of credits per ballot.
    pub fn credits(&self) -> u64 {
        self.credit_range.decomposition().upper_bound() - 1
    }

    /// Returns the maximum number of votes per option.
    pub fn max_votes(&self) -> u64 {
        self.vote_count_range.decomposition().upper_bound() - 1
    }

    /// Sets the maximum number of votes per option.
    ///
    /// # Panics
    ///
    /// Panics if `max_votes * max_votes` exceeds `credits`; in this case, this number of votes
    /// cannot be cast for a single option.
    pub fn set_max_votes(&mut self, max_votes: u64) {
        assert!(
            max_votes * max_votes <= self.credits(),
            "Vote bound {max_votes} is too large; its square is greater than credit bound {}",
            self.credits()
        );
        self.vote_count_range = RangeDecomposition::optimal(max_votes + 1).into();
    }

    fn check_options_count(&self, actual_count: usize) -> Result<(), QuadraticVotingError> {
        if self.options_count == actual_count {
            Ok(())
        } else {
            Err(QuadraticVotingError::OptionsLenMismatch {
                expected: self.options_count,
                actual: actual_count,
            })
        }
    }
}

/// Integer square root of a `u64` number. Uses the digit-by-digit calculation method in base 2;
/// see https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Binary_numeral_system_(base_2)
fn isqrt(mut x: u64) -> u64 {
    let mut root = 0_u64;
    let mut power_of_4 = 1_u64 << 62;
    while power_of_4 > x {
        power_of_4 /= 4;
    }
    while power_of_4 > 0 {
        if x >= root + power_of_4 {
            x -= root + power_of_4;
            root = root / 2 + power_of_4;
        } else {
            root /= 2;
        }
        power_of_4 /= 4;
    }
    root
}

/// Encrypted ballot for [quadratic voting] together with zero-knowledge proofs of correctness.
///
/// # Overview
///
/// Quadratic voting assumes a non-exclusive selection among `n >= 1` predefined options.
/// Unlike with [`MultiChoice`](crate::app::MultiChoice) polling, a voter can cast more than
/// one vote for a single option. The additional votes come at a quadratic expense for the voter,
/// however. For example, to cast 4 votes for a certain option, a voter needs 16 credits,
/// while single votes for 4 different options are worth 4 credits.
///
/// The `QuadraticVotingBallot` construction assumes that there is a known number of credits
/// for each ballot (e.g., it is uniform across all eligible voters), and that votes are tallied
/// by a tallier or a federation of talliers that jointly control a [`SecretKey`](crate::SecretKey).
/// As such, the ballot is represented as follows:
///
/// - ElGamal [`Ciphertext`] for each of `n` options (can be summed across all valid ballots
///   to get vote totals that will be decrypted by the talliers)
/// - [`RangeProof`] for each of these ciphertexts proving that the encrypted value
///   is in range `0..=V`
/// - [`Ciphertext`] for the number of credits used by the ballot, and a [`RangeProof`]
///   that it is in range `0..=C`
/// - Zero-knowledge [`SumOfSquaresProof`] proving that the encrypted number of credits is computed
///   correctly, i.e., as a sum of squares of the values encrypted in the vote ciphertexts.
///
/// Here, `C` (the number of credits) and `V` (max votes per option) are the protocol parameters
/// encapsulated in [`QuadraticVotingParams`].
///
/// [quadratic voting]: https://en.wikipedia.org/wiki/Quadratic_voting
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{
/// #     app::{QuadraticVotingParams, QuadraticVotingBallot}, group::Ristretto, Keypair,
/// #     DiscreteLogTable,
/// # };
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = thread_rng();
/// let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
/// let params = QuadraticVotingParams::new(pk, 5, 20);
/// // 5 options, 20 credits (= 4 max votes per option)
/// assert_eq!(params.max_votes(), 4);
///
/// let votes = [4, 0, 0, 1, 1];
/// let ballot = QuadraticVotingBallot::new(&params, &votes, &mut rng);
/// let encrypted: Vec<_> = ballot.verify(&params)?.collect();
///
/// assert_eq!(encrypted.len(), 5);
/// let lookup = DiscreteLogTable::new(0..=params.max_votes());
/// let decrypted: Vec<_> = encrypted
///     .into_iter()
///     .map(|vote| sk.decrypt(vote, &lookup).unwrap())
///     .collect();
/// assert_eq!(decrypted, votes);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct QuadraticVotingBallot<G: Group> {
    votes: Vec<CiphertextWithRangeProof<G>>,
    credit: CiphertextWithRangeProof<G>,
    credit_equivalence_proof: SumOfSquaresProof<G>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
struct CiphertextWithRangeProof<G: Group> {
    ciphertext: Ciphertext<G>,
    range_proof: RangeProof<G>,
}

impl<G: Group> CiphertextWithRangeProof<G> {
    fn new(ciphertext: Ciphertext<G>, range_proof: RangeProof<G>) -> Self {
        Self {
            ciphertext,
            range_proof,
        }
    }
}

impl<G: Group> QuadraticVotingBallot<G> {
    /// Creates a ballot based on the provided parameters and voter's `votes`.
    ///
    /// # Panics
    ///
    /// Panics if the length of `votes` differs from the number of options in `params`.
    pub fn new<R: CryptoRng + RngCore>(
        params: &QuadraticVotingParams<G>,
        votes: &[u64],
        rng: &mut R,
    ) -> Self {
        assert_eq!(
            votes.len(),
            params.options_count,
            "Mismatch between expected and actual number of choices"
        );
        let credit = votes.iter().map(|&x| x * x).sum::<u64>();

        let votes: Vec<_> = votes
            .iter()
            .map(|&vote_count| {
                let (ciphertext, proof) = RangeProof::new(
                    &params.receiver,
                    &params.vote_count_range,
                    vote_count,
                    &mut Transcript::new(b"quadratic_voting_variant"),
                    rng,
                );
                (ciphertext.generalize(), proof)
            })
            .collect();
        let (credit, credit_range_proof) = RangeProof::new(
            &params.receiver,
            &params.credit_range,
            credit,
            &mut Transcript::new(b"quadratic_voting_credit_range"),
            rng,
        );
        let credit = credit.generalize();

        let credit_equivalence_proof = SumOfSquaresProof::new(
            votes.iter().map(|(ciphertext, _)| ciphertext),
            &credit,
            &params.receiver,
            &mut Transcript::new(b"quadratic_voting_credit_equiv"),
            rng,
        );

        Self {
            votes: votes
                .into_iter()
                .map(|(ciphertext, proof)| CiphertextWithRangeProof::new(ciphertext.into(), proof))
                .collect(),
            credit: CiphertextWithRangeProof::new(credit.into(), credit_range_proof),
            credit_equivalence_proof,
        }
    }

    /// Verifies this ballot against the provided parameters.
    ///
    /// # Errors
    ///
    /// - Returns an error if verification fails.
    pub fn verify(
        &self,
        params: &QuadraticVotingParams<G>,
    ) -> Result<impl Iterator<Item = Ciphertext<G>> + '_, QuadraticVotingError> {
        params.check_options_count(self.votes.len())?;

        for (i, vote_count) in self.votes.iter().enumerate() {
            vote_count
                .range_proof
                .verify(
                    &params.receiver,
                    &params.vote_count_range,
                    vote_count.ciphertext,
                    &mut Transcript::new(b"quadratic_voting_variant"),
                )
                .map_err(|error| QuadraticVotingError::Variant { index: i, error })?;
        }

        self.credit
            .range_proof
            .verify(
                &params.receiver,
                &params.credit_range,
                self.credit.ciphertext,
                &mut Transcript::new(b"quadratic_voting_credit_range"),
            )
            .map_err(QuadraticVotingError::CreditRange)?;

        self.credit_equivalence_proof
            .verify(
                self.votes.iter().map(|c| &c.ciphertext),
                &self.credit.ciphertext,
                &params.receiver,
                &mut Transcript::new(b"quadratic_voting_credit_equiv"),
            )
            .map_err(QuadraticVotingError::CreditEquivalence)?;

        Ok(self.votes.iter().map(|c| c.ciphertext))
    }
}

/// Errors that can occur when verifying [`QuadraticVotingBallot`]s.
#[derive(Debug)]
#[non_exhaustive]
pub enum QuadraticVotingError {
    /// Error verifying a [`RangeProof`] for a vote for a particular option.
    Variant {
        /// Zero-based option index.
        index: usize,
        /// Error that occurred during range proof verification.
        error: VerificationError,
    },
    /// Error verifying a [`RangeProof`] for credits.
    CreditRange(VerificationError),
    /// Error verifying the [proof of equivalence](SumOfSquaresProof) for credits.
    CreditEquivalence(VerificationError),
    /// Mismatch between expected and actual number of options in the ballot.
    OptionsLenMismatch {
        /// Expected number of options.
        expected: usize,
        /// Actual number of options.
        actual: usize,
    },
}

impl fmt::Display for QuadraticVotingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Variant { index, error } => {
                write!(
                    formatter,
                    "error verifying range proof for option #{}: {error}",
                    *index + 1
                )
            }
            Self::CreditRange(err) => {
                write!(formatter, "error verifying range proof for credits: {err}")
            }
            Self::CreditEquivalence(err) => {
                write!(formatter, "error verifying credit equivalence proof: {err}")
            }
            Self::OptionsLenMismatch { expected, actual } => write!(
                formatter,
                "number of options in the ballot ({actual}) differs from expected ({expected})"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for QuadraticVotingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Variant { error, .. }
            | Self::CreditRange(error)
            | Self::CreditEquivalence(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        group::{ElementOps, Ristretto},
        DiscreteLogTable, Keypair,
    };

    use rand::thread_rng;

    #[test]
    fn isqrt_is_correct() {
        let samples = (0..1_000).chain((0..1_000).map(|x| x * 1_000)).chain([
            u64::MAX,
            u64::MAX - 1,
            1 << 63,
            1 << 62,
            (1 << 62) - 1,
        ]);
        for sample in samples {
            let sqrt = isqrt(sample);
            assert!(sqrt * sqrt <= sample, "sqrt({sample}) ?= {sqrt}");

            let next_square = (sqrt + 1).checked_mul(sqrt + 1);
            assert!(
                next_square.map_or(true, |sq| sq > sample),
                "sqrt({sample}) ?= {sqrt}"
            );
        }
    }

    #[test]
    fn quadratic_voting() {
        let mut rng = thread_rng();
        let (pk, sk) = Keypair::generate(&mut rng).into_tuple();
        let params = QuadraticVotingParams::<Ristretto>::new(pk, 5, 25);
        let ballot = QuadraticVotingBallot::new(&params, &[1, 3, 0, 3, 2], &mut rng);

        let choices = ballot.verify(&params).unwrap();
        let lookup_table = DiscreteLogTable::new(0..=5);
        let choices: Vec<_> = choices
            .map(|c| sk.decrypt(c, &lookup_table).unwrap())
            .collect();
        assert_eq!(choices, [1, 3, 0, 3, 2]);

        {
            let mut bogus_ballot = ballot.clone();
            bogus_ballot.votes[0].ciphertext.blinded_element += Ristretto::generator();
            let err = bogus_ballot.verify(&params).map(drop).unwrap_err();
            assert!(matches!(
                err,
                QuadraticVotingError::Variant {
                    index: 0,
                    error: VerificationError::ChallengeMismatch
                }
            ));
        }

        {
            let mut bogus_ballot = ballot.clone();
            bogus_ballot.credit.ciphertext.blinded_element -= Ristretto::generator();
            let err = bogus_ballot.verify(&params).map(drop).unwrap_err();
            assert!(matches!(err, QuadraticVotingError::CreditRange(_)));
        }

        let mut bogus_ballot = ballot.clone();
        let (ciphertext, proof) = RangeProof::new(
            &params.receiver,
            &params.vote_count_range,
            3, // << overly large
            &mut Transcript::new(b"quadratic_voting_variant"),
            &mut rng,
        );
        bogus_ballot.votes[0] = CiphertextWithRangeProof::new(ciphertext.into(), proof);

        let err = bogus_ballot.verify(&params).map(drop).unwrap_err();
        assert!(matches!(err, QuadraticVotingError::CreditEquivalence(_)));
    }
}
