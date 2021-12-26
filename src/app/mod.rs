//! High-level applications for proofs defined in this crate.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use core::fmt;

use crate::{
    group::Group, Ciphertext, PreparedRange, PublicKey, RangeDecomposition, RangeProof,
    SumOfSquaresProof, VerificationError,
};

/// Quadratic voting parameters prepared for a certain [`Group`].
#[derive(Debug)]
pub struct QuadraticVotingParams<G: Group> {
    variant_range: PreparedRange<G>,
    credit_range: PreparedRange<G>,
}

impl<G: Group> QuadraticVotingParams<G> {
    /// Creates new parameters for the specified maximum number of votes per issue and
    /// the credits allocated per voter.
    ///
    /// # Panics
    ///
    /// - Panics if `max_votes * max_votes` exceeds `credits`; in this case, this number of votes
    ///   cannot be cast for a single issue.
    pub fn new(max_votes: u64, credits: u64) -> Self {
        assert!(
            max_votes * max_votes <= credits,
            "Vote bound {} is too large; its square is greater than credit bound {}",
            max_votes,
            credits
        );

        let variant_range = RangeDecomposition::optimal(max_votes + 1);
        let credit_range = RangeDecomposition::optimal(credits + 1);
        Self {
            variant_range: variant_range.into(),
            credit_range: credit_range.into(),
        }
    }
}

/// Ballot for quadratic voting.
///
/// FIXME: describe voting protocol; add example
#[derive(Debug, Clone)]
pub struct QuadraticVotingBallot<G: Group> {
    variants: Vec<CiphertextWithRangeProof<G>>,
    credit: CiphertextWithRangeProof<G>,
    credit_equivalence_proof: SumOfSquaresProof<G>,
}

#[derive(Debug, Clone)]
struct CiphertextWithRangeProof<G: Group> {
    ciphertext: Ciphertext<G>,
    proof: RangeProof<G>,
}

impl<G: Group> CiphertextWithRangeProof<G> {
    fn new(ciphertext: Ciphertext<G>, proof: RangeProof<G>) -> Self {
        Self { ciphertext, proof }
    }
}

impl<G: Group> QuadraticVotingBallot<G> {
    /// Creates a ballot based on the provided parameters and voter's `votes`.
    pub fn new<R: CryptoRng + RngCore>(
        params: &QuadraticVotingParams<G>,
        votes: &[u64],
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let credit = votes.iter().map(|&x| x * x).sum::<u64>();

        let variants: Vec<_> = votes
            .iter()
            .map(|&variant| {
                RangeProof::new(
                    receiver,
                    &params.variant_range,
                    variant,
                    &mut Transcript::new(b"quadratic_voting_variant"),
                    rng,
                )
            })
            .collect();
        let (credit, credit_range_proof) = RangeProof::new(
            receiver,
            &params.credit_range,
            credit,
            &mut Transcript::new(b"quadratic_voting_credit_range"),
            rng,
        );
        let credit_equivalence_proof = SumOfSquaresProof::new(
            variants.iter().map(|(ciphertext, _)| ciphertext),
            &credit,
            receiver,
            &mut Transcript::new(b"quadratic_voting_credit_equiv"),
            rng,
        );

        Self {
            variants: variants
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
        receiver: &PublicKey<G>,
    ) -> Result<impl Iterator<Item = Ciphertext<G>> + '_, QuadraticVotingError> {
        for (i, variant) in self.variants.iter().enumerate() {
            variant
                .proof
                .verify(
                    receiver,
                    &params.variant_range,
                    variant.ciphertext,
                    &mut Transcript::new(b"quadratic_voting_variant"),
                )
                .map_err(|error| QuadraticVotingError::Variant { index: i, error })?;
        }

        self.credit
            .proof
            .verify(
                receiver,
                &params.credit_range,
                self.credit.ciphertext,
                &mut Transcript::new(b"quadratic_voting_credit_range"),
            )
            .map_err(QuadraticVotingError::CreditRange)?;

        self.credit_equivalence_proof
            .verify(
                self.variants.iter().map(|c| &c.ciphertext),
                &self.credit.ciphertext,
                receiver,
                &mut Transcript::new(b"quadratic_voting_credit_equiv"),
            )
            .map_err(QuadraticVotingError::CreditEquivalence)?;

        Ok(self.variants.iter().map(|c| c.ciphertext))
    }
}

/// Errors that can occur when verifying [`QuadraticVotingBallot`]s.
#[derive(Debug)]
#[non_exhaustive]
pub enum QuadraticVotingError {
    /// Error verifying a [`RangeProof`] for a variant.
    Variant {
        /// Zero-based variant index.
        index: usize,
        /// Error that occurred during range proof verification.
        error: VerificationError,
    },
    /// Error verifying a [`RangeProof`] for credits.
    CreditRange(VerificationError),
    /// Error verifying the [proof of equivalence](SumOfSquaresProof) for credits.
    CreditEquivalence(VerificationError),
}

impl fmt::Display for QuadraticVotingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Variant { index, error } => {
                write!(
                    formatter,
                    "error verifying range proof for variant #{}: {}",
                    *index + 1,
                    error
                )
            }
            Self::CreditRange(err) => write!(
                formatter,
                "error verifying range proof for credits: {}",
                err
            ),
            Self::CreditEquivalence(err) => write!(
                formatter,
                "error verifying credit equivalence proof: {}",
                err
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
    fn quadratic_voting() {
        let mut rng = thread_rng();
        let params = QuadraticVotingParams::<Ristretto>::new(5, 25);
        let receiver = Keypair::generate(&mut rng);
        let ballot =
            QuadraticVotingBallot::new(&params, &[1, 3, 0, 3, 2], receiver.public(), &mut rng);

        let choices = ballot.verify(&params, receiver.public()).unwrap();
        let lookup_table = DiscreteLogTable::new(0..=5);
        let choices: Vec<_> = choices
            .map(|c| receiver.secret().decrypt(c, &lookup_table).unwrap())
            .collect();
        assert_eq!(choices, [1, 3, 0, 3, 2]);

        {
            let mut bogus_ballot = ballot.clone();
            bogus_ballot.variants[0].ciphertext.blinded_element += Ristretto::generator();
            let err = bogus_ballot
                .verify(&params, receiver.public())
                .map(drop)
                .unwrap_err();
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
            let err = bogus_ballot
                .verify(&params, receiver.public())
                .map(drop)
                .unwrap_err();
            assert!(matches!(err, QuadraticVotingError::CreditRange(_)));
        }

        let mut bogus_ballot = ballot.clone();
        let (ciphertext, proof) = RangeProof::new(
            receiver.public(),
            &params.variant_range,
            3, // << overly large
            &mut Transcript::new(b"quadratic_voting_variant"),
            &mut rng,
        );
        bogus_ballot.variants[0] = CiphertextWithRangeProof::new(ciphertext.into(), proof);

        let err = bogus_ballot
            .verify(&params, receiver.public())
            .map(drop)
            .unwrap_err();
        assert!(matches!(err, QuadraticVotingError::CreditEquivalence(_)));
    }
}
