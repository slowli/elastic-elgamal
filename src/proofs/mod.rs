//! Zero-knowledge proofs.

use merlin::Transcript;

use core::fmt;

use crate::group::{Group, RandomBytesProvider};

mod log_equality;
mod mul;
mod possession;
mod range;
mod ring;

pub use self::{
    log_equality::LogEqualityProof,
    mul::SumOfSquaresProof,
    possession::ProofOfPossession,
    range::{PreparedRange, RangeDecomposition, RangeProof},
    ring::{RingProof, RingProofBuilder},
};

/// Extension trait for Merlin transcripts used in constructing our proofs.
pub(crate) trait TranscriptForGroup {
    fn start_proof(&mut self, proof_label: &'static [u8]);

    fn append_element_bytes(&mut self, label: &'static [u8], element_bytes: &[u8]);

    fn append_element<G: Group>(&mut self, label: &'static [u8], element: &G::Element);

    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar;
}

impl TranscriptForGroup for Transcript {
    fn start_proof(&mut self, proof_label: &'static [u8]) {
        self.append_message(b"dom-sep", proof_label);
    }

    fn append_element_bytes(&mut self, label: &'static [u8], element_bytes: &[u8]) {
        self.append_message(label, element_bytes);
    }

    fn append_element<G: Group>(&mut self, label: &'static [u8], element: &G::Element) {
        let mut output = vec![0_u8; G::ELEMENT_SIZE];
        G::serialize_element(element, &mut output);
        self.append_element_bytes(label, &output);
    }

    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar {
        G::scalar_from_random_bytes(RandomBytesProvider::new(self, label))
    }
}

/// Error verifying base proofs, such as [`RingProof`], [`LogEqualityProof`]
/// or [`ProofOfPossession`].
#[derive(Debug)]
#[non_exhaustive]
pub enum VerificationError {
    /// Restored challenge scalar does not match the one provided in the proof.
    ///
    /// This error most likely means that the proof itself is malformed, or that it was created
    /// for a different context than it is being verified for.
    ChallengeMismatch,
    /// A collection (e.g., number of responses in a [`RingProof`]) has a different size
    /// than expected.
    ///
    /// This error most likely means that the proof is malformed.
    LenMismatch {
        /// Human-readable collection name, such as "public keys".
        collection: &'static str,
        /// Expected size of the collection.
        expected: usize,
        /// Actual size of the collection.
        actual: usize,
    },
}

impl VerificationError {
    pub(crate) fn check_lengths(
        collection: &'static str,
        expected: usize,
        actual: usize,
    ) -> Result<(), Self> {
        if expected == actual {
            Ok(())
        } else {
            Err(Self::LenMismatch {
                collection,
                expected,
                actual,
            })
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChallengeMismatch => formatter.write_str(
                "restored challenge scalar does not match the one provided in the proof",
            ),

            Self::LenMismatch {
                collection,
                expected,
                actual,
            } => write!(
                formatter,
                "number of {collection} ({act}) differs from expected ({exp})",
                collection = collection,
                act = actual,
                exp = expected
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerificationError {}
