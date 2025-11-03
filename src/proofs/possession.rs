//! [`ProofOfPossession`] and related logic.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::{ScalarHelper, VecHelper};
use crate::{
    alloc::Vec,
    group::Group,
    proofs::{TranscriptForGroup, VerificationError},
    Keypair, PublicKey, SecretKey,
};

/// Zero-knowledge proof of possession of one or more secret scalars.
///
/// # Construction
///
/// The proof is a generalization of the standard Schnorr protocol for proving knowledge
/// of a discrete log. The difference with the combination of several concurrent Schnorr
/// protocol instances is that the challenge is shared among all instances (which yields a
/// ~2x proof size reduction).
///
/// # Implementation notes
///
/// - Proof generation is constant-time. Verification is **not** constant-time.
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, Keypair, ProofOfPossession};
/// # use merlin::Transcript;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = rand::rng();
/// let keypairs: Vec<_> =
///     (0..5).map(|_| Keypair::<Ristretto>::generate(&mut rng)).collect();
///
/// // Prove possession of the generated key pairs.
/// let proof = ProofOfPossession::new(
///     &keypairs,
///     &mut Transcript::new(b"custom_proof"),
///     &mut rng,
/// );
/// proof.verify(
///     keypairs.iter().map(Keypair::public),
///     &mut Transcript::new(b"custom_proof"),
/// )?;
///
/// // If we change the context of the `Transcript`, the proof will not verify.
/// assert!(proof
///     .verify(
///         keypairs.iter().map(Keypair::public),
///         &mut Transcript::new(b"other_proof"),
///     )
///     .is_err());
/// // Likewise if the public keys are reordered.
/// assert!(proof
///     .verify(
///         keypairs.iter().rev().map(Keypair::public),
///         &mut Transcript::new(b"custom_proof"),
///     )
///     .is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ProofOfPossession<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    challenge: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ScalarHelper<G>, 1>"))]
    responses: Vec<G::Scalar>,
}

impl<G: Group> ProofOfPossession<G> {
    /// Creates a proof of possession with the specified `keypairs`.
    pub fn new<R: CryptoRng + RngCore>(
        keypairs: &[Keypair<G>],
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self {
        Self::from_keys(
            keypairs.iter().map(Keypair::secret),
            keypairs.iter().map(Keypair::public),
            transcript,
            rng,
        )
    }

    pub(crate) fn from_keys<'a, R: CryptoRng + RngCore>(
        secrets: impl Iterator<Item = &'a SecretKey<G>>,
        public_keys: impl Iterator<Item = &'a PublicKey<G>>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self {
        transcript.start_proof(b"multi_pop");
        let mut key_count = 0;
        for public_key in public_keys {
            transcript.append_element_bytes(b"K", public_key.as_bytes());
            key_count += 1;
        }

        let random_scalars: Vec<_> = (0..key_count)
            .map(|_| {
                let randomness = SecretKey::<G>::generate(rng);
                let random_element = G::mul_generator(randomness.expose_scalar());
                transcript.append_element::<G>(b"R", &random_element);
                randomness
            })
            .collect();

        let challenge = transcript.challenge_scalar::<G>(b"c");
        let responses = secrets
            .zip(random_scalars)
            .map(|(log, mut randomness)| {
                randomness += log * &challenge;
                *randomness.expose_scalar()
            })
            .collect();

        Self {
            challenge,
            responses,
        }
    }

    /// Verifies this proof against the provided `public_keys`.
    ///
    /// # Errors
    ///
    /// Returns an error if this proof does not verify.
    pub fn verify<'a>(
        &self,
        public_keys: impl Iterator<Item = &'a PublicKey<G>> + Clone,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError> {
        let mut key_count = 0;
        transcript.start_proof(b"multi_pop");
        for public_key in public_keys.clone() {
            transcript.append_element_bytes(b"K", public_key.as_bytes());
            key_count += 1;
        }
        VerificationError::check_lengths("public keys", self.responses.len(), key_count)?;

        for (public_key, response) in public_keys.zip(&self.responses) {
            let random_element = G::vartime_double_mul_generator(
                &-self.challenge,
                public_key.as_element(),
                response,
            );
            transcript.append_element::<G>(b"R", &random_element);
        }

        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        if expected_challenge == self.challenge {
            Ok(())
        } else {
            Err(VerificationError::ChallengeMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Ristretto;

    type Keypair = crate::Keypair<Ristretto>;

    #[test]
    fn proof_of_possession_basics() {
        let mut rng = rand::rng();
        let poly: Vec<_> = (0..5).map(|_| Keypair::generate(&mut rng)).collect();

        ProofOfPossession::new(&poly, &mut Transcript::new(b"test_multi_PoP"), &mut rng)
            .verify(
                poly.iter().map(Keypair::public),
                &mut Transcript::new(b"test_multi_PoP"),
            )
            .unwrap();
    }
}
