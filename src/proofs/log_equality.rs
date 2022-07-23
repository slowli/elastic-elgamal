//! [`LogEqualityProof`] and related logic.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::ScalarHelper;
use crate::{
    alloc::{vec, Vec},
    group::Group,
    proofs::{TranscriptForGroup, VerificationError},
    PublicKey, SecretKey,
};

/// Zero-knowledge proof of equality of two discrete logarithms in different bases,
/// aka Chaum–Pedersen protocol.
///
/// # Construction
///
/// This proof is a result of the [Fiat–Shamir transform][fst] applied to a standard
/// ZKP of equality of the two discrete logs in different bases.
///
/// - Public parameters of the proof are the two bases `G` and `K` in a prime-order group
///   in which discrete log problem is believed to be hard.
/// - Prover and verifier both know group elements `R` and `B`, which presumably have
///   the same discrete log in bases `G` and `K` respectively.
/// - Prover additionally knows the discrete log in question: `r = dlog_G(R) = dlog_K(B)`.
///
/// The interactive proof is specified as a sigma protocol (see, e.g., [this course])
/// as follows:
///
/// 1. **Commitment:** The prover generates random scalar `x`. The prover sends to the verifier
///   `X_G = [x]G` and `X_K = [x]K`.
/// 2. **Challenge:** The verifier sends to the prover random scalar `c`.
/// 3. **Response:** The prover computes scalar `s = x + cr` and sends it to the verifier.
///
/// Verification equations are:
///
/// ```text
/// [s]G ?= X_G + [c]R;
/// [s]K ?= X_K + [c]B.
/// ```
///
/// In the non-interactive version of the proof, challenge `c` is derived from `hash(M)`,
/// where `hash()` is a cryptographically secure hash function, and `M` is an optional message
/// verified together with the proof (cf. public-key digital signatures). If `M` is set, we
/// use a proof as a *signature of knowledge*. This allows to tie the proof to the context,
/// so it cannot be (re)used in other contexts.
///
/// To reduce the size of the proof, we use the trick underpinning ring signature constructions.
/// Namely, we represent the proof as `(c, s)`; during verification, we restore `X_G`, `X_K`
/// from the original verification equations above.
///
/// # Implementation details
///
/// - The proof is serialized as 2 scalars: `(c, s)`.
/// - Proof generation is constant-time. Verification is **not** constant-time.
/// - Challenge `c` is derived using [`Transcript`] API.
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, Keypair, SecretKey, LogEqualityProof};
/// # use merlin::Transcript;
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = thread_rng();
/// let (log_base, _) =
///     Keypair::<Ristretto>::generate(&mut rng).into_tuple();
/// let (power_g, discrete_log) =
///     Keypair::<Ristretto>::generate(&mut rng).into_tuple();
/// let power_k = log_base.as_element() * discrete_log.expose_scalar();
///
/// let proof = LogEqualityProof::new(
///     &log_base,
///     &discrete_log,
///     (power_g.as_element(), power_k),
///     &mut Transcript::new(b"custom_proof"),
///     &mut rng,
/// );
/// proof.verify(
///     &log_base,
///     (power_g.as_element(), power_k),
///     &mut Transcript::new(b"custom_proof"),
/// )?;
/// # Ok(())
/// # }
/// ```
///
/// [fst]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [this course]: http://www.cs.au.dk/~ivan/Sigma.pdf
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct LogEqualityProof<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    challenge: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    response: G::Scalar,
}

impl<G: Group> LogEqualityProof<G> {
    /// Creates a new proof.
    ///
    /// # Parameters
    ///
    /// - `log_base` is the second discrete log base (`K` in the notation above). The first
    ///   log base is always the [`Group`] generator.
    /// - `secret` is the discrete log (`r` in the notation above).
    /// - `powers` are `[r]G` and `[r]K`, respectively. It is **not** checked whether `r`
    ///   is a discrete log of these powers; if this is not the case, the constructed proof
    ///   will not [`verify`](Self::verify()).
    pub fn new<R: CryptoRng + RngCore>(
        log_base: &PublicKey<G>,
        secret: &SecretKey<G>,
        powers: (G::Element, G::Element),
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self {
        transcript.start_proof(b"log_eq");
        transcript.append_element_bytes(b"K", log_base.as_bytes());
        transcript.append_element::<G>(b"[r]G", &powers.0);
        transcript.append_element::<G>(b"[r]K", &powers.1);

        let random_scalar = SecretKey::<G>::generate(rng);
        transcript.append_element::<G>(b"[x]G", &G::mul_generator(random_scalar.expose_scalar()));
        transcript.append_element::<G>(
            b"[x]K",
            &(log_base.as_element() * random_scalar.expose_scalar()),
        );
        let challenge = transcript.challenge_scalar::<G>(b"c");
        let response = challenge * secret.expose_scalar() + random_scalar.expose_scalar();

        Self {
            challenge,
            response,
        }
    }

    /// Verifies this proof.
    ///
    /// # Parameters
    ///
    /// - `log_base` is the second discrete log base (`K` in the notation above). The first
    ///   log base is always the [`Group`] generator.
    /// - `powers` are group elements presumably equal to `[r]G` and `[r]K` respectively,
    ///   where `r` is a secret scalar.
    ///
    /// # Errors
    ///
    /// Returns an error if this proof does not verify.
    pub fn verify(
        &self,
        log_base: &PublicKey<G>,
        powers: (G::Element, G::Element),
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError> {
        let commitments = (
            G::vartime_double_mul_generator(&-self.challenge, powers.0, &self.response),
            G::vartime_multi_mul(
                &[-self.challenge, self.response],
                [powers.1, log_base.as_element()],
            ),
        );

        transcript.start_proof(b"log_eq");
        transcript.append_element_bytes(b"K", log_base.as_bytes());
        transcript.append_element::<G>(b"[r]G", &powers.0);
        transcript.append_element::<G>(b"[r]K", &powers.1);
        transcript.append_element::<G>(b"[x]G", &commitments.0);
        transcript.append_element::<G>(b"[x]K", &commitments.1);
        let expected_challenge = transcript.challenge_scalar::<G>(b"c");

        if expected_challenge == self.challenge {
            Ok(())
        } else {
            Err(VerificationError::ChallengeMismatch)
        }
    }

    /// Serializes this proof into bytes. As described [above](#implementation-details),
    /// the is serialized as 2 scalars: `(c, s)`, i.e., challenge and response.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0_u8; 2 * G::SCALAR_SIZE];
        G::serialize_scalar(&self.challenge, &mut bytes[..G::SCALAR_SIZE]);
        G::serialize_scalar(&self.response, &mut bytes[G::SCALAR_SIZE..]);
        bytes
    }

    /// Attempts to parse the proof from `bytes`. Returns `None` if `bytes` do not represent
    /// a well-formed proof.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 2 * G::SCALAR_SIZE {
            return None;
        }

        let challenge = G::deserialize_scalar(&bytes[..G::SCALAR_SIZE])?;
        let response = G::deserialize_scalar(&bytes[G::SCALAR_SIZE..])?;
        Some(Self {
            challenge,
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::group::Ristretto;

    type Keypair = crate::Keypair<Ristretto>;

    #[test]
    fn log_equality_basics() {
        let mut rng = thread_rng();
        let log_base = Keypair::generate(&mut rng).public().clone();

        for _ in 0..100 {
            let (generator_val, secret) = Keypair::generate(&mut rng).into_tuple();
            let key_val = log_base.as_element() * secret.expose_scalar();
            let proof = LogEqualityProof::new(
                &log_base,
                &secret,
                (generator_val.as_element(), key_val),
                &mut Transcript::new(b"testing_log_equality"),
                &mut rng,
            );

            proof
                .verify(
                    &log_base,
                    (generator_val.as_element(), key_val),
                    &mut Transcript::new(b"testing_log_equality"),
                )
                .unwrap();
        }
    }
}
