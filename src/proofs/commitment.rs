//! Zero-knowledge proof of ElGamal encryption and Pedersen commitment equivalence.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::ScalarHelper;
use crate::{
    group::Group,
    proofs::{TranscriptForGroup, VerificationError},
    Ciphertext, CiphertextWithValue, PublicKey, SecretKey,
};

/// Zero-knowledge proof that an ElGamal ciphertext encrypts the same value as a Pedersen
/// commitment.
///
/// This proof can be used to switch from frameworks applicable to ElGamal ciphertexts, to ones
/// applicable to Pedersen commitments (e.g., [Bulletproofs] for range proofs).
///
/// [Bulletproofs]: https://crypto.stanford.edu/bulletproofs/
///
/// # Construction
///
/// We want to prove in zero knowledge the knowledge of scalars `r_e`, `v`, `r_c` such as
///
/// ```text
/// R = [r_e]G; B = [v]G + [r_e]K;
/// // (R, B) is ElGamal ciphertext of `v` for public key `K`
/// C = [v]G + [r_c]H;
/// // C is Pedersen commitment to `v`
/// ```
///
/// Here, we assume that the conventional group generator `G` is shared between encryption and
/// commitment protocols.
///
/// An interactive version of the proof can be built as a sigma protocol:
///
/// 1. **Commitment.** The prover generates 3 random scalars `e_r`, `e_v` and `e_c` and commits
///   to them via `E_r = [e_r]G`, `E_b = [e_v]G + [e_r]K`, and `E_c = [e_v]G + [e_c]H`.
/// 2. **Challenge.** The verifier sends to the prover random scalar `c`.
/// 3. **Response.** The prover computes the following scalars and sends them to the verifier.
///
/// ```text
/// s_r = e_r + c * r_e;
/// s_v = e_v + c * v;
/// s_c = e_c + c * r_c;
/// ```
///
/// The verification equations are
///
/// ```text
/// [s_r]G ?= E_r + [c]R;
/// [s_v]G + [s_r]K ?= E_b + [c]B;
/// [s_v]G + [s_c]H ?= E_c + [c]C;
/// ```
///
/// A non-interactive version of the proof is obtained by applying [Fiat–Shamir transform][fst].
/// As with other proofs, it is more efficient to represent a proof as the challenge
/// and responses (i.e., 4 scalars in total).
///
/// [fst]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{
/// #     group::{ElementOps, ScalarOps, Group, Ristretto},
/// #     Keypair, SecretKey, CommitmentEquivalenceProof, CiphertextWithValue,
/// # };
/// # use merlin::Transcript;
/// # use rand::thread_rng;
/// #
/// # const BLINDING_BASE: &[u8] = &[
/// #     140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4,
/// #     141, 116, 95, 148, 160, 140, 219, 127, 68, 203, 205, 123, 70,
/// #     243, 64, 72, 135, 17, 52,
/// # ];
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let blinding_base = // Blinding base for Pedersen commitments
///                     // (e.g., from Bulletproofs)
/// #    Ristretto::deserialize_element(BLINDING_BASE).unwrap();
/// let mut rng = thread_rng();
/// let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
///
/// // Create an ElGamal ciphertext of `value` for `receiver`.
/// let value = 424242_u64;
/// let ciphertext = CiphertextWithValue::new(value, &receiver, &mut rng)
///     .generalize();
/// // Create a Pedersen commitment of the same value.
/// let blinding = SecretKey::generate(&mut rng);
/// let commitment = Ristretto::multi_mul(
///     [&value.into(), blinding.expose_scalar()],
///     [Ristretto::generator(), blinding_base],
/// );
/// // Use `commitment` and `blinding` in other proofs...
///
/// let (proof, commitment) = CommitmentEquivalenceProof::new(
///     &ciphertext,
///     &receiver,
///     &blinding,
///     blinding_base,
///     &mut Transcript::new(b"custom_proof"),
///     &mut rng,
/// );
/// proof.verify(
///     &ciphertext.into(),
///     &receiver,
///     commitment,
///     blinding_base,
///     &mut Transcript::new(b"custom_proof"),
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct CommitmentEquivalenceProof<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    challenge: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    randomness_response: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    value_response: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    commitment_response: G::Scalar,
}

impl<G: Group> CommitmentEquivalenceProof<G> {
    /// Creates a proof based on the `ciphertext` for `receiver` and `commitment_blinding`
    /// with `commitment_blinding_base` for a Pedersen commitment. (The latter two args
    /// correspond to `r_c` and `H` in the [*Construction*](#construction) section, respectively.)
    ///
    /// # Return value
    ///
    /// Returns a proof together with the Pedersen commitment.
    pub fn new<R: RngCore + CryptoRng>(
        ciphertext: &CiphertextWithValue<G>,
        receiver: &PublicKey<G>,
        commitment_blinding: &SecretKey<G>,
        commitment_blinding_base: G::Element,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> (Self, G::Element) {
        let commitment = G::multi_mul(
            [ciphertext.value(), commitment_blinding.expose_scalar()],
            [G::generator(), commitment_blinding_base],
        );

        transcript.start_proof(b"commitment_equivalence");
        transcript.append_element_bytes(b"K", receiver.as_bytes());
        transcript.append_element::<G>(b"R", &ciphertext.inner().random_element);
        transcript.append_element::<G>(b"B", &ciphertext.inner().blinded_element);
        transcript.append_element::<G>(b"C", &commitment);

        let random_scalar = SecretKey::<G>::generate(rng);
        let value_scalar = SecretKey::<G>::generate(rng);
        let commitment_scalar = SecretKey::<G>::generate(rng);
        let random_commitment = G::mul_generator(random_scalar.expose_scalar());
        transcript.append_element::<G>(b"[e_r]G", &random_commitment);

        let value_element = G::mul_generator(value_scalar.expose_scalar());
        let enc_blinding_commitment =
            value_element + receiver.as_element() * random_scalar.expose_scalar();
        transcript.append_element::<G>(b"[e_v]G + [e_r]K", &enc_blinding_commitment);
        let commitment_commitment =
            value_element + commitment_blinding_base * commitment_scalar.expose_scalar();
        transcript.append_element::<G>(b"[e_v]G + [e_c]H", &commitment_commitment);

        let challenge = transcript.challenge_scalar::<G>(b"c");
        let randomness_response =
            challenge * ciphertext.randomness().expose_scalar() + random_scalar.expose_scalar();
        let value_response = challenge * ciphertext.value() + value_scalar.expose_scalar();
        let commitment_response =
            challenge * commitment_blinding.expose_scalar() + commitment_scalar.expose_scalar();

        let proof = Self {
            challenge,
            randomness_response,
            value_response,
            commitment_response,
        };
        (proof, commitment)
    }

    /// # Errors
    ///
    /// Returns an error if this proof does not verify.
    pub fn verify(
        &self,
        ciphertext: &Ciphertext<G>,
        receiver: &PublicKey<G>,
        commitment: G::Element,
        commitment_blinding_base: G::Element,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError> {
        transcript.start_proof(b"commitment_equivalence");
        transcript.append_element_bytes(b"K", receiver.as_bytes());
        transcript.append_element::<G>(b"R", &ciphertext.random_element);
        transcript.append_element::<G>(b"B", &ciphertext.blinded_element);
        transcript.append_element::<G>(b"C", &commitment);

        let neg_challenge = -self.challenge;
        let random_commitment = G::vartime_double_mul_generator(
            &neg_challenge,
            ciphertext.random_element,
            &self.randomness_response,
        );
        transcript.append_element::<G>(b"[e_r]G", &random_commitment);

        let enc_blinding_commitment = G::vartime_multi_mul(
            [
                &self.value_response,
                &self.randomness_response,
                &neg_challenge,
            ],
            [
                G::generator(),
                receiver.as_element(),
                ciphertext.blinded_element,
            ],
        );
        transcript.append_element::<G>(b"[e_v]G + [e_r]K", &enc_blinding_commitment);

        let commitment_commitment = G::vartime_multi_mul(
            [
                &self.value_response,
                &self.commitment_response,
                &neg_challenge,
            ],
            [G::generator(), commitment_blinding_base, commitment],
        );
        transcript.append_element::<G>(b"[e_v]G + [e_c]H", &commitment_commitment);

        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        if expected_challenge == self.challenge {
            Ok(())
        } else {
            Err(VerificationError::ChallengeMismatch)
        }
    }
}

#[cfg(all(test, feature = "curve25519-dalek-ng"))]
mod tests {
    use super::*;
    use crate::{
        group::{ElementOps, Ristretto},
        Keypair,
    };

    use bulletproofs::PedersenGens;
    use rand::thread_rng;

    #[test]
    fn equivalence_proof_basics() {
        let mut rng = thread_rng();
        let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        let value = 1234_u64;
        let ciphertext = CiphertextWithValue::new(value, &receiver, &mut rng).generalize();

        let commitment_gens = PedersenGens::default();
        assert_eq!(commitment_gens.B, Ristretto::generator());
        let blinding = SecretKey::generate(&mut rng);

        let (proof, commitment) = CommitmentEquivalenceProof::new(
            &ciphertext,
            &receiver,
            &blinding,
            commitment_gens.B_blinding,
            &mut Transcript::new(b"test"),
            &mut rng,
        );
        assert_eq!(
            commitment,
            commitment_gens.commit(*ciphertext.value(), *blinding.expose_scalar())
        );

        let ciphertext = ciphertext.into();
        proof
            .verify(
                &ciphertext,
                &receiver,
                commitment,
                commitment_gens.B_blinding,
                &mut Transcript::new(b"test"),
            )
            .unwrap();

        let other_ciphertext = receiver.encrypt(8_u64, &mut rng);
        let err = proof
            .verify(
                &other_ciphertext,
                &receiver,
                commitment,
                commitment_gens.B_blinding,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = proof
            .verify(
                &ciphertext,
                &receiver,
                commitment + Ristretto::generator(),
                commitment_gens.B_blinding,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = proof
            .verify(
                &ciphertext,
                &receiver,
                commitment,
                commitment_gens.B_blinding,
                &mut Transcript::new(b"other_test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));
    }
}
