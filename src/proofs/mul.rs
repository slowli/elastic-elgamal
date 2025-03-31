//! Proofs related to multiplication.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use core::iter;

#[cfg(feature = "serde")]
use crate::serde::{ScalarHelper, VecHelper};
use crate::{
    Ciphertext, CiphertextWithValue, PublicKey, SecretKey, VerificationError, alloc::Vec,
    group::Group, proofs::TranscriptForGroup,
};

/// Zero-knowledge proof that an ElGamal-encrypted value is equal to a sum of squares
/// of one or more other ElGamal-encrypted values.
///
/// # Construction
///
/// Consider the case with a single sum element (i.e., proving that an encrypted value is
/// a square of another encrypted value). The prover wants to prove the knowledge of scalars
///
/// ```text
/// r_x, x, r_z:
///   R_x = [r_x]G, X = [x]G + [r_x]K;
///   R_z = [r_z]G, Z = [x^2]G + [r_z]K,
/// ```
///
/// where
///
/// - `G` is the conventional generator of the considered prime-order group
/// - `K` is a group element equivalent to the receiver's public key
/// - `(R_x, X)` and `(R_z, Z)` are ElGamal ciphertexts of values `x` and `x^2`, respectively.
///
/// Observe that
///
/// ```text
/// r'_z := r_z - x * r_x =>
///   R_z = [r'_z]G + [x]R_x; Z = [x]X + [r'_z]K.
/// ```
///
/// and that proving the knowledge of `(r_x, x, r'_z)` is equivalent to the initial problem.
/// The new problem can be solved using a conventional sigma protocol:
///
/// 1. **Commitment.** The prover generates random scalars `e_r`, `e_x` and `e_z` and commits
///    to them via `E_r = [e_r]G`, `E_x = [e_x]G + [e_r]K`, `E_rz = [e_x]R_x + [e_z]G` and
///    `E_z = [e_x]X + [e_z]K`.
/// 2. **Challenge.** The verifier sends to the prover random scalar `c`.
/// 3. **Response.** The prover computes the following scalars and sends them to the verifier.
///
/// ```text
/// s_r = e_r + c * r_x;
/// s_x = e_x + c * x;
/// s_z = e_z + c * (r_z - x * r_x);
/// ```
///
/// The verification equations are
///
/// ```text
/// [s_r]G ?= E_r + [c]R_x;
/// [s_x]G + [s_r]K ?= E_x + [c]X;
/// [s_x]R_x + [s_z]G ?= E_rz + [c]R_z;
/// [s_x]X + [s_z]K ?= E_z + [c]Z.
/// ```
///
/// The case with multiple squares is a straightforward generalization:
///
/// - `e_r`, `E_r`, `e_x`, `E_x`, `s_r` and `s_x` are independently defined for each
///   partial ciphertext in the same way as above.
/// - Commitments `E_rz` and `E_z` sum over `[e_x]R_x` and `[e_x]X` for all ciphertexts,
///   respectively.
/// - Response `s_z` similarly substitutes `x * r_x` with the corresponding sum.
///
/// A non-interactive version of the proof is obtained by applying [Fiat–Shamir transform][fst].
/// As with [`LogEqualityProof`], it is more efficient to represent a proof as the challenge
/// and responses; in this case, the proof size is `2n + 2` scalars, where `n` is the number of
/// partial ciphertexts.
///
/// [fst]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [`LogEqualityProof`]: crate::LogEqualityProof
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct SumOfSquaresProof<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    challenge: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ScalarHelper<G>, 2>"))]
    ciphertext_responses: Vec<G::Scalar>,
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    sum_response: G::Scalar,
}

impl<G: Group> SumOfSquaresProof<G> {
    fn initialize_transcript(transcript: &mut Transcript, receiver: &PublicKey<G>) {
        transcript.start_proof(b"sum_of_squares");
        transcript.append_element_bytes(b"K", receiver.as_bytes());
    }

    /// Creates a new proof that squares of values encrypted in `ciphertexts` for `receiver` sum up
    /// to a value encrypted in `sum_of_squares_ciphertext`.
    ///
    /// All provided ciphertexts must be encrypted for `receiver`; otherwise, the created proof
    /// will not verify.
    #[allow(clippy::needless_collect)] // false positive
    pub fn new<'a, R: RngCore + CryptoRng>(
        ciphertexts: impl Iterator<Item = &'a CiphertextWithValue<G>>,
        sum_of_squares_ciphertext: &CiphertextWithValue<G>,
        receiver: &PublicKey<G>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self {
        Self::initialize_transcript(transcript, receiver);

        let sum_scalar = SecretKey::<G>::generate(rng);
        let mut sum_random_scalar = sum_of_squares_ciphertext.randomness().clone();

        let partial_scalars: Vec<_> = ciphertexts
            .map(|ciphertext| {
                transcript.append_element::<G>(b"R_x", &ciphertext.inner().random_element);
                transcript.append_element::<G>(b"X", &ciphertext.inner().blinded_element);

                let random_scalar = SecretKey::<G>::generate(rng);
                let random_commitment = G::mul_generator(random_scalar.expose_scalar());
                transcript.append_element::<G>(b"[e_r]G", &random_commitment);
                let value_scalar = SecretKey::<G>::generate(rng);
                let value_commitment = G::mul_generator(value_scalar.expose_scalar())
                    + receiver.as_element() * random_scalar.expose_scalar();
                transcript.append_element::<G>(b"[e_x]G + [e_r]K", &value_commitment);

                let neg_value = Zeroizing::new(-*ciphertext.value());
                sum_random_scalar += ciphertext.randomness() * &neg_value;
                (ciphertext, random_scalar, value_scalar)
            })
            .collect();

        let scalars = partial_scalars
            .iter()
            .map(|(_, _, value_scalar)| value_scalar.expose_scalar())
            .chain(iter::once(sum_scalar.expose_scalar()));
        let random_sum_commitment = {
            let elements = partial_scalars
                .iter()
                .map(|(ciphertext, ..)| ciphertext.inner().random_element)
                .chain(iter::once(G::generator()));
            G::multi_mul(scalars.clone(), elements)
        };
        let value_sum_commitment = {
            let elements = partial_scalars
                .iter()
                .map(|(ciphertext, ..)| ciphertext.inner().blinded_element)
                .chain(iter::once(receiver.as_element()));
            G::multi_mul(scalars, elements)
        };

        transcript.append_element::<G>(b"R_z", &sum_of_squares_ciphertext.inner().random_element);
        transcript.append_element::<G>(b"Z", &sum_of_squares_ciphertext.inner().blinded_element);
        transcript.append_element::<G>(b"[e_x]R_x + [e_z]G", &random_sum_commitment);
        transcript.append_element::<G>(b"[e_x]X + [e_z]K", &value_sum_commitment);
        let challenge = transcript.challenge_scalar::<G>(b"c");

        let ciphertext_responses = partial_scalars
            .into_iter()
            .flat_map(|(ciphertext, random_scalar, value_scalar)| {
                [
                    challenge * ciphertext.randomness().expose_scalar()
                        + random_scalar.expose_scalar(),
                    challenge * ciphertext.value() + value_scalar.expose_scalar(),
                ]
            })
            .collect();
        let sum_response =
            challenge * sum_random_scalar.expose_scalar() + sum_scalar.expose_scalar();

        Self {
            challenge,
            ciphertext_responses,
            sum_response,
        }
    }

    /// Verifies this proof against the provided partial ciphertexts and the ciphertext of the
    /// sum of their squares. The order of partial ciphertexts must correspond to their order
    /// when creating the proof.
    ///
    /// # Errors
    ///
    /// Returns an error if this proof does not verify.
    pub fn verify<'a>(
        &self,
        ciphertexts: impl Iterator<Item = &'a Ciphertext<G>> + Clone,
        sum_of_squares_ciphertext: &Ciphertext<G>,
        receiver: &PublicKey<G>,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError> {
        let ciphertexts_count = ciphertexts.clone().count();
        VerificationError::check_lengths(
            "ciphertext responses",
            self.ciphertext_responses.len(),
            ciphertexts_count * 2,
        )?;

        Self::initialize_transcript(transcript, receiver);
        let neg_challenge = -self.challenge;

        for (response_chunk, ciphertext) in
            self.ciphertext_responses.chunks(2).zip(ciphertexts.clone())
        {
            transcript.append_element::<G>(b"R_x", &ciphertext.random_element);
            transcript.append_element::<G>(b"X", &ciphertext.blinded_element);

            let r_response = &response_chunk[0];
            let v_response = &response_chunk[1];
            let random_commitment = G::vartime_double_mul_generator(
                &-self.challenge,
                ciphertext.random_element,
                r_response,
            );
            transcript.append_element::<G>(b"[e_r]G", &random_commitment);
            let value_commitment = G::vartime_multi_mul(
                [v_response, r_response, &neg_challenge],
                [
                    G::generator(),
                    receiver.as_element(),
                    ciphertext.blinded_element,
                ],
            );
            transcript.append_element::<G>(b"[e_x]G + [e_r]K", &value_commitment);
        }

        let scalars = OddItems::new(self.ciphertext_responses.iter())
            .chain([&self.sum_response, &neg_challenge]);
        let random_sum_commitment = {
            let elements = ciphertexts
                .clone()
                .map(|c| c.random_element)
                .chain([G::generator(), sum_of_squares_ciphertext.random_element]);
            G::vartime_multi_mul(scalars.clone(), elements)
        };
        let value_sum_commitment = {
            let elements = ciphertexts.map(|c| c.blinded_element).chain([
                receiver.as_element(),
                sum_of_squares_ciphertext.blinded_element,
            ]);
            G::vartime_multi_mul(scalars, elements)
        };

        transcript.append_element::<G>(b"R_z", &sum_of_squares_ciphertext.random_element);
        transcript.append_element::<G>(b"Z", &sum_of_squares_ciphertext.blinded_element);
        transcript.append_element::<G>(b"[e_x]R_x + [e_z]G", &random_sum_commitment);
        transcript.append_element::<G>(b"[e_x]X + [e_z]K", &value_sum_commitment);
        let expected_challenge = transcript.challenge_scalar::<G>(b"c");

        if expected_challenge == self.challenge {
            Ok(())
        } else {
            Err(VerificationError::ChallengeMismatch)
        }
    }
}

/// Thin wrapper around an iterator that drops its even-indexed elements. This is necessary
/// because `Ristretto::vartime_multi_mul()` panics otherwise, which is caused by an imprecise
/// `Iterator::size_hint()` value.
#[derive(Debug, Clone)]
struct OddItems<I> {
    iter: I,
    ended: bool,
}

impl<I: Iterator> OddItems<I> {
    fn new(iter: I) -> Self {
        Self { iter, ended: false }
    }
}

impl<I: Iterator> Iterator for OddItems<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        self.ended = self.iter.next().is_none();
        if self.ended {
            return None;
        }

        let item = self.iter.next();
        self.ended = item.is_none();
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        (min / 2, max.map(|max| max / 2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, group::Ristretto};

    use rand::rng;

    #[test]
    fn sum_of_squares_proof_basics() {
        let mut rng = rng();
        let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        let ciphertext = CiphertextWithValue::new(3_u64, &receiver, &mut rng).generalize();
        let sq_ciphertext = CiphertextWithValue::new(9_u64, &receiver, &mut rng).generalize();

        let proof = SumOfSquaresProof::new(
            [&ciphertext].into_iter(),
            &sq_ciphertext,
            &receiver,
            &mut Transcript::new(b"test"),
            &mut rng,
        );

        let ciphertext = ciphertext.into();
        let sq_ciphertext = sq_ciphertext.into();
        proof
            .verify(
                [&ciphertext].into_iter(),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap();

        let other_ciphertext = receiver.encrypt(8_u64, &mut rng);
        let err = proof
            .verify(
                [&ciphertext].into_iter(),
                &other_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = proof
            .verify(
                [&other_ciphertext].into_iter(),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = proof
            .verify(
                [&ciphertext].into_iter(),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"other_transcript"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));
    }

    #[test]
    fn sum_of_squares_proof_with_bogus_inputs() {
        let mut rng = rng();
        let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        let ciphertext = CiphertextWithValue::new(3_u64, &receiver, &mut rng).generalize();
        let sq_ciphertext = CiphertextWithValue::new(10_u64, &receiver, &mut rng).generalize();

        let proof = SumOfSquaresProof::new(
            [&ciphertext].into_iter(),
            &sq_ciphertext,
            &receiver,
            &mut Transcript::new(b"test"),
            &mut rng,
        );

        let ciphertext = ciphertext.into();
        let sq_ciphertext = sq_ciphertext.into();
        let err = proof
            .verify(
                [&ciphertext].into_iter(),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));
    }

    #[test]
    fn sum_of_squares_proof_with_several_squares() {
        let mut rng = rng();
        let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        let ciphertexts =
            [3_u64, 1, 4, 1].map(|x| CiphertextWithValue::new(x, &receiver, &mut rng).generalize());
        let sq_ciphertext = CiphertextWithValue::new(27_u64, &receiver, &mut rng).generalize();

        let proof = SumOfSquaresProof::new(
            ciphertexts.iter(),
            &sq_ciphertext,
            &receiver,
            &mut Transcript::new(b"test"),
            &mut rng,
        );

        let sq_ciphertext = sq_ciphertext.into();
        proof
            .verify(
                ciphertexts.iter().map(CiphertextWithValue::inner),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap();

        // The proof will not verify if ciphertexts are rearranged.
        let err = proof
            .verify(
                ciphertexts.iter().rev().map(CiphertextWithValue::inner),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = proof
            .verify(
                ciphertexts.iter().take(2).map(CiphertextWithValue::inner),
                &sq_ciphertext,
                &receiver,
                &mut Transcript::new(b"test"),
            )
            .unwrap_err();
        assert!(matches!(err, VerificationError::LenMismatch { .. }));
    }

    #[test]
    fn odd_items() {
        let odd_items = OddItems::new(iter::once(1).chain([2, 3, 4]));
        assert_eq!(odd_items.size_hint(), (2, Some(2)));
        assert_eq!(odd_items.collect::<Vec<_>>(), [2, 4]);

        let other_items = OddItems::new(0..7);
        assert_eq!(other_items.size_hint(), (3, Some(3)));
        assert_eq!(other_items.collect::<Vec<_>>(), [1, 3, 5]);
    }
}
