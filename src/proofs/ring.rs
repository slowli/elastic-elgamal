//! Ring proofs.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use subtle::ConstantTimeEq;

use std::fmt;

#[cfg(feature = "serde")]
use crate::serde::{ScalarHelper, VecHelper};
use crate::{
    encryption::ExtendedCiphertext, group::Group, proofs::TranscriptForGroup, Ciphertext,
    PublicKey, SecretKey,
};

/// An incomplete ring proving that the encrypted value is in the a priori known set of
/// admissible values.
struct Ring<'a, G: Group> {
    // Public parameters of the ring.
    index: usize,
    admissible_values: &'a [G::Element],
    ciphertext: Ciphertext<G>,

    // ZKP-related public values.
    transcript: Transcript,
    responses: SmallVec<[G::Scalar; 4]>,
    terminal_commitments: (G::Element, G::Element),

    // Secret values.
    value_index: usize,
    discrete_log: SecretKey<G>,
    random_scalar: SecretKey<G>,
}

impl<G: Group> fmt::Debug for Ring<'_, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ring")
            .field("index", &self.index)
            .field("admissible_values", &self.admissible_values)
            .field("ciphertext", &self.ciphertext)
            .field("responses", &self.responses)
            .field("terminal_commitments", &self.terminal_commitments)
            .finish()
    }
}

impl<'a, G: Group> Ring<'a, G> {
    fn new<R>(
        index: usize,
        log_base: G::Element,
        ciphertext: ExtendedCiphertext<G>,
        admissible_values: &'a [G::Element],
        value_index: usize,
        transcript: &Transcript,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        assert!(
            !admissible_values.is_empty(),
            "No admissible values supplied"
        );
        assert!(
            value_index < admissible_values.len(),
            "Specified value index is out of bounds"
        );

        let random_element = ciphertext.inner.random_element;
        let blinded_value = ciphertext.inner.blinded_element;
        debug_assert!(
            {
                let expected_blinded_value =
                    log_base * &ciphertext.random_scalar.0 + admissible_values[value_index];
                bool::from(expected_blinded_value.ct_eq(&blinded_value))
            },
            "Specified ciphertext does not match the specified `value_index`"
        );

        let mut transcript = transcript.clone();
        transcript.start_proof(b"ring_enc");
        transcript.append_message(b"enc", &ciphertext.inner.to_bytes());
        // NB: we don't add `admissible_values` to the transcript since we assume that
        // they are fixed in the higher-level protocol.
        transcript.append_u64(b"i", index as u64);

        // Choose a random scalar to use in the equation matching the known discrete log.
        let random_scalar = SecretKey::<G>::generate(rng);
        let mut commitments = (
            G::mul_generator(&random_scalar.0),
            log_base * &random_scalar.0,
        );

        // We create the entire response vector at once to prevent timing attack possibilities.
        let mut responses = smallvec![G::Scalar::from(0_u64); admissible_values.len()];

        let it = admissible_values.iter().enumerate().skip(value_index + 1);
        for (eq_index, &admissible_value) in it {
            let mut eq_transcript = transcript.clone();
            eq_transcript.append_u64(b"j", eq_index as u64 - 1);
            eq_transcript.append_element::<G>(b"R_G", &commitments.0);
            eq_transcript.append_element::<G>(b"R_K", &commitments.1);
            let challenge = eq_transcript.challenge_scalar::<G>(b"c");

            let response = G::generate_scalar(rng);
            responses[eq_index] = response;
            let dh_element = blinded_value - admissible_value;
            commitments = (
                G::mul_generator(&response) - random_element * &challenge,
                G::multi_mul(
                    [response, -challenge].iter(),
                    [log_base, dh_element].iter().copied(),
                ),
            );
        }

        Self {
            index,
            value_index,
            admissible_values,
            ciphertext: ciphertext.inner,
            transcript,
            responses,
            terminal_commitments: commitments,
            discrete_log: ciphertext.random_scalar,
            random_scalar,
        }
    }

    /// Completes the ring by calculating the common challenge and closing all rings using it.
    fn aggregate<R>(
        rings: Vec<Self>,
        log_base: G::Element,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> RingProof<G>
    where
        R: CryptoRng + RngCore,
    {
        debug_assert!(
            rings.iter().enumerate().all(|(i, ring)| i == ring.index),
            "Rings have bogus indexes"
        );

        for ring in &rings {
            let commitments = &ring.terminal_commitments;
            transcript.append_element::<G>(b"R_G", &commitments.0);
            transcript.append_element::<G>(b"R_K", &commitments.1);
        }

        let common_challenge = transcript.challenge_scalar::<G>(b"c");
        let mut proof = RingProof {
            common_challenge,
            ring_responses: Vec::with_capacity(rings.len()),
        };
        for ring in rings {
            proof
                .ring_responses
                .extend(ring.finalize(log_base, common_challenge, rng));
        }
        proof
    }

    fn finalize<R>(
        mut self,
        log_base: G::Element,
        common_challenge: G::Scalar,
        rng: &mut R,
    ) -> Vec<G::Scalar>
    where
        R: CryptoRng + RngCore,
    {
        // Compute remaining responses for non-reversible equations.
        let mut challenge = common_challenge;
        let it = self.admissible_values[..self.value_index]
            .iter()
            .enumerate();
        for (eq_index, &admissible_value) in it {
            let response = G::generate_scalar(rng);
            self.responses[eq_index] = response;
            let dh_element = self.ciphertext.blinded_element - admissible_value;
            let commitments = (
                G::mul_generator(&response) - self.ciphertext.random_element * &challenge,
                G::multi_mul(
                    [response, -challenge].iter(),
                    [log_base, dh_element].iter().copied(),
                ),
            );

            let mut eq_transcript = self.transcript.clone();
            eq_transcript.append_u64(b"j", eq_index as u64);
            eq_transcript.append_element::<G>(b"R_G", &commitments.0);
            eq_transcript.append_element::<G>(b"R_K", &commitments.1);
            challenge = eq_transcript.challenge_scalar::<G>(b"c");
        }

        // Finally, compute the response for equation #`value_index`, using our knowledge
        // of the trapdoor.
        debug_assert!(bool::from(
            self.responses[self.value_index].ct_eq(&G::Scalar::from(0_u64))
        ));
        self.responses[self.value_index] = self.random_scalar.0 + challenge * self.discrete_log.0;
        self.responses.to_vec()
    }
}

/// Zero-knowledge proof that the one or more encrypted values is each in the a priori known set of
/// admissible values. (Admissible values may differ among encrypted values.)
///
/// # Construction
///
/// In short, a proof is constructed almost identically to [Borromean ring signatures] by
/// Maxwell and Poelstra, with the only major difference being that we work on ElGamal ciphertexts
/// instead of group elements (= public keys).
///
/// A proof consists of one or more *rings*. Each ring proves than a certain
/// ElGamal ciphertext `E = (R, B)` for public key `K` in a group with generator `G`
/// encrypts one of distinct admissible values `x_0`, `x_1`, ..., `x_n`.
/// `K` and `G` are shared among rings, admissible values are generally not.
/// Different rings may have different number of admissible values.
///
/// ## Single ring
///
/// A ring is a challenge `e_0` and a set of responses `s_0`, `s_1`, ..., `s_n`, which
/// must satisfy the following verification procedure:
///
/// For each `j` in `0..=n`, compute
///
/// ```text
/// R_G(j) = [s_j]G - [e_j]R;
/// R_K(j) = [s_j]K - [e_j](B - [x_j]G);
/// e_{j+1} = H(j, R_G(j), R_K(j));
/// ```
///
/// Here, `H` is a cryptographic hash function. The ring is valid if `e_0 = e_{n+1}`.
///
/// This construction is almost identical to [Abe–Ohkubo–Suzuki ring signatures][ring],
/// with the only difference that two group elements are hashed on each iteration instead of one.
/// If admissible values consist of a single value, this protocol reduces to
/// [`LogEqualityProof`] / Chaum–Pedersen protocol.
///
/// As with "ordinary" ring signatures, constructing a ring is only feasible when knowing
/// additional *trapdoor information*. Namely, the prover must know
///
/// ```text
/// r = dlog_G(R) = dlog_K(B - [x_j]G)
/// ```
///
/// for a certain `j`. (This discrete log `r` is the random scalar used in ElGamal encryption.)
/// With this info, the prover constructs the ring as follows:
///
/// 1. Select random scalar `x` and compute `R_G(j) = [x]G`, `R_K(j) = [x]K`.
/// 2. Compute `e_{j+1}`, ... `e_n`, ..., `e_j` ("wrapping" around `e_0 = e_{n+1}`)
///   as per verification formulas. `s_*` scalars are selected uniformly at random.
/// 3. Compute `s_j` using the trapdoor information: `s_j = x + e_j * r`.
///
/// ## Multiple rings
///
/// Transformation to multiple rings is analogous to one in [Borromean ring signatures].
/// Namely, challenge `e_0` is shared among all rings and is computed by hashing
/// values of `R_G` and `R_K` with the maximum index for each of the rings.
///
/// # Applications
///
/// ## Voting protocols
///
/// [`EncryptedChoice`](crate::EncryptedChoice) uses `RingProof` to prove that all encrypted
/// values are Boolean (0 or 1). Using a common challenge allows to reduce proof size by ~33%.
///
/// ## Range proofs
///
/// Another application is a *range proof* for an ElGamal ciphertext: proving that an encrypted
/// value is in range `0..=n`, where `n` is a positive integer. To make the proof more compact,
/// the same trick can be used as for [Pedersen commitments] (used, e.g., for confidential
/// transaction amounts in [Elements]):
///
/// 1. Represent the value in base 2: `n = n_0 + n_1 * 2 + n_2 * 4 + ...`, where `n_i in {0, 1}`.
///   (Other bases are applicable as well.)
/// 2. Split the ciphertext correspondingly: `E = E_0 + E_1 + ...`, where `E_i` encrypts
///   `n_i * 2^i`. That is, `E_0` encrypts 0 or 1, `E_1` encrypts 0 or 2, `E_2` – 0 or 4, etc.
/// 3. Produce a `RingProof` that `E_i` is valid for all `i`.
///
/// As with "ordinary" range proofs, this construction is not optimal in terms of space
/// or proving / verification complexity for large ranges; it is linear w.r.t. the bit length
/// of the range. (Constructions like [Bulletproofs] are *logarithmic* w.r.t. the bit length.)
/// Still, it can be useful for small ranges.
///
/// # Implementation details
///
/// - The proof is serialized as the common challenge `e_0` followed by `s_i` scalars for
///   all the rings.
/// - Standalone proof generation and verification are not exposed in public crate APIs.
///   Rather, proofs are part of large protocols, such as [`PublicKey::encrypt_bool()`] /
///   [`PublicKey::verify_bool()`].
/// - The context of the proof is set using [`Transcript`] APIs, which provides hash functions
///   in the protocol described above. Importantly, the proof itself commits to encrypted values
///   and ring indexes, but not to the admissible values across the rings. This must be taken
///   care of in a higher-level protocol, and this is the case for protocols exposed by the crate.
///
/// [Pedersen commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
/// [Elements]: https://elementsproject.org/features/confidential-transactions/investigation
/// [Borromean ring signatures]: https://raw.githubusercontent.com/Blockstream/borromean_paper/master/borromean_draft_0.01_34241bb.pdf
/// [ring]: https://link.springer.com/content/pdf/10.1007/3-540-36178-2_26.pdf
/// [Bulletproofs]: https://crypto.stanford.edu/bulletproofs/
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
// TODO: range proof (think about base etc.)
pub struct RingProof<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ScalarHelper::<G>"))]
    common_challenge: G::Scalar,
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ScalarHelper<G>, 2>"))]
    ring_responses: Vec<G::Scalar>,
}

impl<G: Group> RingProof<G> {
    fn initialize_transcript(transcript: &mut Transcript, receiver: &PublicKey<G>) {
        transcript.start_proof(b"multi_ring_enc");
        transcript.append_element_bytes(b"K", &receiver.bytes);
    }

    pub(crate) fn verify(
        &self,
        receiver: &PublicKey<G>,
        admissible_values: &[&[G::Element]],
        ciphertexts: &[Ciphertext<G>],
        transcript: &mut Transcript,
    ) -> bool {
        // Do quick preliminary checks.
        assert_eq!(ciphertexts.len(), admissible_values.len());
        let total_rings_size: usize = admissible_values.iter().map(|values| values.len()).sum();
        if total_rings_size != self.total_rings_size() {
            return false;
        }

        Self::initialize_transcript(transcript, receiver);
        // We add common commitments to the `transcript` as we cycle through rings,
        // so we need a separate transcript copy to initialize ring transcripts.
        let initial_ring_transcript = transcript.clone();

        let it = admissible_values.iter().zip(ciphertexts).enumerate();
        let mut starting_response = 0;
        for (ring_index, (values, ciphertext)) in it {
            let mut challenge = self.common_challenge;
            let mut commitments = (G::generator(), G::generator());

            let mut ring_transcript = initial_ring_transcript.clone();
            ring_transcript.start_proof(b"ring_enc");
            ring_transcript.append_message(b"enc", &ciphertext.to_bytes());
            ring_transcript.append_u64(b"i", ring_index as u64);

            for (eq_index, (&admissible_value, response)) in values
                .iter()
                .zip(&self.ring_responses[starting_response..])
                .enumerate()
            {
                let dh_element = ciphertext.blinded_element - admissible_value;
                let neg_challenge = -challenge;

                commitments = (
                    G::vartime_double_mul_generator(
                        &neg_challenge,
                        ciphertext.random_element,
                        response,
                    ),
                    G::vartime_multi_mul(
                        [response, &neg_challenge].iter().copied(),
                        [receiver.element, dh_element].iter().copied(),
                    ),
                );

                // We can skip deriving the challenge for the last equation; it's not used anyway.
                if eq_index + 1 < values.len() {
                    let mut eq_transcript = ring_transcript.clone();
                    eq_transcript.append_u64(b"j", eq_index as u64);
                    eq_transcript.append_element::<G>(b"R_G", &commitments.0);
                    eq_transcript.append_element::<G>(b"R_K", &commitments.1);
                    challenge = eq_transcript.challenge_scalar::<G>(b"c");
                }
            }

            starting_response += values.len();
            transcript.append_element::<G>(b"R_G", &commitments.0);
            transcript.append_element::<G>(b"R_K", &commitments.1);
        }

        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        bool::from(expected_challenge.ct_eq(&self.common_challenge))
    }

    pub(crate) fn total_rings_size(&self) -> usize {
        self.ring_responses.len()
    }

    /// Serializes this proof into bytes. As described [above](#implementation-details),
    /// the proof is serialized as the common challenge `e_0` followed by response scalars `s_*`
    /// corresponding successively to each admissible value in each ring.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0_u8; G::SCALAR_SIZE * (1 + self.total_rings_size())];
        G::serialize_scalar(&self.common_challenge, &mut bytes[..G::SCALAR_SIZE]);

        let chunks = bytes[G::SCALAR_SIZE..].chunks_mut(G::SCALAR_SIZE);
        for (response, buffer) in self.ring_responses.iter().zip(chunks) {
            G::serialize_scalar(response, buffer);
        }
        bytes
    }

    /// Attempts to deserialize a proof from bytes. Returns `None` if `bytes` do not represent
    /// a well-formed proof.
    #[allow(clippy::missing_panics_doc)] // triggered by `debug_assert`
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() % G::SCALAR_SIZE != 0 || bytes.len() < 3 * G::SCALAR_SIZE {
            return None;
        }
        let common_challenge = G::deserialize_scalar(&bytes[..G::SCALAR_SIZE])?;

        let ring_responses: Option<Vec<_>> = bytes[G::SCALAR_SIZE..]
            .chunks(G::SCALAR_SIZE)
            .map(G::deserialize_scalar)
            .collect();
        let ring_responses = ring_responses?;
        debug_assert!(ring_responses.len() >= 2);

        Some(Self {
            common_challenge,
            ring_responses,
        })
    }
}

/// **NB.** Separate method calls of the builder depend on the position of the encrypted values
/// within admissible ones. This means that if a proof is constructed with interruptions between
/// method calls, there is a chance for an adversary to perform a timing attack.
#[doc(hidden)] // only public for benchmarking
pub struct RingProofBuilder<'a, G: Group, R> {
    receiver: &'a PublicKey<G>,
    transcript: &'a mut Transcript,
    rings: Vec<Ring<'a, G>>,
    rng: &'a mut R,
}

impl<G: Group, R: fmt::Debug> fmt::Debug for RingProofBuilder<'_, G, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RingProofBuilder")
            .field("receiver", self.receiver)
            .field("rings", &self.rings)
            .field("rng", self.rng)
            .finish()
    }
}

impl<'a, G: Group, R: RngCore + CryptoRng> RingProofBuilder<'a, G, R> {
    /// Starts building a [`RingProof`].
    pub fn new(receiver: &'a PublicKey<G>, transcript: &'a mut Transcript, rng: &'a mut R) -> Self {
        RingProof::<G>::initialize_transcript(transcript, receiver);
        Self {
            receiver,
            transcript,
            rings: vec![],
            rng,
        }
    }

    /// Adds a value among `admissible_values` as a new ring to this proof.
    pub fn add_value(
        &mut self,
        admissible_values: &'a [G::Element],
        value_index: usize,
    ) -> ExtendedCiphertext<G> {
        let ext_ciphertext =
            ExtendedCiphertext::new(admissible_values[value_index], self.receiver, self.rng);
        let ring = Ring::new(
            self.rings.len(),
            self.receiver.element,
            ext_ciphertext.clone(),
            admissible_values,
            value_index,
            &*self.transcript,
            self.rng,
        );
        self.rings.push(ring);
        ext_ciphertext
    }

    /// Finishes building a [`RingProof`].
    pub fn build(self) -> RingProof<G> {
        Ring::aggregate(self.rings, self.receiver.element, self.transcript, self.rng)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        ristretto::RistrettoPoint, scalar::Scalar as Scalar25519, traits::Identity,
    };
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::group::{ElementOps, Ristretto};

    type Keypair = crate::Keypair<Ristretto>;

    #[test]
    fn single_ring_with_2_elements_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values = [RistrettoPoint::identity(), Ristretto::generator()];

        let value = RistrettoPoint::identity();
        let ext_ciphertext = ExtendedCiphertext::new(value, keypair.public(), &mut rng);
        let ciphertext = ext_ciphertext.inner;

        let mut transcript = Transcript::new(b"test_ring_encryption");
        RingProof::initialize_transcript(&mut transcript, keypair.public());

        let signature_ring = Ring::new(
            0,
            keypair.public().element,
            ext_ciphertext,
            &admissible_values,
            0,
            &transcript,
            &mut rng,
        );
        let proof = Ring::aggregate(
            vec![signature_ring],
            keypair.public().element,
            &mut transcript,
            &mut rng,
        );

        let mut transcript = Transcript::new(b"test_ring_encryption");
        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values],
            &[ciphertext],
            &mut transcript
        ));

        // Check a proof for encryption of 1.
        let value = Ristretto::generator();
        let ext_ciphertext = ExtendedCiphertext::new(value, keypair.public(), &mut rng);
        let ciphertext = ext_ciphertext.inner;

        let mut transcript = Transcript::new(b"test_ring_encryption");
        RingProof::initialize_transcript(&mut transcript, keypair.public());
        let signature_ring = Ring::new(
            0,
            keypair.public().element,
            ext_ciphertext,
            &admissible_values,
            1,
            &transcript,
            &mut rng,
        );
        let proof = Ring::aggregate(
            vec![signature_ring],
            keypair.public().element,
            &mut transcript,
            &mut rng,
        );

        let mut transcript = Transcript::new(b"test_ring_encryption");
        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values],
            &[ciphertext],
            &mut transcript
        ));
    }

    #[test]
    fn single_ring_with_4_elements_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values: Vec<_> = (0_u32..4)
            .map(|i| Ristretto::mul_generator(&Scalar25519::from(i)))
            .collect();

        for _ in 0..100 {
            let val: u32 = rng.gen_range(0..4);
            let element_val = Ristretto::mul_generator(&Scalar25519::from(val));
            let ext_ciphertext = ExtendedCiphertext::new(element_val, keypair.public(), &mut rng);
            let ciphertext = ext_ciphertext.inner;

            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let signature_ring = Ring::new(
                0,
                keypair.public().element,
                ext_ciphertext,
                &admissible_values,
                val as usize,
                &transcript,
                &mut rng,
            );
            let proof = Ring::aggregate(
                vec![signature_ring],
                keypair.public().element,
                &mut transcript,
                &mut rng,
            );

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &[&admissible_values],
                &[ciphertext],
                &mut transcript
            ));
        }
    }

    #[test]
    fn multiple_rings_with_boolean_flags_work() {
        const RING_COUNT: usize = 5;

        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values = [RistrettoPoint::identity(), Ristretto::generator()];

        for _ in 0..20 {
            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let (ciphertexts, rings): (Vec<_>, Vec<_>) = (0..RING_COUNT)
                .map(|ring_index| {
                    let val = rng.gen_bool(0.5) as u32;
                    let element_val = Ristretto::mul_generator(&Scalar25519::from(val));
                    let ext_ciphertext =
                        ExtendedCiphertext::new(element_val, keypair.public(), &mut rng);
                    let ciphertext = ext_ciphertext.inner;

                    let signature_ring = Ring::new(
                        ring_index,
                        keypair.public().element,
                        ext_ciphertext,
                        &admissible_values,
                        val as usize,
                        &transcript,
                        &mut rng,
                    );

                    (ciphertext, signature_ring)
                })
                .unzip();

            let proof = Ring::aggregate(rings, keypair.public().element, &mut transcript, &mut rng);

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &[&admissible_values as &[_]; RING_COUNT],
                &ciphertexts,
                &mut transcript,
            ));
        }
    }

    #[test]
    fn multiple_rings_with_base4_value_encoding_work() {
        // We're testing ciphertexts of `u8` integers, hence 4 rings with 4 elements (=2 bits) each.
        const RING_COUNT: u8 = 4;

        // Admissible values are `[O, G, [2]G, [3]G]` for the first ring,
        // `[O, [4]G, [8]G, [12]G]` for the second ring, etc.
        let admissible_values: Vec<_> = (0..RING_COUNT)
            .map(|ring_index| {
                let power: u32 = 1 << (2 * u32::from(ring_index));
                [
                    RistrettoPoint::identity(),
                    Ristretto::mul_generator(&Scalar25519::from(power)),
                    Ristretto::mul_generator(&Scalar25519::from(power * 2)),
                    Ristretto::mul_generator(&Scalar25519::from(power * 3)),
                ]
            })
            .collect();

        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        for _ in 0..20 {
            let overall_value: u8 = rng.gen();
            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let (ciphertexts, rings): (Vec<_>, Vec<_>) = (0..RING_COUNT)
                .map(|ring_index| {
                    let mask = 3 << (2 * ring_index);
                    let val = overall_value & mask;
                    let val_index = (val >> (2 * ring_index)) as usize;
                    assert!(val_index < 4);

                    let element_val = Ristretto::mul_generator(&Scalar25519::from(val));
                    let ext_ciphertext =
                        ExtendedCiphertext::new(element_val, keypair.public(), &mut rng);
                    let ciphertext = ext_ciphertext.inner;

                    let ring_index = usize::from(ring_index);
                    let signature_ring = Ring::new(
                        ring_index,
                        keypair.public().element,
                        ext_ciphertext,
                        &admissible_values[ring_index],
                        val_index,
                        &transcript,
                        &mut rng,
                    );

                    (ciphertext, signature_ring)
                })
                .unzip();

            let proof = Ring::aggregate(rings, keypair.public().element, &mut transcript, &mut rng);
            let admissible_values: Vec<_> = admissible_values
                .iter()
                .map(|values| values as &[_])
                .collect();

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &admissible_values,
                &ciphertexts,
                &mut transcript
            ));
        }
    }

    #[test]
    fn proof_builder_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let mut transcript = Transcript::new(b"test_ring_encryption");
        let admissible_values = [RistrettoPoint::identity(), Ristretto::generator()];

        let mut builder = RingProofBuilder::new(keypair.public(), &mut transcript, &mut rng);
        let ciphertexts: Vec<_> = (0..5)
            .map(|i| builder.add_value(&admissible_values, i & 1).inner)
            .collect();
        let proof = builder.build();

        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values as &[_]; 5],
            &ciphertexts,
            &mut Transcript::new(b"test_ring_encryption"),
        ));
    }
}
