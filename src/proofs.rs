//! Zero-knowledge proofs.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use smallvec::{smallvec, SmallVec};
use subtle::ConstantTimeEq;

use crate::group::{Group, PublicKey, SecretKey, SECRET_KEY_SIZE};
use crate::{Encryption, EncryptionWithLog};

/// Extension trait for Merlin transcripts used in constructing our proofs.
pub(crate) trait TranscriptForGroup {
    fn start_proof(&mut self, proof_label: &'static [u8]);

    fn append_compressed_point<G: Group>(
        &mut self,
        label: &'static [u8],
        point: &G::CompressedPoint,
    );

    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G::Point);

    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar;
}

impl TranscriptForGroup for Transcript {
    fn start_proof(&mut self, proof_label: &'static [u8]) {
        self.append_message(b"dom-sep", proof_label);
    }

    fn append_compressed_point<G: Group>(
        &mut self,
        label: &'static [u8],
        point: &G::CompressedPoint,
    ) {
        self.append_message(label, &G::serialize_point(point));
    }

    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G::Point) {
        self.append_compressed_point::<G>(label, &G::compress(point));
    }

    fn challenge_scalar<G: Group>(&mut self, label: &'static [u8]) -> G::Scalar {
        let mut buf = [0_u8; 64];
        self.challenge_bytes(label, &mut buf);
        G::scalar_from_random_bytes(buf)
    }
}

/// Proof of possession of several secret scalars.
///
/// # Construction
///
/// The proof is a generalization of the standard Schnorr protocol for proving knowledge
/// of a discrete log. The difference with the combination of several concurrent Schnorr
/// protocol instances is that the challenge is shared among all instances (which yields a
/// ~2x proof size reduction).
#[derive(Clone)]
pub struct ProofOfPossession<G: Group> {
    challenge: G::Scalar,
    responses: Vec<G::Scalar>,
}

impl<G: Group> ProofOfPossession<G> {
    pub fn new<R>(
        secrets: &[SecretKey<G>],
        public_keys: &[PublicKey<G>],
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        transcript.start_proof(b"multi_pop");
        for public_key in public_keys {
            transcript.append_compressed_point::<G>(b"K", &public_key.compressed);
        }

        let mut random_scalars: Vec<_> = (0..secrets.len())
            .map(|_| {
                let random_scalar = SecretKey::<G>::generate(rng);
                let random_point = G::scalar_mul_basepoint(&random_scalar.0);
                transcript.append_point::<G>(b"R", &random_point);
                random_scalar
            })
            .collect();

        let challenge = transcript.challenge_scalar::<G>(b"c");
        for (secret, response) in secrets.iter().zip(&mut random_scalars) {
            *response += secret.clone() * challenge;
        }

        Self {
            challenge,
            responses: random_scalars.into_iter().map(|scalar| scalar.0).collect(),
        }
    }

    pub fn verify(&self, public_keys: &[PublicKey<G>], transcript: &mut Transcript) -> bool {
        if self.responses.len() != public_keys.len() {
            return false;
        }

        transcript.start_proof(b"multi_pop");
        for public_key in public_keys {
            transcript.append_compressed_point::<G>(b"K", &public_key.compressed);
        }

        for (public_key, &response) in public_keys.iter().zip(&self.responses) {
            let random_point =
                G::vartime_double_scalar_mul_basepoint(-self.challenge, public_key.full, response);
            transcript.append_point::<G>(b"R", &random_point);
        }

        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        expected_challenge == self.challenge
    }
}

/// Zero-knowledge proof of equality of two discrete logarithms in different bases,
/// aka Chaum - Pedersen protocol.
///
/// # Implementation details
///
/// This proof is a result of the [Fiat – Shamir transform][fst] applied to a standard
/// ZKP of equality of the two discrete logs in different bases.
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
/// In the non-interactive version of the proof, `c` is derived from `hash(M)`,
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
/// - The context of the proof (i.e., `M`) is set via [`Transcript`] API.
///
/// [fst]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [this course]: http://www.cs.au.dk/~ivan/Sigma.pdf
/// [serialized encryption]: struct.Encrypted.html#method.to_bytes
/// [`EncryptedChoice`]: struct.EncryptedChoice.html
/// [`DecryptionShare`]: shared/struct.DecryptionShare.html
#[derive(Debug, Clone, Copy)]
pub struct LogEqualityProof<G: Group> {
    challenge: G::Scalar,
    response: G::Scalar,
}

/// Size of a serialized `LogEqualityProof` (64 bytes).
pub const LOG_EQ_PROOF_SIZE: usize = 2 * SECRET_KEY_SIZE;

impl<G: Group> LogEqualityProof<G> {
    pub(crate) fn new<R>(
        log_base: PublicKey<G>,
        powers: (G::Point, G::Point),
        secret: &G::Scalar,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        transcript.start_proof(b"log_eq");
        transcript.append_compressed_point::<G>(b"K", &log_base.compressed);
        transcript.append_point::<G>(b"[x]G", &powers.0);
        transcript.append_point::<G>(b"[x]K", &powers.1);

        let random_scalar = SecretKey::<G>::generate(rng);
        transcript.append_point::<G>(b"[r]G", &G::scalar_mul_basepoint(&random_scalar.0));
        transcript.append_point::<G>(b"[r]K", &(log_base.full * &random_scalar.0));
        let challenge = transcript.challenge_scalar::<G>(b"c");
        let response = random_scalar.0 + challenge * (*secret);

        Self {
            challenge,
            response,
        }
    }

    /// Attempts to parse the proof from `bytes`. Parsing will fail if the proof components
    /// (specifically, the response scalar `s`) do not have the canonical form.
    pub fn from_bytes(bytes: [u8; LOG_EQ_PROOF_SIZE]) -> Option<Self> {
        let mut challenge_bytes = [0_u8; SECRET_KEY_SIZE];
        challenge_bytes.copy_from_slice(&bytes[..SECRET_KEY_SIZE]);
        let challenge = G::deserialize_scalar(challenge_bytes)?;
        let mut response_bytes = [0_u8; SECRET_KEY_SIZE];
        response_bytes.copy_from_slice(&bytes[SECRET_KEY_SIZE..]);
        let response = G::deserialize_scalar(response_bytes)?;

        Some(Self {
            challenge,
            response,
        })
    }

    /// Verifies this proof against a given encryption and its intended receiver.
    pub(crate) fn verify(
        &self,
        log_base: PublicKey<G>,
        powers: (G::Point, G::Point),
        transcript: &mut Transcript,
    ) -> bool {
        let commitments = (
            G::vartime_double_scalar_mul_basepoint(-self.challenge, powers.0, self.response),
            G::vartime_multiscalar_mul(
                [-self.challenge, self.response].iter().cloned(),
                [powers.1, log_base.full].iter().cloned(),
            ),
        );

        transcript.start_proof(b"log_eq");
        transcript.append_compressed_point::<G>(b"K", &log_base.compressed);
        transcript.append_point::<G>(b"[x]G", &powers.0);
        transcript.append_point::<G>(b"[x]K", &powers.1);
        transcript.append_point::<G>(b"[r]G", &commitments.0);
        transcript.append_point::<G>(b"[r]K", &commitments.1);
        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        expected_challenge == self.challenge
    }

    /// Serializes this proof into bytes.
    pub fn to_bytes(&self) -> [u8; LOG_EQ_PROOF_SIZE] {
        let mut bytes = [0_u8; LOG_EQ_PROOF_SIZE];
        let challenge_bytes = G::serialize_scalar(&self.challenge);
        bytes[..SECRET_KEY_SIZE].copy_from_slice(&challenge_bytes);
        let response_bytes = G::serialize_scalar(&self.response);
        bytes[SECRET_KEY_SIZE..].copy_from_slice(&response_bytes);
        bytes
    }
}

/// An incomplete ring proving that the encrypted value is in the a priori known set of
/// admissible values.
struct Ring<'a, G: Group> {
    // Public parameters of the ring.
    index: usize,
    admissible_values: &'a [G::Point],
    encryption: Encryption<G>,

    // ZKP-related public values.
    transcript: Transcript,
    responses: SmallVec<[G::Scalar; 4]>,
    terminal_commitments: (G::Point, G::Point),

    // Secret values.
    value_index: usize,
    discrete_log: SecretKey<G>,
    random_scalar: SecretKey<G>,
}

impl<'a, G: Group> Ring<'a, G> {
    fn new<R>(
        index: usize,
        log_base: PublicKey<G>,
        encryption_with_log: EncryptionWithLog<G>,
        admissible_values: &'a [G::Point],
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

        let random_point = encryption_with_log.encryption.random_point;
        let blinded_value = encryption_with_log.encryption.blinded_point;
        debug_assert!(
            {
                let expected_blinded_value = log_base.full * &encryption_with_log.discrete_log.0
                    + admissible_values[value_index];
                expected_blinded_value.ct_eq(&blinded_value).unwrap_u8() == 1
            },
            "Specified encryption does not match the specified `value_index`"
        );

        let mut transcript = transcript.clone();
        transcript.start_proof(b"ring_enc");
        transcript.append_message(b"enc", &encryption_with_log.encryption.to_bytes()[..]);
        // NB: we don't add `admissible_values` to the transcript since we assume that
        // they are fixed in the higher-level protocol.
        transcript.append_u64(b"i", index as u64);

        // Choose a random scalar to use in the equation matching the known discrete log.
        let random_scalar = SecretKey::<G>::generate(rng);
        let mut commitments = (
            G::scalar_mul_basepoint(&random_scalar.0),
            log_base.full * &random_scalar.0,
        );

        // We create the entire response vector at once to prevent timing attack possibilities.
        let mut responses = smallvec![G::Scalar::from(0_u64); admissible_values.len()];

        let it = admissible_values.iter().enumerate().skip(value_index + 1);
        for (eq_index, &admissible_value) in it {
            let mut eq_transcript = transcript.clone();
            eq_transcript.append_u64(b"j", eq_index as u64 - 1);
            eq_transcript.append_point::<G>(b"R_G", &commitments.0);
            eq_transcript.append_point::<G>(b"R_K", &commitments.1);
            let challenge = eq_transcript.challenge_scalar::<G>(b"c");

            let response = G::generate_scalar(rng);
            responses[eq_index] = response;
            let dh_point = blinded_value - admissible_value;
            commitments = (
                G::scalar_mul_basepoint(&response) - random_point * &challenge,
                G::multiscalar_mul(
                    [response, -challenge].iter(),
                    [log_base.full, dh_point].iter().cloned(),
                ),
            );
        }

        Self {
            index,
            value_index,
            admissible_values,
            encryption: encryption_with_log.encryption,
            transcript,
            responses,
            terminal_commitments: commitments,
            discrete_log: encryption_with_log.discrete_log,
            random_scalar,
        }
    }

    /// Completes the ring by calculating the common challenge and closing all rings using it.
    fn aggregate<R>(
        rings: Vec<Self>,
        log_base: PublicKey<G>,
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
            transcript.append_point::<G>(b"R_G", &commitments.0);
            transcript.append_point::<G>(b"R_K", &commitments.1);
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
        log_base: PublicKey<G>,
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
            let dh_point = self.encryption.blinded_point - admissible_value;
            let commitments = (
                G::scalar_mul_basepoint(&response) - self.encryption.random_point * &challenge,
                G::multiscalar_mul(
                    [response, -challenge].iter(),
                    [log_base.full, dh_point].iter().cloned(),
                ),
            );

            let mut eq_transcript = self.transcript.clone();
            eq_transcript.append_u64(b"j", eq_index as u64);
            eq_transcript.append_point::<G>(b"R_G", &commitments.0);
            eq_transcript.append_point::<G>(b"R_K", &commitments.1);
            challenge = eq_transcript.challenge_scalar::<G>(b"c");
        }

        // Finally, compute the response for equation #`value_index`, using our knowledge
        // of the trapdoor.
        debug_assert!(self.responses[self.value_index] == G::Scalar::from(0_u64));
        self.responses[self.value_index] = self.random_scalar.0 + challenge * self.discrete_log.0;
        self.responses.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct RingProof<G: Group> {
    common_challenge: G::Scalar,
    ring_responses: Vec<G::Scalar>,
}

impl<G: Group> RingProof<G> {
    fn initialize_transcript(transcript: &mut Transcript, receiver: PublicKey<G>) {
        transcript.start_proof(b"multi_ring_enc");
        transcript.append_compressed_point::<G>(b"K", &receiver.compressed);
    }

    pub(crate) fn verify(
        &self,
        receiver: PublicKey<G>,
        admissible_values: &[&[G::Point]],
        encryptions: &[Encryption<G>],
        transcript: &mut Transcript,
    ) -> bool {
        // Do quick preliminary checks.
        assert_eq!(encryptions.len(), admissible_values.len());
        let total_rings_size: usize = admissible_values.iter().map(|values| values.len()).sum();
        if total_rings_size != self.total_rings_size() {
            return false;
        }

        Self::initialize_transcript(transcript, receiver);
        // We add common commitments to the `transcript` as we cycle through rings,
        // so we need a separate transcript copy to initialize ring transcripts.
        let initial_ring_transcript = transcript.clone();

        let it = admissible_values.iter().zip(encryptions).enumerate();
        let mut starting_response = 0;
        for (ring_index, (values, encryption)) in it {
            let mut challenge = self.common_challenge;
            let mut commitments = (G::BASE_POINT, G::BASE_POINT);

            let mut ring_transcript = initial_ring_transcript.clone();
            ring_transcript.start_proof(b"ring_enc");
            ring_transcript.append_message(b"enc", &encryption.to_bytes()[..]);
            ring_transcript.append_u64(b"i", ring_index as u64);

            for (eq_index, (&admissible_value, response)) in values
                .iter()
                .zip(&self.ring_responses[starting_response..])
                .enumerate()
            {
                let dh_point = encryption.blinded_point - admissible_value;
                commitments = (
                    G::vartime_double_scalar_mul_basepoint(
                        -challenge,
                        encryption.random_point,
                        *response,
                    ),
                    G::vartime_multiscalar_mul(
                        [*response, -challenge].iter().cloned(),
                        [receiver.full, dh_point].iter().cloned(),
                    ),
                );

                // We can skip deriving the challenge for the last equation; it's not used anyway.
                if eq_index + 1 < values.len() {
                    let mut eq_transcript = ring_transcript.clone();
                    eq_transcript.append_u64(b"j", eq_index as u64);
                    eq_transcript.append_point::<G>(b"R_G", &commitments.0);
                    eq_transcript.append_point::<G>(b"R_K", &commitments.1);
                    challenge = eq_transcript.challenge_scalar::<G>(b"c");
                }
            }

            starting_response += values.len();
            transcript.append_point::<G>(b"R_G", &commitments.0);
            transcript.append_point::<G>(b"R_K", &commitments.1);
        }

        let expected_challenge = transcript.challenge_scalar::<G>(b"c");
        expected_challenge == self.common_challenge
    }

    pub fn total_rings_size(&self) -> usize {
        self.ring_responses.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SECRET_KEY_SIZE * (1 + self.total_rings_size()));
        bytes.extend_from_slice(&G::serialize_scalar(&self.common_challenge));
        for response in &self.ring_responses {
            bytes.extend_from_slice(&G::serialize_scalar(response));
        }
        bytes
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() % SECRET_KEY_SIZE != 0 || bytes.len() < 3 * SECRET_KEY_SIZE {
            return None;
        }
        let mut scalar_bytes = [0_u8; SECRET_KEY_SIZE];
        scalar_bytes.copy_from_slice(&bytes[..SECRET_KEY_SIZE]);
        let common_challenge = G::deserialize_scalar(scalar_bytes)?;

        let ring_responses: Option<Vec<_>> = bytes[SECRET_KEY_SIZE..]
            .chunks(SECRET_KEY_SIZE)
            .map(|scalar_slice| {
                scalar_bytes.copy_from_slice(&scalar_slice);
                G::deserialize_scalar(scalar_bytes)
            })
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
pub struct RingProofBuilder<'a, G: Group, R> {
    receiver: PublicKey<G>,
    transcript: &'a mut Transcript,
    rings: Vec<Ring<'a, G>>,
    rng: &'a mut R,
}

impl<'a, G: Group, R: RngCore + CryptoRng> RingProofBuilder<'a, G, R> {
    pub fn new(receiver: PublicKey<G>, transcript: &'a mut Transcript, rng: &'a mut R) -> Self {
        RingProof::<G>::initialize_transcript(transcript, receiver);
        Self {
            receiver,
            transcript,
            rings: vec![],
            rng,
        }
    }

    pub fn add_value(
        &mut self,
        admissible_values: &'a [G::Point],
        value_index: usize,
    ) -> EncryptionWithLog<G> {
        let encryption_with_log =
            EncryptionWithLog::new(admissible_values[value_index], self.receiver, self.rng);
        let ring = Ring::new(
            self.rings.len(),
            self.receiver,
            encryption_with_log.clone(),
            admissible_values,
            value_index,
            &*self.transcript,
            self.rng,
        );
        self.rings.push(ring);
        encryption_with_log
    }

    pub fn build(self) -> RingProof<G> {
        Ring::aggregate(self.rings, self.receiver, self.transcript, self.rng)
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{
        edwards::EdwardsPoint, scalar::Scalar as Scalar25519, traits::Identity,
    };
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::{
        group::{PointOps, ScalarOps},
        Edwards,
    };

    type Keypair = crate::Keypair<Edwards>;

    #[test]
    fn proof_of_possession_basics() {
        let mut rng = thread_rng();
        let (poly_secrets, poly): (Vec<_>, Vec<_>) = (0..5)
            .map(|_| {
                let keypair = Keypair::generate(&mut rng);
                (keypair.secret().clone(), keypair.public())
            })
            .unzip();

        let proof = ProofOfPossession::new(
            &poly_secrets,
            &poly,
            &mut Transcript::new(b"test_multi_PoP"),
            &mut rng,
        );
        assert!(proof.verify(&poly, &mut Transcript::new(b"test_multi_PoP")));
    }

    #[test]
    fn log_equality_basics() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        for _ in 0..100 {
            let secret = Edwards::generate_scalar(&mut rng);
            let basepoint_val = Edwards::scalar_mul_basepoint(&secret);
            let key_val = keypair.public().full * secret;
            let proof = LogEqualityProof::new(
                keypair.public(),
                (basepoint_val, key_val),
                &secret,
                &mut Transcript::new(b"testing_log_equality"),
                &mut rng,
            );
            assert!(proof.verify(
                keypair.public(),
                (basepoint_val, key_val),
                &mut Transcript::new(b"testing_log_equality")
            ));
        }
    }

    #[test]
    fn single_ring_with_2_elements_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values = [EdwardsPoint::identity(), Edwards::BASE_POINT];

        let value = EdwardsPoint::identity();
        let encryption_with_log = EncryptionWithLog::new(value, keypair.public(), &mut rng);
        let encryption = encryption_with_log.encryption;

        let mut transcript = Transcript::new(b"test_ring_encryption");
        RingProof::initialize_transcript(&mut transcript, keypair.public());

        let ring = Ring::new(
            0,
            keypair.public(),
            encryption_with_log,
            &admissible_values,
            0,
            &transcript,
            &mut rng,
        );
        let proof = Ring::aggregate(vec![ring], keypair.public(), &mut transcript, &mut rng);

        let mut transcript = Transcript::new(b"test_ring_encryption");
        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values],
            &[encryption],
            &mut transcript
        ));

        // Check a proof for the encryption of 1.
        let value = Edwards::BASE_POINT;
        let encryption_with_log = EncryptionWithLog::new(value, keypair.public(), &mut rng);
        let encryption = encryption_with_log.encryption;

        let mut transcript = Transcript::new(b"test_ring_encryption");
        RingProof::initialize_transcript(&mut transcript, keypair.public());
        let ring = Ring::new(
            0,
            keypair.public(),
            encryption_with_log,
            &admissible_values,
            1,
            &transcript,
            &mut rng,
        );
        let proof = Ring::aggregate(vec![ring], keypair.public(), &mut transcript, &mut rng);

        let mut transcript = Transcript::new(b"test_ring_encryption");
        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values],
            &[encryption],
            &mut transcript
        ));
    }

    #[test]
    fn single_ring_with_4_elements_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values: Vec<_> = (0_u32..4)
            .map(|i| Edwards::scalar_mul_basepoint(&Scalar25519::from(i)))
            .collect();

        for _ in 0..100 {
            let val: u32 = rng.gen_range(0, 4);
            let value_point = Edwards::scalar_mul_basepoint(&Scalar25519::from(val));
            let encryption_with_log =
                EncryptionWithLog::new(value_point, keypair.public(), &mut rng);
            let encryption = encryption_with_log.encryption;

            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let ring = Ring::new(
                0,
                keypair.public(),
                encryption_with_log,
                &admissible_values,
                val as usize,
                &transcript,
                &mut rng,
            );
            let proof = Ring::aggregate(vec![ring], keypair.public(), &mut transcript, &mut rng);

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &[&admissible_values],
                &[encryption],
                &mut transcript
            ));
        }
    }

    #[test]
    fn multiple_rings_with_boolean_flags_work() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let admissible_values = [EdwardsPoint::identity(), Edwards::BASE_POINT];

        const RING_COUNT: usize = 5;

        for _ in 0..20 {
            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let (encryptions, rings): (Vec<_>, Vec<_>) = (0..RING_COUNT)
                .map(|ring_index| {
                    let val = rng.gen_bool(0.5) as u32;
                    let value_point = Edwards::scalar_mul_basepoint(&Scalar25519::from(val));
                    let encryption_with_log =
                        EncryptionWithLog::new(value_point, keypair.public(), &mut rng);
                    let encryption = encryption_with_log.encryption;

                    let ring = Ring::new(
                        ring_index,
                        keypair.public(),
                        encryption_with_log,
                        &admissible_values,
                        val as usize,
                        &transcript,
                        &mut rng,
                    );

                    (encryption, ring)
                })
                .unzip();

            let proof = Ring::aggregate(rings, keypair.public(), &mut transcript, &mut rng);

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &[&admissible_values as &[_]; RING_COUNT],
                &encryptions,
                &mut transcript,
            ));
        }
    }

    #[test]
    fn multiple_rings_with_base4_value_encoding_work() {
        // We're testing encryptions of `u8` integers, hence 4 rings with 4 elements (=2 bits) each.
        const RING_COUNT: usize = 4;

        // Admissible values are `[O, G, [2]G, [3]G]` for the first ring,
        // `[O, [4]G, [8]G, [12]G]` for the second ring, etc.
        let admissible_values: Vec<_> = (0..RING_COUNT)
            .map(|ring_index| {
                let power: u32 = 1 << (2 * ring_index as u32);
                [
                    EdwardsPoint::identity(),
                    Edwards::scalar_mul_basepoint(&Scalar25519::from(power)),
                    Edwards::scalar_mul_basepoint(&Scalar25519::from(power * 2)),
                    Edwards::scalar_mul_basepoint(&Scalar25519::from(power * 3)),
                ]
            })
            .collect();

        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);

        for _ in 0..20 {
            let overall_value: u8 = rng.gen();
            let mut transcript = Transcript::new(b"test_ring_encryption");
            RingProof::initialize_transcript(&mut transcript, keypair.public());

            let (encryptions, rings): (Vec<_>, Vec<_>) = (0..RING_COUNT)
                .map(|ring_index| {
                    let mask = 3 << (2 * ring_index as u8);
                    let val = overall_value & mask;
                    let val_index = (val >> (2 * ring_index as u8)) as usize;
                    assert!(val_index < 4);

                    let value_point = Edwards::scalar_mul_basepoint(&Scalar25519::from(val));
                    let encryption_with_log =
                        EncryptionWithLog::new(value_point, keypair.public(), &mut rng);
                    let encryption = encryption_with_log.encryption;

                    let ring = Ring::new(
                        ring_index,
                        keypair.public(),
                        encryption_with_log,
                        &admissible_values[ring_index],
                        val_index,
                        &transcript,
                        &mut rng,
                    );

                    (encryption, ring)
                })
                .unzip();

            let proof = Ring::aggregate(rings, keypair.public(), &mut transcript, &mut rng);
            let admissible_values: Vec<_> = admissible_values
                .iter()
                .map(|values| values as &[_])
                .collect();

            let mut transcript = Transcript::new(b"test_ring_encryption");
            assert!(proof.verify(
                keypair.public(),
                &admissible_values,
                &encryptions,
                &mut transcript
            ));
        }
    }

    #[test]
    fn proof_builder_works() {
        let mut rng = thread_rng();
        let keypair = Keypair::generate(&mut rng);
        let mut transcript = Transcript::new(b"test_ring_encryption");
        let admissible_values = [EdwardsPoint::identity(), Edwards::BASE_POINT];

        let mut builder = RingProofBuilder::new(keypair.public(), &mut transcript, &mut rng);
        let encryptions: Vec<_> = (0..5)
            .map(|i| builder.add_value(&admissible_values, i & 1).unwrap())
            .collect();
        let proof = builder.build();

        assert!(proof.verify(
            keypair.public(),
            &[&admissible_values as &[_]; 5],
            &encryptions,
            &mut Transcript::new(b"test_ring_encryption"),
        ));
    }
}
