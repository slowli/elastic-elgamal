//! Shamir's secret sharing for ElGamal encryption.
//!
//! # Problem
//!
//! We want to instantiate `(n, t)` threshold encryption scheme, i.e., a scheme with
//! `n` participants, each `t + 1` of which (but not less!) can jointly decrypt any ciphertext
//! encrypted under the joint public key `K`.
//!
//! Assumptions:
//!
//! - There is a secure broadcast among participants, which acts as a single source of truth.
//!  (E.g., a blockchain.) The broadcast is synchronous w.r.t. the protocol steps (in practice,
//!  this means that protocol steps take sufficiently long amount of time).
//!
//! # Distributed key generation
//!
//! **1.** Each participant in the `(n, t)` scheme generates a polynomial of degree `t`
//! with random scalar coefficients:
//!
//! ```text
//! P_i(x) = a_i0 + a_i1 * x + ... + a_it * x^t,
//! ```
//!
//! where `1 <= i <= n` is the participant's index.
//!
//! Each participant then broadcasts the EC points corresponding
//! to her coefficients:
//!
//! ```text
//! Q_i(x) = [a_i0]G + [x][a_i1]G + ... + [x^t][a_it]G,
//! ```
//!
//! together with a zero-knowledge proof of possession of `a_i0`, ..., `a_it`.
//!
//! At this point, all participants know the joint polynomial equal to the sum
//!
//! ```text
//! Q(x) = Q_1(x) + Q_2(x) + ... + Q_n(x),
//! ```
//!
//! with the shared public key `K = Q(0)` and the participant key shares `K_i = Q(i)`.
//! (Secret key `x` corresponding to `K` is not known by any single entity.)
//! Each participant now needs a secret key `x_i` corresponding to her share, `[x_i]G = K_i`.
//!
//! **2.** To obtain `x_i`, every participant `i` sends to every participant `j != i`
//! a scalar value `P_i(j)` via the corresponding peer channel.
//! The participant can verify incoming messages by checking
//! `[P_i(j)]G ?= Q_i(j)`.
//!
//! **3.** Once all messages are exchanged, the participant computes
//!
//! ```text
//! x_j = P_1(j) + P_2(j) + ... + P_n(j).
//! ```
//!
//! If at any step any participant deviates from the protocol, the protocol **MUST** be aborted.
//! Indeed, [Gennaro et al.] show that the protocol with "fault tolerance"
//! allows an adversary to influence the distribution of the shared secret `x`.
//!
//! ## Accountability during key generation
//!
//! Fault attribution can be built into the protocol in the following way:
//!
//! - Replace P2P channels with broadcast + asymmetric encryption (such as libsodium's `box`).
//!   The participants choose encryption keypairs at the protocol
//!   start and destroy their secrets once the protocol is finished.
//! - If a participant does not publish a polynomial `Q_i` at step 1, they are at fault.
//! - If a participant does not send a message to any other participant during step 2,
//!   they are at fault.
//! - If the sent share is incorrect, the receiving participant must publish an incorrectness proof
//!   (i.e., a proof of decryption). In this case, the message sender is at fault.
//! - If the participant has received all messages and did not publish incorrectness proofs,
//!   we assume that the participant should have `x_i` restored. We may demand a corresponding
//!   proof of possession; if the participant does not publish such a proof, they are at fault.
//!
//! If there are any faulting participants during protocol execution
//! the protocol starts anew (presumably, after punishing the faulting participants and excluding
//! them from further protocol runs). We may tolerate up to `t` faults at the last stage
//! (or not demand proof of possession at all); at this stage,
//! the shared secret `x` is already fixed, hence the attack from [Gennaro et al.]
//! is no longer feasible.
//!
//! # Verifiable decryption
//!
//! Assume `(R, B) = ([r]G, [m]G + [r]K)` is an encryption of scalar `m` for the shared key `K`.
//! In order to decrypt it, participants perform Diffie - Hellman exchange with the random part
//! of the encryption: `D_i = [x_i]R`. Validity of this *decryption share* can be verified
//! via a ZKP of discrete log equality:
//!
//! ```text
//! x_i = dlog_G(K_i) = dlog_R(D_i).
//! ```
//!
//! Given any `t + 1` decryption shares, it is possible to restore `D = [x]R` using Lagrange
//! interpolation. (Indeed, `D_i` are tied to `D` by the same relations as key shares `x_i`
//! are to `x`.) Once we have `D`, the encrypted value is restored as `[m]G = B - D`.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    slice,
};

use crate::{
    proofs::{LogEqualityProof, ProofOfPossession, TranscriptForGroup},
    Encryption, Group, Keypair, PublicKey, SecretKey,
};

/// Computes value of EC polynomial at the specified point in variable time.
fn polynomial_value<G: Group>(coefficients: &[G::Point], x: G::Scalar) -> G::Point {
    let mut val = G::Scalar::from(1_u64);
    let scalars: Vec<_> = (0..coefficients.len())
        .map(|_| {
            let output = val;
            val = val * x;
            output
        })
        .collect();

    G::vartime_multiscalar_mul(&scalars, coefficients.iter().copied())
}

/// Computes multipliers for the Lagrange polynomial interpolation based on the function value
/// at the given points. The indexes are zero-based, hence points are determined as
/// `indexes.iter().map(|&i| i + 1)`.
///
/// The returned scalars need to be additionally scaled by the common multiplier, equal
/// to the product of all points, which is returned as the second value.
fn lagrange_coefficients<G: Group>(indexes: &[usize]) -> (Vec<G::Scalar>, G::Scalar) {
    // `false` corresponds to positive sign, `true` to negative. This is in order
    // to make XOR work as expected.

    let mut denominators: Vec<_> = indexes
        .iter()
        .map(|&index| {
            let (sign, denominator) = indexes
                .iter()
                .map(|&other_index| match index.cmp(&other_index) {
                    Ordering::Greater => (true, G::Scalar::from((index - other_index) as u64)),
                    Ordering::Less => (false, G::Scalar::from((other_index - index) as u64)),
                    Ordering::Equal => (false, G::Scalar::from(index as u64 + 1)),
                })
                .fold(
                    (false, G::Scalar::from(1)),
                    |(sign, magnitude), (elem_sign, elem_magnitude)| {
                        (sign ^ elem_sign, magnitude * elem_magnitude)
                    },
                );

            if sign {
                -denominator
            } else {
                denominator
            }
        })
        .collect();
    G::invert_scalars(&mut denominators);

    let scale = indexes
        .iter()
        .map(|&index| G::Scalar::from(index as u64 + 1))
        .fold(G::Scalar::from(1), |acc, value| acc * value);
    (denominators, scale)
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    MalformedParticipantPolynomial,
    InvalidSecret,
    InvalidProofOfPossession,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    pub shares: usize,
    pub threshold: usize,
}

impl Params {
    pub fn new(shares: usize, threshold: usize) -> Self {
        assert!(shares > 0);
        assert!(threshold > 0 && threshold <= shares);
        Self { shares, threshold }
    }
}

/// In-progress information about the participants of a shared ElGamal encryption scheme.
pub struct PartialPublicKeySet<G: Group> {
    params: Params,
    received_polynomials: BTreeMap<usize, Vec<G::Point>>,
}

impl<G: Group> PartialPublicKeySet<G> {
    /// Creates an instance without information about any participants.
    pub fn new(params: Params) -> Self {
        Self {
            params,
            received_polynomials: BTreeMap::new(),
        }
    }

    pub fn has_participant(&self, index: usize) -> bool {
        self.received_polynomials.contains_key(&index)
    }

    pub fn is_complete(&self) -> bool {
        self.received_polynomials.len() == self.params.shares
    }

    pub fn complete(&self) -> Option<PublicKeySet<G>> {
        if !self.is_complete() {
            return None;
        }

        let coefficients = self.received_polynomials.values().fold(
            vec![G::identity(); self.params.threshold],
            |mut acc, val| {
                for (i, &coefficient) in val.iter().enumerate() {
                    acc[i] = acc[i] + coefficient;
                }
                acc
            },
        );

        // The shared public key is the value of the resulting polynomial at `0`.
        let shared_key = PublicKey::from_point(coefficients[0]);
        // A participant's public key is the value of the resulting polynomial at her index
        // (1-based).
        let participant_keys: Vec<_> = (0..self.params.shares)
            .map(|index| {
                let x = G::Scalar::from(index as u64 + 1);
                PublicKey::from_point(polynomial_value::<G>(&coefficients, x))
            })
            .collect();

        Some(PublicKeySet {
            params: self.params,
            shared_key,
            participant_keys,
        })
    }

    /// Adds information about the participant, which was previously obtained
    /// with [`public_info()`].
    ///
    /// # Errors
    ///
    /// This method returns an error if the participant info is malformed.
    ///
    /// # Panics
    ///
    /// - `index` must be within the bounds determined by the scheme parameters.
    /// - The participant with this index must not be added previously.
    ///
    /// [`public_info()`]: struct.StartingParticipant.html#fn.public_info
    pub fn add_participant(
        &mut self,
        index: usize,
        polynomial: Vec<G::Point>,
        proof_of_possession: &ProofOfPossession<G>,
    ) -> Result<(), Error> {
        assert!(index < self.params.shares);
        assert!(!self.has_participant(index));

        if polynomial.len() != self.params.threshold {
            return Err(Error::MalformedParticipantPolynomial);
        }

        let mut public_keys = Vec::with_capacity(self.params.threshold);
        for point in polynomial {
            let public_key = PublicKey::from_point(point);
            public_keys.push(public_key);
        }

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", self.params.shares as u64);
        transcript.append_u64(b"t", self.params.threshold as u64);
        transcript.append_u64(b"i", index as u64);

        if !proof_of_possession.verify(&public_keys, &mut transcript) {
            Err(Error::InvalidProofOfPossession)
        } else {
            let points = public_keys.into_iter().map(|key| key.full).collect();
            self.received_polynomials.insert(index, points);
            Ok(())
        }
    }

    fn references_for_participant(&self, participant_index: usize) -> Option<Vec<G::Point>> {
        assert!(participant_index < self.params.shares);
        if !self.is_complete() {
            return None;
        }

        let power = G::Scalar::from(participant_index as u64 + 1);
        Some(
            self.received_polynomials
                .values()
                .map(|polynomial| polynomial_value::<G>(&polynomial, power))
                .collect(),
        )
    }
}

#[derive(Clone)]
pub struct PublicKeySet<G: Group> {
    params: Params,
    shared_key: PublicKey<G>,
    participant_keys: Vec<PublicKey<G>>,
}

impl<G: Group> PublicKeySet<G> {
    pub fn from_participants(params: Params, participant_keys: Vec<PublicKey<G>>) -> Self {
        assert_eq!(params.shares, participant_keys.len());
        let indexes: Vec<_> = (0..params.threshold).collect();
        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let shared_key = G::vartime_multiscalar_mul(
            &denominators,
            participant_keys
                .iter()
                .map(|key| key.full)
                .take(params.threshold),
        );

        Self {
            params,
            shared_key: PublicKey::from_point(shared_key * &scale),
            participant_keys,
        }
    }

    pub fn params(&self) -> Params {
        self.params
    }

    pub fn shared_key(&self) -> &PublicKey<G> {
        &self.shared_key
    }

    pub fn participant_key(&self, index: usize) -> Option<PublicKey<G>> {
        self.participant_keys.get(index).cloned()
    }

    pub fn participant_keys(&self) -> &[PublicKey<G>] {
        &self.participant_keys
    }

    fn commit(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"n", self.params.shares as u64);
        transcript.append_u64(b"t", self.params.threshold as u64);
        transcript.append_point_bytes(b"K", &self.shared_key.bytes);
    }

    pub fn verify_participant(&self, index: usize, proof: &ProofOfPossession<G>) -> bool {
        let mut transcript = Transcript::new(b"elgamal_participant_pop");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);
        proof.verify(&[self.participant_key(index).unwrap()], &mut transcript)
    }

    pub fn verify_share(
        &self,
        candidate_share: CandidateShare<G>,
        encryption: Encryption<G>,
        index: usize,
        proof: &LogEqualityProof<G>,
    ) -> Option<DecryptionShare<G>> {
        let key_share = self.participant_keys[index].full;
        let dh_point = candidate_share.inner.dh_point;
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);

        let is_valid = proof.verify(
            &PublicKey::from_point(encryption.random_point),
            (key_share, dh_point),
            &mut transcript,
        );

        if is_valid {
            Some(DecryptionShare { dh_point })
        } else {
            None
        }
    }
}

pub struct StartingParticipant<G: Group> {
    params: Params,
    index: usize,
    secrets: Vec<SecretKey<G>>,
    public_points: Vec<G::Point>,
    proof_of_possession: ProofOfPossession<G>,
}

impl<G: Group> StartingParticipant<G> {
    pub fn new<R>(params: Params, index: usize, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        assert!(index < params.shares);

        let (public_keys, secrets): (Vec<_>, Vec<_>) = (0..params.threshold)
            .map(|_| {
                let keypair = Keypair::<G>::generate(rng);
                keypair.into_tuple()
            })
            .unzip();

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", params.shares as u64);
        transcript.append_u64(b"t", params.threshold as u64);
        transcript.append_u64(b"i", index as u64);

        let proof_of_possession =
            ProofOfPossession::new(&secrets, &public_keys, &mut transcript, rng);

        Self {
            params,
            index,
            secrets,
            public_points: public_keys.into_iter().map(|key| key.full).collect(),
            proof_of_possession,
        }
    }

    pub fn public_info(&self) -> (Vec<G::Point>, ProofOfPossession<G>) {
        (self.public_points.clone(), self.proof_of_possession.clone())
    }

    pub fn finalize_key_set(
        &self,
        key_set: &PartialPublicKeySet<G>,
    ) -> Option<ParticipantExchangingSecrets<G>> {
        assert_eq!(key_set.params, self.params);
        let references = key_set.references_for_participant(self.index)?;
        let key_set = key_set.complete()?;

        let mut messages: HashMap<_, _> = (0..self.params.shares)
            .map(|index| {
                let power = G::Scalar::from(index as u64 + 1);
                let mut poly_value = SecretKey::new(G::Scalar::from(0));
                for secret_scalar in self.secrets.iter().rev() {
                    poly_value = poly_value * power + secret_scalar.clone();
                }
                (index, poly_value)
            })
            .collect();
        let starting_share = messages.remove(&self.index).unwrap();

        Some(ParticipantExchangingSecrets {
            key_set,
            index: self.index,
            secret_share: starting_share,
            messages_to_others: messages,
            references,
            received_messages: HashSet::new(),
        })
    }
}

pub struct ParticipantExchangingSecrets<G: Group> {
    key_set: PublicKeySet<G>,
    index: usize,
    messages_to_others: HashMap<usize, SecretKey<G>>,
    secret_share: SecretKey<G>,
    references: Vec<G::Point>,
    received_messages: HashSet<usize>,
}

impl<G: Group> ParticipantExchangingSecrets<G> {
    /// Returns a message that should be sent to a scheme participant with the specified index.
    /// The message is not encrypted; it must be encrypted separately.
    pub fn message(&self, participant_index: usize) -> SecretKey<G> {
        self.messages_to_others[&participant_index].clone()
    }

    /// Checks whether we have received a message from a specific participant.
    pub fn has_message(&self, participant_index: usize) -> bool {
        self.index == participant_index || self.received_messages.contains(&participant_index)
    }

    pub fn is_complete(&self) -> bool {
        self.received_messages.len() == self.key_set.params.shares - 1
    }

    pub fn complete(self) -> Result<ActiveParticipant<G>, Self> {
        if !self.is_complete() {
            return Err(self);
        }

        debug_assert_eq!(
            G::scalar_mul_basepoint(&self.secret_share.0)
                .ct_eq(&self.key_set.participant_keys[self.index].full)
                .unwrap_u8(),
            1
        );

        Ok(ActiveParticipant {
            index: self.index,
            key_set: self.key_set,
            secret_share: self.secret_share,
        })
    }

    pub fn receive_message(
        &mut self,
        participant_index: usize,
        message: SecretKey<G>,
    ) -> Result<(), Error> {
        assert!(participant_index < self.key_set.params.shares);
        assert!(!self.has_message(participant_index));

        // Check that the received value is valid.
        let expected_value = &self.references[participant_index];
        if expected_value
            .ct_eq(&G::scalar_mul_basepoint(&message.0))
            .unwrap_u8()
            == 0
        {
            return Err(Error::InvalidSecret);
        }

        self.received_messages.insert(participant_index);
        self.secret_share += message;
        Ok(())
    }
}

pub struct ActiveParticipant<G: Group> {
    key_set: PublicKeySet<G>,
    index: usize,
    secret_share: SecretKey<G>,
}

impl<G: Group> ActiveParticipant<G> {
    pub fn new(key_set: PublicKeySet<G>, index: usize, secret_share: SecretKey<G>) -> Self {
        assert_eq!(
            G::scalar_mul_basepoint(&secret_share.0)
                .ct_eq(&key_set.participant_keys[index].full)
                .unwrap_u8(),
            1,
            "Secret key share does not correspond to public key share"
        );

        Self {
            key_set,
            index,
            secret_share,
        }
    }

    pub fn key_set(&self) -> &PublicKeySet<G> {
        &self.key_set
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn secret_share(&self) -> &SecretKey<G> {
        &self.secret_share
    }

    pub fn public_key_share(&self) -> &PublicKey<G> {
        &self.key_set.participant_keys[self.index]
    }

    pub fn proof_of_possession<R: CryptoRng + RngCore>(&self, rng: &mut R) -> ProofOfPossession<G> {
        let mut transcript = Transcript::new(b"elgamal_participant_pop");
        self.key_set.commit(&mut transcript);
        transcript.append_u64(b"i", self.index as u64);
        ProofOfPossession::new(
            &[self.secret_share.clone()],
            slice::from_ref(self.public_key_share()),
            &mut transcript,
            rng,
        )
    }

    pub fn decrypt_share<R>(
        &self,
        encryption: Encryption<G>,
        rng: &mut R,
    ) -> (DecryptionShare<G>, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let dh_point = encryption.random_point * &self.secret_share.0;
        let our_public_key = self.key_set.participant_keys[self.index].full;
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.key_set.commit(&mut transcript);
        transcript.append_u64(b"i", self.index as u64);

        let proof = LogEqualityProof::new(
            &PublicKey::from_point(encryption.random_point),
            (our_public_key, dh_point),
            &self.secret_share.0,
            &mut transcript,
            rng,
        );
        (DecryptionShare { dh_point }, proof)
    }
}

#[derive(Clone, Copy)]
pub struct DecryptionShare<G: Group> {
    dh_point: G::Point,
}

impl<G: Group> DecryptionShare<G> {
    pub fn combine(
        params: Params,
        encryption: Encryption<G>,
        shares: impl IntoIterator<Item = (usize, Self)>,
    ) -> Option<G::Point> {
        let (indexes, shares): (Vec<_>, Vec<_>) = shares
            .into_iter()
            .take(params.threshold)
            .map(|(index, share)| (index, share.dh_point))
            .unzip();
        if shares.len() < params.threshold {
            return None;
        }
        assert!(indexes.iter().all(|&index| index < params.shares));

        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let restored_value = G::vartime_multiscalar_mul(&denominators, shares);
        let dh_point = restored_value * &scale;
        Some(encryption.blinded_point - dh_point)
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(G::POINT_SIZE);
        G::serialize_point(&self.dh_point, &mut bytes);
        bytes
    }
}

#[derive(Clone, Copy)]
pub struct CandidateShare<G: Group> {
    inner: DecryptionShare<G>,
}

impl<G: Group> CandidateShare<G> {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == G::POINT_SIZE {
            let dh_point = G::deserialize_point(bytes)?;
            Some(Self {
                inner: DecryptionShare { dh_point },
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;
    use rand::thread_rng;

    use super::*;
    use crate::Edwards;

    impl<G: Group> DecryptionShare<G> {
        fn to_candidate(self) -> CandidateShare<G> {
            CandidateShare { inner: self }
        }
    }

    #[test]
    fn shared_1_of_2_key() {
        //! 1-of-N share schemes are a bit weird: all participants obtain the same secret
        //! at the end, and all decryption shares are always the same.

        let mut rng = thread_rng();
        let params = Params::new(2, 1);
        let alice: StartingParticipant<Edwards> = StartingParticipant::new(params, 0, &mut rng);
        let (alice_poly, alice_proof) = alice.public_info();
        assert_eq!(
            alice_poly,
            vec![Edwards::scalar_mul_basepoint(&alice.secrets[0].0)]
        );
        let bob: StartingParticipant<Edwards> = StartingParticipant::new(params, 1, &mut rng);
        let (bob_poly, bob_proof) = bob.public_info();
        assert_eq!(
            bob_poly,
            vec![Edwards::scalar_mul_basepoint(&bob.secrets[0].0)]
        );

        let mut group_info = PartialPublicKeySet::new(params);
        group_info
            .add_participant(0, alice_poly, &alice_proof)
            .unwrap();
        group_info.add_participant(1, bob_poly, &bob_proof).unwrap();
        assert!(group_info.is_complete());

        let joint_secret = (alice.secrets[0].clone() + bob.secrets[0].clone()).0;
        let joint_pt = Edwards::scalar_mul_basepoint(&joint_secret);

        let mut alice = alice.finalize_key_set(&group_info).unwrap();
        let a2b_message = alice.message(1);
        let mut bob = bob.finalize_key_set(&group_info).unwrap();
        let b2a_message = bob.message(0);
        bob.receive_message(0, a2b_message).unwrap();
        alice.receive_message(1, b2a_message).unwrap();

        let alice = alice.complete().map_err(drop).unwrap();
        let bob = bob.complete().map_err(drop).unwrap();
        assert_eq!(alice.secret_share.0, joint_secret);
        assert_eq!(bob.secret_share.0, joint_secret);

        let group_info = group_info.complete().unwrap();
        assert_eq!(group_info.shared_key.full, joint_pt);
        assert_eq!(
            group_info.participant_keys,
            vec![PublicKey::from_point(joint_pt); 2]
        );

        let message = Edwards::scalar_mul_basepoint(&Scalar25519::from(5_u32));
        let encryption = Encryption::new(message, &group_info.shared_key, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(encryption, &mut rng);
        let alice_share = group_info
            .verify_share(alice_share.to_candidate(), encryption, 0, &proof)
            .unwrap();

        let (bob_share, proof) = bob.decrypt_share(encryption, &mut rng);
        let bob_share = group_info
            .verify_share(bob_share.to_candidate(), encryption, 1, &proof)
            .unwrap();
        assert_eq!(alice_share.dh_point, encryption.blinded_point - message);
        assert_eq!(alice_share.dh_point, bob_share.dh_point);
    }

    #[test]
    fn shared_2_of_3_key() {
        let mut rng = thread_rng();
        let params = Params::new(3, 2);

        let alice = StartingParticipant::<Edwards>::new(params, 0, &mut rng);
        let (alice_poly, alice_proof) = alice.public_info();
        let bob = StartingParticipant::<Edwards>::new(params, 1, &mut rng);
        let (bob_poly, bob_proof) = bob.public_info();
        let carol = StartingParticipant::<Edwards>::new(params, 2, &mut rng);
        let (carol_poly, carol_proof) = carol.public_info();

        let mut key_set = PartialPublicKeySet::<Edwards>::new(params);
        key_set
            .add_participant(0, alice_poly, &alice_proof)
            .unwrap();
        key_set.add_participant(1, bob_poly, &bob_proof).unwrap();
        key_set
            .add_participant(2, carol_poly, &carol_proof)
            .unwrap();
        assert!(key_set.is_complete());

        let secret0 = alice.secrets[0].0 + bob.secrets[0].0 + carol.secrets[0].0;
        let pt0 = Edwards::scalar_mul_basepoint(&secret0);
        let secret1 = alice.secrets[1].0 + bob.secrets[1].0 + carol.secrets[1].0;
        let pt1 = Edwards::scalar_mul_basepoint(&secret1);

        let mut alice = alice.finalize_key_set(&key_set).unwrap();
        let mut bob = bob.finalize_key_set(&key_set).unwrap();
        let mut carol = carol.finalize_key_set(&key_set).unwrap();
        let mut actors = vec![&mut alice, &mut bob, &mut carol];
        for i in 0..3 {
            for j in 0..3 {
                if j != i {
                    let message = actors[i].message(j);
                    actors[j].receive_message(i, message).unwrap();
                }
            }
        }
        assert!(actors.iter().all(|actor| actor.is_complete()));

        let key_set = key_set.complete().unwrap();
        assert_eq!(key_set.shared_key.full, pt0);
        assert_eq!(
            key_set.participant_keys,
            vec![
                PublicKey::from_point(pt0 + pt1),
                PublicKey::from_point(pt0 + pt1 * Scalar25519::from(2_u32)),
                PublicKey::from_point(pt0 + pt1 * Scalar25519::from(3_u32)),
            ]
        );

        let alice = alice.complete().map_err(drop).unwrap();
        assert_eq!(alice.secret_share.0, secret0 + secret1);
        let bob = bob.complete().map_err(drop).unwrap();
        assert_eq!(
            bob.secret_share.0,
            secret0 + secret1 * Scalar25519::from(2_u32)
        );
        let carol = carol.complete().map_err(drop).unwrap();
        assert_eq!(
            carol.secret_share.0,
            secret0 + secret1 * Scalar25519::from(3_u32)
        );

        assert!(key_set.verify_participant(0, &alice.proof_of_possession(&mut rng)));
        assert!(key_set.verify_participant(1, &bob.proof_of_possession(&mut rng)));
        assert!(key_set.verify_participant(2, &carol.proof_of_possession(&mut rng)));
        assert!(!key_set.verify_participant(1, &alice.proof_of_possession(&mut rng)));

        let message = Edwards::scalar_mul_basepoint(&Scalar25519::from(15_u32));
        let encryption = Encryption::new(message, &key_set.shared_key, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(encryption, &mut rng);
        assert!(key_set
            .verify_share(alice_share.to_candidate(), encryption, 0, &proof,)
            .is_some());

        let (bob_share, proof) = bob.decrypt_share(encryption, &mut rng);
        assert!(key_set
            .verify_share(bob_share.to_candidate(), encryption, 1, &proof,)
            .is_some());

        // We need to find `a0` from the following equations:
        // a0 +   a1 = alice_share.dh_point;
        // a0 + 2*a1 = bob_share.dh_point;
        let composite_dh_point =
            alice_share.dh_point * Scalar25519::from(2_u32) - bob_share.dh_point;
        assert_eq!(composite_dh_point, encryption.blinded_point - message);
    }

    #[test]
    fn lagrange_coeffs_are_computed_correctly() {
        // d_0 = 2 / (2 - 1) = 2
        // d_1 = 1 / (1 - 2) = -1
        let (coeffs, scale) = lagrange_coefficients::<Edwards>(&[0, 1]);
        assert_eq!(
            coeffs,
            vec![Scalar25519::from(1_u32), -Scalar25519::from(2_u32).invert()]
        );
        assert_eq!(scale, Scalar25519::from(2_u32));

        // d_0 = 3 / (3 - 1) = 3/2
        // d_1 = 1 / (1 - 3) = -1/2
        let (coeffs, scale) = lagrange_coefficients::<Edwards>(&[0, 2]);
        assert_eq!(
            coeffs,
            vec![
                Scalar25519::from(2_u32).invert(),
                -Scalar25519::from(6_u32).invert(),
            ]
        );
        assert_eq!(scale, Scalar25519::from(3_u32));

        // d_0 = 4 * 5 / (4 - 1) * (5 - 1) = 20/12 = 5/3
        // d_1 = 1 * 5 / (1 - 4) * (5 - 4) = -5/3
        // d_2 = 1 * 4 / (1 - 5) * (4 - 5) = 4/4 = 1
        let (coeffs, scale) = lagrange_coefficients::<Edwards>(&[0, 3, 4]);
        assert_eq!(
            coeffs,
            vec![
                Scalar25519::from(12_u32).invert(),
                -Scalar25519::from(12_u32).invert(),
                Scalar25519::from(20_u32).invert(),
            ]
        );
        assert_eq!(scale, Scalar25519::from(20_u32));
    }
}
