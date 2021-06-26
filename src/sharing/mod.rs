//! [Shamir's secret sharing][sss] for ElGamal encryption.
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
//! **1.** Each participant in the `(n, t)` scheme generates a *secret polynomial* of degree `t`
//! with random scalar coefficients:
//!
//! ```text
//! P_i(x) = a_i0 + a_i1 * x + ... + a_it * x^t,
//! ```
//!
//! where `1 <= i <= n` is the participant's index.
//!
//! Each participant then broadcasts their *public polynomial*, i.e., the group elements
//! corresponding to partipant's coefficients:
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
//! Assume `(R, B) = ([r]G, [m]G + [r]K)` encrypts scalar `m` for the shared key `K`.
//! In order to decrypt it, participants perform Diffie–Hellman exchange with the random part
//! of the ciphertext: `D_i = [x_i]R`. Validity of this *decryption share* can be verified
//! via a ZKP of discrete log equality:
//!
//! ```text
//! x_i = dlog_G(K_i) = dlog_R(D_i).
//! ```
//!
//! Given any `t + 1` decryption shares, it is possible to restore `D = [x]R` using Lagrange
//! interpolation. (Indeed, `D_i` are tied to `D` by the same relations as key shares `x_i`
//! are to `x`.) Once we have `D`, the encrypted value is restored as `[m]G = B - D`.
//!
//! [sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
//! [Gennaro et al.]: https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf
//!
//! # Examples
//!
//! Threshold encryption scheme requiring 2 of 3 participants.
//!
//! ```
//! # use elastic_elgamal::{group::Ristretto, sharing::*, Ciphertext, DiscreteLogTable};
//! # use rand::thread_rng;
//! let mut rng = thread_rng();
//! let params = Params::new(3, 2);
//!
//! // Initialize participants of the scheme.
//! let participants: Vec<_> = (0..3)
//!     .map(|i| StartingParticipant::<Ristretto>::new(params, i, &mut rng))
//!     .collect();
//!
//! // Get public info from all participants. This info should be broadcast.
//! let public_infos = participants.iter().map(StartingParticipant::public_info);
//! let mut key_set = PartialPublicKeySet::new(params);
//! for (i, (poly, proof)) in public_infos.enumerate() {
//!     key_set.add_participant(i, poly, proof);
//! }
//! assert!(key_set.is_complete());
//!
//! // Once all commitments are collected, all participants may proceed
//! // to the next stage: exchanging secret shares.
//! let mut participants: Vec<_> = participants
//!     .into_iter()
//!     .map(|p| p.finalize_key_set(&key_set).unwrap())
//!     .collect();
//! let key_set = key_set.complete().unwrap();
//!
//! // Exchange P2P messages. In real setting, this should be performed
//! // via secure channels.
//! for i in 0..3 {
//!     for j in 0..3 {
//!         if j != i {
//!              let message = participants[i].message(j).clone();
//!              participants[j].process_message(i, message).unwrap();
//!         }
//!     }
//! }
//!
//! let participants: Vec<_> = participants
//!     .into_iter()
//!     .map(ParticipantExchangingSecrets::complete)
//!     .collect();
//!
//! // At last, participants can decrypt messages!
//! let encrypted_value = 5_u64;
//! let enc = key_set.shared_key().encrypt(encrypted_value, &mut rng);
//! let shares_with_proofs = participants
//!     .iter()
//!     .map(|p| p.decrypt_share(enc, &mut rng))
//!     .take(2); // emulate the 3rd participant dropping off
//!
//! // Emulate share transfer via untrusted network.
//! let dec_shares = shares_with_proofs
//!     .enumerate()
//!     .map(|(i, (share, proof))| {
//!         let share = CandidateShare::from_bytes(&share.to_bytes()).unwrap();
//!         key_set.verify_share(share, enc, i, &proof).unwrap()
//!     });
//!
//! // Reconstruct decryption from the shares.
//! let dec = DecryptionShare::combine(params, enc, dec_shares.enumerate())
//!     .unwrap();
//! // Use lookup table to map decryption back to scalar.
//! let lookup_table = DiscreteLogTable::<Ristretto>::new(0..10);
//! assert_eq!(lookup_table.get(&dec), Some(encrypted_value));
//! ```

use merlin::Transcript;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::{cmp::Ordering, fmt, iter, ops};

#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};
use crate::{
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession, TranscriptForGroup},
    Ciphertext, PublicKey,
};

mod participant;
pub use self::participant::{
    ActiveParticipant, CandidateShare, DecryptionShare, ParticipantExchangingSecrets,
    StartingParticipant,
};

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

/// Errors that can occur during the secret sharing protocol.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Public polynomial received from a participant is malformed.
    MalformedParticipantPolynomial,
    /// Secret received from a participant does not correspond to their commitment via
    /// public polynomial.
    InvalidSecret,
    /// Proof of possession supplied with a participant's public polynomial is invalid.
    InvalidProofOfPossession,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedParticipantPolynomial => {
                "public polynomial received from a participant is malformed"
            }
            Self::InvalidSecret => {
                "secret received from a participant does not correspond to their commitment via \
                 public polynomial"
            }
            Self::InvalidProofOfPossession => {
                "proof of possession supplied with a participant's public polynomial is invalid"
            }
        })
    }
}

impl std::error::Error for Error {}

/// Parameters of a threshold ElGamal encryption scheme.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Params {
    /// Total number of shares / participants.
    pub shares: usize,
    /// Number of participants necessary to jointly restore the secret.
    pub threshold: usize,
}

impl Params {
    /// Creates new parameters.
    ///
    /// # Panics
    ///
    /// Panics if `shares` is equal to zero or if `threshold` is not in `1..=shares`.
    pub fn new(shares: usize, threshold: usize) -> Self {
        assert!(shares > 0);
        assert!(threshold > 0 && threshold <= shares);
        Self { shares, threshold }
    }
}

#[derive(Debug, Clone)]
struct PublicPolynomial<G: Group>(Vec<G::Element>);

impl<G: Group> PublicPolynomial<G> {
    fn identity(len: usize) -> Self {
        Self(vec![G::identity(); len])
    }

    fn value_at_zero(&self) -> G::Element {
        self.0[0]
    }

    /// Computes value of this public polynomial at the specified point in variable time.
    fn value_at(&self, x: G::Scalar) -> G::Element {
        let mut val = G::Scalar::from(1_u64);
        let scalars: Vec<_> = (0..self.0.len())
            .map(|_| {
                let output = val;
                val = val * x;
                output
            })
            .collect();

        G::vartime_multi_mul(&scalars, self.0.iter().copied())
    }
}

impl<G: Group> ops::AddAssign<&Self> for PublicPolynomial<G> {
    fn add_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(
            self.0.len(),
            rhs.0.len(),
            "cannot add polynomials of different degrees"
        );
        for (val, &rhs_val) in self.0.iter_mut().zip(&rhs.0) {
            *val = *val + rhs_val;
        }
    }
}

#[cfg(feature = "serde")]
impl<G: Group> Serialize for PublicPolynomial<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        VecHelper::<ElementHelper<G>, 1>::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, G: Group> Deserialize<'de> for PublicPolynomial<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        VecHelper::<ElementHelper<G>, 1>::deserialize(deserializer).map(Self)
    }
}

/// In-progress information about the participants of a threshold ElGamal encryption scheme
/// before all participants' commitments are collected.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PartialPublicKeySet<G: Group> {
    params: Params,
    received_polynomials: Vec<Option<PublicPolynomial<G>>>,
}

impl<G: Group> PartialPublicKeySet<G> {
    /// Creates an instance without information about any participants.
    pub fn new(params: Params) -> Self {
        Self {
            params,
            received_polynomials: vec![None; params.shares],
        }
    }

    /// Checks whether a valid polynomial commitment was received from a participant with
    /// the specified `index`.
    pub fn has_participant(&self, index: usize) -> bool {
        self.received_polynomials
            .get(index)
            .map_or(false, Option::is_some)
    }

    /// Checks whether this set is complete (has commitments from all participants).
    pub fn is_complete(&self) -> bool {
        self.received_polynomials.iter().all(Option::is_some)
    }

    fn all_polynomials(&self) -> impl Iterator<Item = &PublicPolynomial<G>> + '_ {
        self.received_polynomials
            .iter()
            .map(|poly| poly.as_ref().unwrap())
    }

    /// Completes this set returning [`PublicKeySet`]. Returns `None` if this set is currently
    /// not complete (i.e., [`Self::is_complete()`] returns `false`).
    pub fn complete(&self) -> Option<PublicKeySet<G>> {
        if !self.is_complete() {
            return None;
        }

        let coefficients = self.all_polynomials().fold(
            PublicPolynomial::identity(self.params.threshold),
            |mut acc, val| {
                acc += val;
                acc
            },
        );

        // The shared public key is the value of the resulting polynomial at `0`.
        let shared_key = PublicKey::from_element(coefficients.value_at_zero());
        // A participant's public key is the value of the resulting polynomial at their index
        // (1-based).
        let participant_keys: Vec<_> = (0..self.params.shares)
            .map(|index| {
                let x = G::Scalar::from(index as u64 + 1);
                PublicKey::from_element(coefficients.value_at(x))
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
    /// [`public_info()`]: StartingParticipant::public_info()
    pub fn add_participant(
        &mut self,
        index: usize,
        polynomial: Vec<G::Element>,
        proof_of_possession: &ProofOfPossession<G>,
    ) -> Result<(), Error> {
        assert!(
            index < self.params.shares,
            "participant index {} out of bounds, expected a value in 0..{}",
            index,
            self.params.shares
        );
        assert!(
            !self.has_participant(index),
            "participant #{} was already initialized",
            index
        );

        if polynomial.len() != self.params.threshold {
            return Err(Error::MalformedParticipantPolynomial);
        }

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", self.params.shares as u64);
        transcript.append_u64(b"t", self.params.threshold as u64);
        transcript.append_u64(b"i", index as u64);

        let public_keys: Vec<_> = polynomial
            .iter()
            .copied()
            .map(PublicKey::from_element)
            .collect();
        if proof_of_possession.verify(public_keys.iter(), &mut transcript) {
            self.received_polynomials[index] = Some(PublicPolynomial(polynomial));
            Ok(())
        } else {
            Err(Error::InvalidProofOfPossession)
        }
    }

    fn commitments_for_participant(&self, participant_index: usize) -> Option<Vec<G::Element>> {
        assert!(participant_index < self.params.shares);
        if !self.is_complete() {
            return None;
        }

        let power = G::Scalar::from(participant_index as u64 + 1);
        Some(
            self.all_polynomials()
                .map(|polynomial| polynomial.value_at(power))
                .collect(),
        )
    }
}

/// Full public information about the participants of a threshold ElGamal encryption scheme
/// after all participants' commitments are collected.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PublicKeySet<G: Group> {
    params: Params,
    shared_key: PublicKey<G>,
    participant_keys: Vec<PublicKey<G>>,
}

impl<G: Group> PublicKeySet<G> {
    /// Creates a key set from the parameters and public keys of all participants.
    ///
    /// # Panics
    ///
    /// Panics if the number of keys in `participant_keys` does not match the number
    /// of participants in `params`.
    pub fn from_participants(params: Params, participant_keys: Vec<PublicKey<G>>) -> Self {
        assert_eq!(params.shares, participant_keys.len());

        let indexes: Vec<_> = (0..params.threshold).collect();
        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let shared_key = G::vartime_multi_mul(
            &denominators,
            participant_keys
                .iter()
                .map(|key| key.element)
                .take(params.threshold),
        );

        Self {
            params,
            shared_key: PublicKey::from_element(shared_key * &scale),
            participant_keys,
        }
    }

    /// Returns parameters for this scheme.
    pub fn params(&self) -> Params {
        self.params
    }

    /// Returns the shared public key used in this scheme.
    pub fn shared_key(&self) -> &PublicKey<G> {
        &self.shared_key
    }

    /// Returns the public key of a participant with the specified `index`. If `index` is
    /// out of bounds, returns `None`.
    pub fn participant_key(&self, index: usize) -> Option<&PublicKey<G>> {
        self.participant_keys.get(index)
    }

    /// Returns the slice with all participants' public keys.
    pub fn participant_keys(&self) -> &[PublicKey<G>] {
        &self.participant_keys
    }

    fn commit(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"n", self.params.shares as u64);
        transcript.append_u64(b"t", self.params.threshold as u64);
        transcript.append_element_bytes(b"K", &self.shared_key.bytes);
    }

    /// Verifies a proof of possession of the participant's secret key.
    ///
    /// Proofs of possession for participants are not required for protocol correctness.
    /// Still, they can be useful to attribute failures or just as an additional safety mechanism;
    /// see [the module docs](index.html) for details.
    ///
    /// # Panics
    ///
    /// Panics if `index` does not correspond to a participant.
    pub fn verify_participant(&self, index: usize, proof: &ProofOfPossession<G>) -> bool {
        let participant_key = self.participant_key(index).unwrap_or_else(|| {
            panic!(
                "participant index {} out of bounds, expected a value in 0..{}",
                index,
                self.participant_keys.len()
            );
        });
        let mut transcript = Transcript::new(b"elgamal_participant_pop");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);
        proof.verify(iter::once(participant_key), &mut transcript)
    }

    /// Verifies a candidate decryption share for `ciphertext` provided by a participant
    /// with the specified `index`.
    pub fn verify_share(
        &self,
        candidate_share: CandidateShare<G>,
        ciphertext: Ciphertext<G>,
        index: usize,
        proof: &LogEqualityProof<G>,
    ) -> Option<DecryptionShare<G>> {
        let key_share = self.participant_keys[index].element;
        let dh_element = candidate_share.dh_element();
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);

        let is_valid = proof.verify(
            &PublicKey::from_element(ciphertext.random_element),
            (key_share, dh_element),
            &mut transcript,
        );

        if is_valid {
            Some(DecryptionShare::new(dh_element))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;

    use super::*;
    use crate::group::Ristretto;

    #[test]
    fn lagrange_coeffs_are_computed_correctly() {
        // d_0 = 2 / (2 - 1) = 2
        // d_1 = 1 / (1 - 2) = -1
        let (coeffs, scale) = lagrange_coefficients::<Ristretto>(&[0, 1]);
        assert_eq!(
            coeffs,
            vec![Scalar25519::from(1_u32), -Scalar25519::from(2_u32).invert()]
        );
        assert_eq!(scale, Scalar25519::from(2_u32));

        // d_0 = 3 / (3 - 1) = 3/2
        // d_1 = 1 / (1 - 3) = -1/2
        let (coeffs, scale) = lagrange_coefficients::<Ristretto>(&[0, 2]);
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
        let (coeffs, scale) = lagrange_coefficients::<Ristretto>(&[0, 3, 4]);
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
