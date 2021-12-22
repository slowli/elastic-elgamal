//! [Feldman's verifiable secret sharing][feldman-vss] (VSS) for ElGamal encryption.
//!
//! Feldman's VSS is an extension of [Shamir's secret sharing][sss] that provides a degree
//! of verifiability for the scheme participants and the public. As with other VSS schemes,
//! the goal is to securely distribute a secret among `n` participants so that the secret can
//! be recombined by any `t` (but not less) of these participants. Unlike distributed key
//! generation (DKG), VSS assumes a central authority (a *dealer*) generating the secret
//! and distributing its shares among participants.
//!
//! # Construction
//!
//! **Inputs:**
//!
//! - Total number of participants `n`
//! - Minimum number of participants necessary to restore secret `t`
//! - Prime-order group with discrete log assumption with generator `G`
//!
//! **Assumptions:**
//!
//! - There is a secure broadcast among participants, which acts as a single source of truth
//!   (e.g., a blockchain). The broadcast is synchronous w.r.t. the protocol steps (in practice,
//!   this means that protocol steps take sufficiently long amount of time).
//! - Secure synchronous P2P channels can be established between the dealer and participants.
//! - The adversary is static (corrupts parties before protocol instantiation) and can corrupt
//!   less than a half of participants (including the dealer).
//!
//! Feldman's VSS proceeds as follows:
//!
//! 1. The dealer generates a secret `x` (a scalar in a group with discrete log assumption).
//!   Along with this scalar, the dealer generates `t` other scalars that are also kept secret.
//!   These scalars form a secret polynomial of degree `t`: `P(z) = x + x_1 * z + x_2 * z^2 + …`.
//! 2. The dealer publishes coefficients `[x]G`, `[x_1]G`, ..., `[x_t]G` of the *public polynomial*
//!   corresponding to `P`: `Q(z) = [x]G + [z][x_1]G + [z^2][x_2]G + …`. Here, `[x]G` is the shared
//!   public key, and values `Q(i)` at `i = 1..=n` are public key shares of participants.
//! 3. The dealer distributes secret key shares `s_i = P(i)` among participants `i = 1..=n`
//!   via secure P2P channels. Each participant can verify share validity by calculating
//!   `[s_i]G ?= Q(i)`.
//!
//! If a participant receives an incorrect secret share, the participant broadcasts a *complaint*
//! against the dealer. The dealer responds by broadcasting the participant's share. Either the
//! share is correct (in which case the complaining participant is at fault), or it is not
//! (in which case the dealer is at fault).
//!
//! To improve auditability, the implemented version of VSS provides zero-knowledge proofs
//! of possession both for the dealer and participants. The dealer must broadcast the public
//! polynomial together with the proof; participants should broadcast proof of knowledge of
//! a secret share once they receive the share from the dealer.
//!
//! # On distributed key generation
//!
//! While DKG allows for a fully decentralized setup unlike VSS, it is difficult to get right.
//! For example, [Gennaro et al.] show that DKG via parallel Feldman's VSS instances where
//! each participant is a dealer in one of the instances is not secure; the adversary
//! can bias distribution of the shared public key. Hence, DKG is not (yet?) implemented
//! in this crate.
//!
//! [sss]: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
//! [feldman-vss]: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
//! [Gennaro et al.]: https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf
//!
//! # Examples
//!
//! Threshold encryption scheme requiring 2 of 3 participants.
//!
//! ```
//! # use elastic_elgamal::{group::Ristretto, sharing::*, Ciphertext, DiscreteLogTable};
//! # use rand::thread_rng;
//! # use std::error::Error as StdError;
//! # fn main() -> Result<(), Box<dyn StdError>> {
//! let mut rng = thread_rng();
//! let params = Params::new(3, 2);
//!
//! // Initialize the dealer.
//! let dealer = Dealer::<Ristretto>::new(params, &mut rng);
//! let (public_poly, poly_proof) = dealer.public_info();
//! let key_set = PublicKeySet::new(params, public_poly, poly_proof)?;
//!
//! // Initialize participants based on secret shares provided by the dealer.
//! let participants = (0..3)
//!     .map(|i| ActiveParticipant::new(
//!         key_set.clone(),
//!         i,
//!         dealer.secret_share_for_participant(i),
//!     ))
//!     .collect::<Result<Vec<_>, _>>()?;
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
//! # Ok(())
//! # }
//! ```

use merlin::Transcript;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

use core::{cmp::Ordering, fmt, iter, ops};

#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};
use crate::{
    alloc::Vec,
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession, TranscriptForGroup, VerificationError},
    Ciphertext, PublicKey,
};

mod participant;
pub use self::participant::{ActiveParticipant, CandidateShare, Dealer, DecryptionShare};

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
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Public polynomial received from the dealer is malformed.
    MalformedDealerPolynomial,
    /// Proof of possession supplied with the dealer's public polynomial is invalid.
    InvalidDealerProof(VerificationError),
    /// Secret received from the dealer does not correspond to their commitment via
    /// the public polynomial.
    InvalidSecret,
    /// Number of participants specified in [`Params`] does not match the number
    /// of provided public keys.
    ParticipantCountMismatch,
    /// Participants' public keys do not correspond to a single shared key.
    MalformedParticipantKeys,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedDealerPolynomial => {
                formatter.write_str("public polynomial received from the dealer is malformed")
            }
            Self::InvalidDealerProof(err) => {
                write!(
                    formatter,
                    "proof of possession supplied with the dealer's public polynomial \
                     is invalid: {}",
                    err
                )
            }
            Self::InvalidSecret => formatter.write_str(
                "secret received from the dealer does not correspond to their commitment via \
                 public polynomial",
            ),
            Self::ParticipantCountMismatch => formatter.write_str(
                "number of participants specified in `Params` does not match the number \
                 of provided public keys",
            ),
            Self::MalformedParticipantKeys => formatter
                .write_str("participants' public keys do not correspond to a single shared key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDealerProof(err) => Some(err),
            _ => None,
        }
    }
}

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
    /// Creates an instance based on information provided by the [`Dealer`].
    ///
    /// # Errors
    ///
    /// Returns an error if the information provided by the dealer is malformed.
    pub fn new(
        params: Params,
        public_poly: Vec<G::Element>,
        public_poly_proof: &ProofOfPossession<G>,
    ) -> Result<Self, Error> {
        if public_poly.len() != params.threshold {
            return Err(Error::MalformedDealerPolynomial);
        }

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", params.shares as u64);
        transcript.append_u64(b"t", params.threshold as u64);

        let public_poly_keys: Vec<_> = public_poly
            .iter()
            .copied()
            .map(PublicKey::from_element)
            .collect();
        public_poly_proof
            .verify(public_poly_keys.iter(), &mut transcript)
            .map_err(Error::InvalidDealerProof)?;

        let public_poly = PublicPolynomial::<G>(public_poly);
        let shared_key = PublicKey::from_element(public_poly.value_at_zero());
        let participant_keys = (0..params.shares)
            .map(|idx| PublicKey::from_element(public_poly.value_at((idx as u64 + 1).into())))
            .collect();

        Ok(Self {
            params,
            shared_key,
            participant_keys,
        })
    }

    /// Creates a key set from the parameters and public keys of all participants.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of keys in `participant_keys` does not match the number
    /// of participants in `params`, or if `participant_keys` are inconsistent (do not correspond
    /// to a single shared key).
    pub fn from_participants(
        params: Params,
        participant_keys: Vec<PublicKey<G>>,
    ) -> Result<Self, Error> {
        if params.shares != participant_keys.len() {
            return Err(Error::ParticipantCountMismatch);
        }

        // Reconstruct the shared key based on first `t` participant keys.
        let indexes: Vec<_> = (0..params.threshold).collect();
        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let starting_keys = participant_keys
            .iter()
            .map(|key| key.element)
            .take(params.threshold);
        let shared_key = G::vartime_multi_mul(&denominators, starting_keys.clone());
        let shared_key = PublicKey::from_element(shared_key * &scale);

        // Check that the remaining participant keys are correct.

        // Prepare multiplicative inverses for `1..=n`.
        let mut inverses: Vec<_> = (1_u64..=params.shares as u64)
            .map(G::Scalar::from)
            .collect();
        G::invert_scalars(&mut inverses);

        for (x, key) in participant_keys.iter().enumerate().skip(params.threshold) {
            let mut key_scale = indexes
                .iter()
                .map(|&idx| G::Scalar::from((x - idx) as u64))
                .fold(G::Scalar::from(1), |acc, value| acc * value);

            let key_denominators: Vec<_> = denominators
                .iter()
                .enumerate()
                .map(|(idx, &d)| d * G::Scalar::from(idx as u64 + 1) * inverses[x - idx - 1])
                .collect();

            // We've ignored the sign in the calculations above. The sign is negative iff
            // threshold `t` is even; indeed, all `t` multiplicands in `key_scale` are negative,
            // as well as the `1 / (idx - x)` multiplicand in each of `key_denominators`.
            if params.threshold % 2 == 0 {
                key_scale = -key_scale;
            }

            let interpolated_key = G::vartime_multi_mul(&key_denominators, starting_keys.clone());
            let interpolated_key = interpolated_key * &key_scale;
            if !bool::from(interpolated_key.ct_eq(&key.element)) {
                return Err(Error::MalformedParticipantKeys);
            }
        }

        Ok(Self {
            params,
            shared_key,
            participant_keys,
        })
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
    ///
    /// # Errors
    ///
    /// Returns an error if the `proof` does not verify.
    pub fn verify_participant(
        &self,
        index: usize,
        proof: &ProofOfPossession<G>,
    ) -> Result<(), VerificationError> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the `proof` does not verify.
    pub fn verify_share(
        &self,
        candidate_share: CandidateShare<G>,
        ciphertext: Ciphertext<G>,
        index: usize,
        proof: &LogEqualityProof<G>,
    ) -> Result<DecryptionShare<G>, VerificationError> {
        let key_share = self.participant_keys[index].element;
        let dh_element = candidate_share.dh_element();
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);

        proof.verify(
            &PublicKey::from_element(ciphertext.random_element),
            (key_share, dh_element),
            &mut transcript,
        )?;
        Ok(DecryptionShare::new(dh_element))
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;
    use rand::thread_rng;

    use super::*;
    use crate::group::{ElementOps, Ristretto};

    #[test]
    fn lagrange_coeffs_are_computed_correctly() {
        // d_0 = 2 / (2 - 1) = 2
        // d_1 = 1 / (1 - 2) = -1
        let (coeffs, scale) = lagrange_coefficients::<Ristretto>(&[0, 1]);
        assert_eq!(
            coeffs,
            [Scalar25519::from(1_u32), -Scalar25519::from(2_u32).invert()]
        );
        assert_eq!(scale, Scalar25519::from(2_u32));

        // d_0 = 3 / (3 - 1) = 3/2
        // d_1 = 1 / (1 - 3) = -1/2
        let (coeffs, scale) = lagrange_coefficients::<Ristretto>(&[0, 2]);
        assert_eq!(
            coeffs,
            [
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
            [
                Scalar25519::from(12_u32).invert(),
                -Scalar25519::from(12_u32).invert(),
                Scalar25519::from(20_u32).invert(),
            ]
        );
        assert_eq!(scale, Scalar25519::from(20_u32));
    }

    #[test]
    fn restoring_key_set_from_participant_keys_errors() {
        let mut rng = thread_rng();
        let params = Params::new(10, 7);

        let dealer = Dealer::<Ristretto>::new(params, &mut rng);
        let (public_poly, _) = dealer.public_info();
        let public_poly = PublicPolynomial::<Ristretto>(public_poly);
        let participant_keys: Vec<PublicKey<Ristretto>> = (1..=params.shares)
            .map(|i| PublicKey::from_element(public_poly.value_at((i as u64).into())))
            .collect();

        // Check that `participant_keys` are computed correctly.
        PublicKeySet::from_participants(params, participant_keys.clone()).unwrap();

        let err =
            PublicKeySet::from_participants(params, participant_keys[1..].to_vec()).unwrap_err();
        assert!(matches!(err, Error::ParticipantCountMismatch));

        // Order of keys matters!
        let mut bogus_keys = participant_keys.clone();
        bogus_keys.swap(1, 5);
        let err = PublicKeySet::from_participants(params, bogus_keys).unwrap_err();
        assert!(matches!(err, Error::MalformedParticipantKeys));

        for i in 0..params.shares {
            let mut bogus_keys = participant_keys.clone();
            bogus_keys[i] = PublicKey::from_element(bogus_keys[i].element + Ristretto::generator());
            let err = PublicKeySet::from_participants(params, bogus_keys).unwrap_err();
            assert!(matches!(err, Error::MalformedParticipantKeys));
        }
    }
}
