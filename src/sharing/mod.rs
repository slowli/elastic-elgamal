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
//!    Along with this scalar, the dealer generates `t` other scalars that are also kept secret.
//!    These scalars form a secret polynomial of degree `t`: `P(z) = x + x_1 * z + x_2 * z^2 + …`.
//! 2. The dealer publishes coefficients `[x]G`, `[x_1]G`, ..., `[x_t]G` of the *public polynomial*
//!    corresponding to `P`: `Q(z) = [x]G + [z][x_1]G + [z^2][x_2]G + …`. Here, `[x]G` is the shared
//!    public key, and values `Q(i)` at `i = 1..=n` are public key shares of participants.
//! 3. The dealer distributes secret key shares `s_i = P(i)` among participants `i = 1..=n`
//!    via secure P2P channels. Each participant can verify share validity by calculating
//!    `[s_i]G ?= Q(i)`.
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
//! # Distributed key generation
//!
//! Distributed key generation (DKG) differs from the approach implemented in this module
//! in that there is no centralized dealer trusted by all participants. Instead, the participants
//! essentially run parallel secret sharing protocol instances where  each participant
//! is a dealer in one of the instances. This approach is implemented
//! in the [`dkg`](crate::dkg) module of this crate. Beware that it may not protect
//! from participants biasing the distribution of the shared public key, e.g. by aborting
//! the protocol; see [Gennaro et al.] for more details.
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
//! # use elastic_elgamal::{
//! #     group::Ristretto, sharing::*, CandidateDecryption, Ciphertext, DiscreteLogTable,
//! # };
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
//!         let share = CandidateDecryption::from_bytes(&share.to_bytes()).unwrap();
//!         key_set.verify_share(share, enc, i, &proof).unwrap()
//!     });
//!
//! // Combine decryption shares.
//! let combined = params.combine_shares(dec_shares.enumerate()).unwrap();
//! // Use a lookup table to decrypt back to scalar.
//! let lookup_table = DiscreteLogTable::<Ristretto>::new(0..10);
//! let dec = combined.decrypt(enc, &lookup_table);
//! assert_eq!(dec, Some(encrypted_value));
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};

use core::{cmp::Ordering, fmt, ops};

use crate::{alloc::Vec, group::Group, proofs::VerificationError, VerifiableDecryption};

mod key_set;
mod participant;

pub use self::{
    key_set::PublicKeySet,
    participant::{ActiveParticipant, Dealer},
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

/// Structure representing public polynomial consisting of group elements.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub(crate) struct PublicPolynomial<G: Group>(
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ElementHelper<G>, 1>"))]
    Vec<G::Element>,
);

impl<G: Group> PublicPolynomial<G> {
    pub(crate) fn new(values: Vec<G::Element>) -> Self {
        Self(values)
    }

    fn value_at_zero(&self) -> G::Element {
        self.0[0]
    }

    /// Computes value of this public polynomial at the specified point in variable time.
    pub(crate) fn value_at(&self, x: G::Scalar) -> G::Element {
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
            Self::InvalidDealerProof(err) => write!(
                formatter,
                "proof of possession supplied with the dealer's public polynomial \
                 is invalid: {err}"
            ),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub const fn new(shares: usize, threshold: usize) -> Self {
        assert!(shares > 0);
        assert!(threshold > 0 && threshold <= shares);
        Self { shares, threshold }
    }

    /// Combines shares decrypting the specified `ciphertext`. The shares must be provided
    /// together with the 0-based indexes of the participants they are coming from.
    ///
    /// Returns the combined decryption, or `None` if the number of shares is insufficient.
    ///
    /// # Panics
    ///
    /// Panics if any index in `shares` exceeds the maximum participant's index as per `params`.
    pub fn combine_shares<G: Group>(
        self,
        shares: impl IntoIterator<Item = (usize, VerifiableDecryption<G>)>,
    ) -> Option<VerifiableDecryption<G>> {
        let (indexes, shares): (Vec<_>, Vec<_>) = shares
            .into_iter()
            .take(self.threshold)
            .map(|(index, share)| (index, *share.as_element()))
            .unzip();
        if shares.len() < self.threshold {
            return None;
        }
        assert!(
            indexes.iter().all(|&index| index < self.shares),
            "Invalid share indexes {:?}; expected values in 0..{}",
            indexes.iter().copied(),
            self.shares
        );

        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let restored_value = G::vartime_multi_mul(&denominators, shares);
        let dh_element = restored_value * &scale;
        Some(VerifiableDecryption::from_element(dh_element))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{curve25519::scalar::Scalar as Scalar25519, group::Ristretto};

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
}
