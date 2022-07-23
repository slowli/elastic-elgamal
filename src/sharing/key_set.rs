//! `PublicKeySet` and associated helpers.

use merlin::Transcript;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use core::{iter, ops};

use super::{lagrange_coefficients, Error, Params};
#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};
use crate::{
    alloc::Vec,
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession, TranscriptForGroup, VerificationError},
    CandidateDecryption, Ciphertext, PublicKey, VerifiableDecryption,
};

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
    ///
    /// [`Dealer`]: crate::sharing::Dealer
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
            .map(PublicKey::as_element)
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
            if interpolated_key != key.as_element() {
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

    pub(super) fn commit(&self, transcript: &mut Transcript) {
        transcript.append_u64(b"n", self.params.shares as u64);
        transcript.append_u64(b"t", self.params.threshold as u64);
        transcript.append_element_bytes(b"K", self.shared_key.as_bytes());
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
        candidate_share: CandidateDecryption<G>,
        ciphertext: Ciphertext<G>,
        index: usize,
        proof: &LogEqualityProof<G>,
    ) -> Result<VerifiableDecryption<G>, VerificationError> {
        let key_share = self.participant_keys[index].as_element();
        let dh_element = candidate_share.dh_element();
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.commit(&mut transcript);
        transcript.append_u64(b"i", index as u64);

        proof.verify(
            &PublicKey::from_element(ciphertext.random_element),
            (key_share, dh_element),
            &mut transcript,
        )?;
        Ok(VerifiableDecryption::from_element(dh_element))
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{
        group::{ElementOps, Ristretto},
        sharing::Dealer,
    };

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
            bogus_keys[i] =
                PublicKey::from_element(bogus_keys[i].as_element() + Ristretto::generator());
            let err = PublicKeySet::from_participants(params, bogus_keys).unwrap_err();
            assert!(matches!(err, Error::MalformedParticipantKeys));
        }
    }
}
