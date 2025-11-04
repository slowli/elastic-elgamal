//! Committed Pedersen's distributed key generation (DKG).
//!
//! DKG allows to securely generate shared secret without a need for a trusted
//! dealer. Compare with Feldman's verifiable secret sharing implemented in the [`sharing`] module
//! which requires a trusted dealer.
//!
//! This implementation is based on [Pedersen's DKG], which was shown by [Gennaro et al.]
//! to contain a flaw allowing an adversary to bias distribution of the shared public key.
//! We try to prevent this kind of possible attacks by forcing the parties to
//! commit to their public key shares before receiving public shares from other
//! parties.
//!
//! [Pedersen's DKG]: https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf
//! [Gennaro et al.]: https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf
//!
//! # Examples
//!
//! Decentralized key generation for 2-of-3 threshold encryption.
//!
//! ```
//! # use elastic_elgamal::{
//! #     group::Ristretto, dkg::*, sharing::Params,
//! # };
//! # use std::error::Error as StdError;
//! # fn main() -> Result<(), Box<dyn StdError>> {
//! let mut rng = rand::rng();
//! let params = Params::new(3, 2);
//!
//! // Initialize participants.
//! let participants = (0..3).map(|i| {
//!     ParticipantCollectingCommitments::<Ristretto>::new(params, i, &mut rng)
//! });
//! let mut participants: Vec<_> = participants.collect();
//!
//! // Publish commitments from all participants...
//! let commitments: Vec<_> = participants
//!     .iter()
//!     .map(|participant| participant.commitment())
//!     .collect();
//! // ...and consume them from each participant's perspective.
//! for (i, participant) in participants.iter_mut().enumerate() {
//!     for (j, &commitment) in commitments.iter().enumerate() {
//!         if i != j {
//!             participant.insert_commitment(j, commitment);
//!         }
//!     }
//! }
//!
//! // Transition all participants to the next stage: exchanging polynomials.
//! let mut participants: Vec<_> = participants
//!     .into_iter()
//!     .map(|participant| participant.finish_commitment_phase())
//!     .collect();
//! // Publish each participant's polynomial...
//! let infos: Vec<_> = participants
//!     .iter()
//!     .map(|participant| participant.public_info().into_owned())
//!     .collect();
//! // ...and consume them from each participant's perspective.
//! for (i, participant) in participants.iter_mut().enumerate() {
//!     for (j, info) in infos.iter().enumerate() {
//!         if i != j {
//!             participant.insert_public_polynomial(j, info.clone())?;
//!         }
//!     }
//! }
//!
//! // Transition all participants to the final phase: exchanging secrets.
//! let mut participants: Vec<_> = participants
//!     .into_iter()
//!     .map(|participant| participant.finish_polynomials_phase())
//!     .collect();
//! // Exchange shares (this should happen over secure peer-to-peer channels).
//! for i in 0..3 {
//!     for j in 0..3 {
//!         if i == j { continue; }
//!         let share = participants[i].secret_share_for_participant(j);
//!         participants[j].insert_secret_share(i, share)?;
//!     }
//! }
//!
//! // Finalize all participants.
//! let participants = participants
//!     .into_iter()
//!     .map(|participant| participant.complete())
//!     .collect::<Result<Vec<_>, _>>()?;
//! // Check that the shared key is the same for all participants.
//! let expected_key = participants[0].key_set().shared_key();
//! for participant in &participants {
//!     assert_eq!(participant.key_set().shared_key(), expected_key);
//! }
//!
//! // Participants can then jointly decrypt messages as showcased
//! // in the example for the `sharing` module.
//! # Ok(())
//! # }
//! ```

use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use core::fmt;

#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};
use crate::{
    PublicKey, SecretKey,
    alloc::{Cow, Vec, vec},
    group::Group,
    proofs::ProofOfPossession,
    sharing::{self, ActiveParticipant, Dealer, Params, PublicKeySet, PublicPolynomial},
};

/// Errors that can occur during the distributed key generation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Secret received from the party does not correspond to their commitment via
    /// the public polynomial.
    InvalidSecret,
    /// Provided commitment does not correspond to the party's public key share.
    InvalidCommitment,
    /// Secret share for this participant was already provided.
    DuplicateShare,
    /// Provided proof of possession or public polynomial is malformed.
    MalformedParticipantProof(sharing::Error),
    /// Public shares obtained from accumulated public polynomial are inconsistent.
    InconsistentPublicShares(sharing::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret => formatter.write_str(
                "secret received from the party does not correspond to their commitment via \
                public polynomial",
            ),
            Self::InvalidCommitment => formatter.write_str(
                "public polynomial received from one of the parties does not correspond \
                to their commitment",
            ),
            Self::DuplicateShare => {
                formatter.write_str("secret share for this participant was already provided")
            }
            Self::MalformedParticipantProof(err) => write!(
                formatter,
                "provided proof of possession or public polynomial is malformed: {err}"
            ),
            Self::InconsistentPublicShares(err) => write!(
                formatter,
                "public shares obtained from accumulated public polynomial \
                 are inconsistent: {err}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InconsistentPublicShares(err) | Self::MalformedParticipantProof(err) => Some(err),
            _ => None,
        }
    }
}

fn create_commitment<G: Group>(element: &G::Element, opening: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
    G::serialize_element(element, &mut bytes);
    hasher.update(&bytes);
    hasher.update(opening);
    hasher.finalize().into()
}

/// Opening for a hash commitment used in Pedersen's distributed key generation.
#[derive(Debug, Clone)]
pub struct Opening(pub(crate) Zeroizing<[u8; 32]>);

/// Participant state during the first stage of the committed Pedersen's distributed key generation.
///
/// During this stage, participants exchange commitments to their public keys via
/// a public bulletin board (e.g., a blockchain).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ParticipantCollectingCommitments<G: Group> {
    params: Params,
    index: usize,
    dealer: Dealer<G>,
    commitments: Vec<Option<[u8; 32]>>,
    opening: Opening,
}

impl<G: Group> ParticipantCollectingCommitments<G> {
    /// Instantiates a distributed key generation participant.
    ///
    /// # Panics
    ///
    /// Panics if `index` is greater or equal to the number of shares.
    pub fn new<R: CryptoRng + RngCore>(params: Params, index: usize, rng: &mut R) -> Self {
        assert!(index < params.shares);

        let dealer = Dealer::new(params, rng);
        let mut opening = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(&mut *opening);

        let mut commitments = vec![None; params.shares];
        let (public_poly, _) = dealer.public_info();
        commitments[index] = Some(create_commitment::<G>(&public_poly[0], opening.as_slice()));
        Self {
            params,
            index,
            dealer,
            commitments,
            opening: Opening(opening),
        }
    }

    /// Returns params of this threshold ElGamal encryption scheme.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Returns 0-based index of this participant.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the commitment of participant's share of the joint public key.
    ///
    /// # Panics
    ///
    /// Panics if the commitment is missing which can only happen if this struct got corrupted
    /// (e.g., after deserialization).
    pub fn commitment(&self) -> [u8; 32] {
        self.commitments[self.index].unwrap()
    }

    /// Inserts a commitment from the participant with index `participant_index`.
    ///
    /// # Panics
    ///
    /// Panics if commitment for given participant was already provided or
    /// `participant_index` is out of bounds.
    pub fn insert_commitment(&mut self, participant_index: usize, commitment: [u8; 32]) {
        assert!(
            self.commitments[participant_index].is_none(),
            "Commitment for participant {participant_index} is already provided"
        );
        self.commitments[participant_index] = Some(commitment);
    }

    /// Returns indices of parties whose commitments were not provided.
    pub fn missing_commitments(&self) -> impl Iterator<Item = usize> + '_ {
        self.commitments
            .iter()
            .enumerate()
            .filter_map(|(i, commitment)| commitment.is_none().then_some(i))
    }

    /// Proceeds to the next step of the DKG protocol, in which participants exchange public
    /// polynomials.
    ///
    /// # Panics
    ///
    /// Panics if any commitments are missing. If this is not known statically, check
    /// with [`Self::missing_commitments()`] before calling this method.
    pub fn finish_commitment_phase(self) -> ParticipantCollectingPolynomials<G> {
        if let Some(missing_idx) = self.missing_commitments().next() {
            panic!("Missing commitment for participant {missing_idx}");
        }

        let (public_polynomial, _) = self.dealer.public_info();
        let mut public_polynomials = vec![None; self.params.shares];
        public_polynomials[self.index] = Some(PublicPolynomial::new(public_polynomial));
        ParticipantCollectingPolynomials {
            params: self.params,
            index: self.index,
            dealer: self.dealer,
            opening: self.opening,
            commitments: self.commitments.into_iter().map(Option::unwrap).collect(),
            // ^ `unwrap()` is safe due to the above checks
            public_polynomials,
        }
    }
}

/// Public participant information in the distributed key generation protocol. Returned by
/// [`ParticipantCollectingPolynomials::public_info()`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct PublicInfo<'a, G: Group> {
    /// Participant's public polynomial.
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ElementHelper<G>, 1>"))]
    pub polynomial: Vec<G::Element>,
    /// Proof of possession for the secret polynomial that corresponds to `polynomial`.
    pub proof_of_possession: Cow<'a, ProofOfPossession<G>>,
    /// Opening for the participant's key commitment.
    pub opening: Opening,
}

impl<G: Group> PublicInfo<'_, G> {
    /// Converts this information to the owned form.
    pub fn into_owned(self) -> PublicInfo<'static, G> {
        PublicInfo {
            polynomial: self.polynomial,
            proof_of_possession: Cow::Owned(self.proof_of_possession.into_owned()),
            opening: self.opening,
        }
    }
}

/// Participant state during the second stage of the committed Pedersen's distributed key generation.
///
/// During this stage, participants exchange public polynomials and openings for the commitments
/// exchanged on the previous stage. The exchange happens using a public bulletin board
/// (e.g., a blockchain).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ParticipantCollectingPolynomials<G: Group> {
    params: Params,
    index: usize,
    dealer: Dealer<G>,
    opening: Opening,
    commitments: Vec<[u8; 32]>,
    public_polynomials: Vec<Option<PublicPolynomial<G>>>,
}

impl<G: Group> ParticipantCollectingPolynomials<G> {
    /// Returns params of this threshold ElGamal encryption scheme.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Returns 0-based index of this participant.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns public participant information: participant's public polynomial,
    /// proof of possession for the corresponding secret polynomial and the opening of
    /// the participant's public key share commitment.
    pub fn public_info(&self) -> PublicInfo<'_, G> {
        let (polynomial, proof) = self.dealer.public_info();
        PublicInfo {
            polynomial,
            proof_of_possession: Cow::Borrowed(proof),
            opening: self.opening.clone(),
        }
    }

    /// Returns the indices of parties whose public polynomials were not provided.
    pub fn missing_public_polynomials(&self) -> impl Iterator<Item = usize> + '_ {
        self.public_polynomials
            .iter()
            .enumerate()
            .filter_map(|(i, poly)| poly.is_none().then_some(i))
    }

    /// Inserts public polynomial from participant with index `participant_index`
    /// their proof of possession of the public polynomial and opening of
    /// their previously provided commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if provided polynomial doesn't correspond to the previous
    /// commitment or the proof of possession is not valid.
    ///
    /// # Panics
    ///
    /// Panics if `participant_index` is out of bounds.
    pub fn insert_public_polynomial(
        &mut self,
        participant_index: usize,
        info: PublicInfo<'_, G>,
    ) -> Result<(), Error> {
        let opening = info.opening.0.as_slice();
        let commitment = create_commitment::<G>(&info.polynomial[0], opening);
        if self.commitments[participant_index] != commitment {
            // provided commitment doesn't match the given public key share
            return Err(Error::InvalidCommitment);
        }

        PublicKeySet::validate(self.params, &info.polynomial, &info.proof_of_possession)
            .map_err(Error::MalformedParticipantProof)?;
        self.public_polynomials[participant_index] = Some(PublicPolynomial::new(info.polynomial));
        Ok(())
    }

    /// Proceeds to the next step of the DKG protocol, in which participants exchange
    /// secret shares.
    ///
    /// # Panics
    ///
    /// Panics if any public polynomials are missing. If this is not known statically, check
    /// with [`Self::missing_public_polynomials()`] before calling this method.
    pub fn finish_polynomials_phase(self) -> ParticipantExchangingSecrets<G> {
        if let Some(missing_idx) = self.missing_public_polynomials().next() {
            panic!("Missing public polynomial for participant {missing_idx}");
        }

        let mut shares_received = vec![false; self.params.shares];
        shares_received[self.index] = true;
        ParticipantExchangingSecrets {
            params: self.params,
            index: self.index,
            public_polynomials: self.public_polynomials.into_iter().flatten().collect(),
            accumulated_share: self.dealer.secret_share_for_participant(self.index),
            dealer: self.dealer,
            shares_received,
        }
    }
}

/// Participant state during the third and final stage of the committed Pedersen's
/// distributed key generation.
///
/// During this stage, participants exchange secret shares corresponding to the polynomials
/// exchanged on the previous stage. The exchange happens using secure peer-to-peer channels
/// established between pairs of participants.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ParticipantExchangingSecrets<G: Group> {
    params: Params,
    index: usize,
    dealer: Dealer<G>,
    public_polynomials: Vec<PublicPolynomial<G>>,
    accumulated_share: SecretKey<G>,
    shares_received: Vec<bool>,
}

impl<G: Group> ParticipantExchangingSecrets<G> {
    /// Returns params of this threshold ElGamal encryption scheme.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Returns 0-based index of this participant.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the secret share for a participant with the specified `participant_index`.
    pub fn secret_share_for_participant(&self, participant_index: usize) -> SecretKey<G> {
        self.dealer.secret_share_for_participant(participant_index)
    }

    /// Returns indices of parties whose secret shares were not provided.
    pub fn missing_shares(&self) -> impl Iterator<Item = usize> + '_ {
        self.shares_received
            .iter()
            .enumerate()
            .filter_map(|(i, &is_received)| (!is_received).then_some(i))
    }

    /// Inserts a secret share from participant with index `participant_index` and
    /// checks that the share is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if provided secret share doesn't correspond to the participant's
    /// public polynomial collected on the previous step of the DKG protocol.
    ///
    /// # Panics
    ///
    /// Panics if `participant_index` is out of bounds.
    pub fn insert_secret_share(
        &mut self,
        participant_index: usize,
        secret_share: SecretKey<G>,
    ) -> Result<(), Error> {
        if self.shares_received[participant_index] {
            return Err(Error::DuplicateShare);
        }

        let polynomial = &self.public_polynomials[participant_index];
        let idx = (self.index as u64 + 1).into();
        let public_share = PublicKey::<G>::from_element(polynomial.value_at(idx));

        if public_share.as_element() != G::mul_generator(secret_share.expose_scalar()) {
            // point corresponding to the received secret share doesn't lie
            // on the public polynomial
            return Err(Error::InvalidSecret);
        }

        self.accumulated_share += secret_share;
        self.shares_received[participant_index] = true;
        Ok(())
    }

    /// Completes the distributed key generation protocol returning an [`ActiveParticipant`].
    ///
    /// # Errors
    ///
    /// Returns error if secret shares from some parties were not provided,
    /// or if the [`PublicKeySet`] cannot be created from participants' keys.
    ///
    /// # Panics
    ///
    /// Panics if shares from any participants are missing. If this is not known statically, check
    /// with [`Self::missing_shares()`] before calling this method.
    pub fn complete(self) -> Result<ActiveParticipant<G>, Error> {
        if let Some(missing_idx) = self.missing_shares().next() {
            panic!("Missing secret share from participant {missing_idx}");
        }

        let accumulated_polynomial = self
            .public_polynomials
            .into_iter()
            .reduce(|mut acc, poly| {
                acc += &poly;
                acc
            })
            .unwrap(); // safe: we have at least ourselves as a participant

        let participant_keys = (0..self.params.shares)
            .map(|idx| {
                let idx = (idx as u64 + 1).into();
                PublicKey::from_element(accumulated_polynomial.value_at(idx))
            })
            .collect();
        let key_set = PublicKeySet::from_participants(self.params, participant_keys)
            .map_err(Error::InconsistentPublicShares)?;

        let active_participant =
            ActiveParticipant::new(key_set, self.index, self.accumulated_share)
                .map_err(Error::InconsistentPublicShares)?;
        Ok(active_participant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encryption::DiscreteLogTable, group::Ristretto, sharing::Params};

    #[test]
    fn dkg_shared_2_of_3_key() {
        let mut rng = rand::rng();
        let params = Params::new(3, 2);

        let mut alice = ParticipantCollectingCommitments::<Ristretto>::new(params, 0, &mut rng);
        assert_eq!(alice.params().shares, params.shares);
        assert_eq!(alice.params().threshold, params.threshold);
        assert_eq!(alice.index(), 0);
        let mut bob = ParticipantCollectingCommitments::<Ristretto>::new(params, 1, &mut rng);
        assert_eq!(bob.index(), 1);
        let mut carol = ParticipantCollectingCommitments::<Ristretto>::new(params, 2, &mut rng);
        assert_eq!(carol.index(), 2);

        assert_eq!(
            alice.missing_commitments().collect::<Vec<_>>(),
            [bob.index(), carol.index()]
        );
        exchange_commitments(&mut alice, &mut bob, &mut carol);

        let mut alice = alice.finish_commitment_phase();
        assert_eq!(alice.params().shares, params.shares);
        assert_eq!(alice.params().threshold, params.threshold);
        assert_eq!(alice.index(), 0);
        let mut bob = bob.finish_commitment_phase();
        assert_eq!(bob.index(), 1);
        let mut carol = carol.finish_commitment_phase();
        assert_eq!(carol.index(), 2);

        assert_eq!(
            alice.missing_public_polynomials().collect::<Vec<_>>(),
            [bob.index(), carol.index()]
        );
        exchange_polynomials(&mut alice, &mut bob, &mut carol).unwrap();

        let mut alice = alice.finish_polynomials_phase();
        assert_eq!(alice.params().shares, params.shares);
        assert_eq!(alice.params().threshold, params.threshold);
        assert_eq!(alice.index(), 0);
        let mut bob = bob.finish_polynomials_phase();
        assert_eq!(bob.index(), 1);
        let mut carol = carol.finish_polynomials_phase();
        assert_eq!(carol.index(), 2);

        exchange_secret_shares(&mut alice, &mut bob, &mut carol).unwrap();

        let alice = alice.complete().unwrap();
        let bob = bob.complete().unwrap();
        carol.complete().unwrap();
        let key_set = alice.key_set();

        let ciphertext = key_set.shared_key().encrypt(15_u64, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(alice_share.into(), ciphertext, alice.index(), &proof)
            .unwrap();

        let (bob_share, proof) = bob.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(bob_share.into(), ciphertext, bob.index(), &proof)
            .unwrap();

        let combined = params
            .combine_shares([(alice.index(), alice_share), (bob.index(), bob_share)])
            .unwrap();
        let lookup_table = DiscreteLogTable::<Ristretto>::new(0..20);

        assert_eq!(combined.decrypt(ciphertext, &lookup_table), Some(15));
    }

    fn exchange_commitments(
        alice: &mut ParticipantCollectingCommitments<Ristretto>,
        bob: &mut ParticipantCollectingCommitments<Ristretto>,
        carol: &mut ParticipantCollectingCommitments<Ristretto>,
    ) {
        let alice_commitment = alice.commitment();
        let bob_commitment = bob.commitment();
        let carol_commitment = carol.commitment();

        alice.insert_commitment(bob.index(), bob_commitment);
        alice.insert_commitment(carol.index(), carol_commitment);
        bob.insert_commitment(alice.index(), alice_commitment);
        bob.insert_commitment(carol.index(), carol_commitment);
        carol.insert_commitment(alice.index(), alice_commitment);
        carol.insert_commitment(bob.index(), bob_commitment);
    }

    fn exchange_polynomials(
        alice: &mut ParticipantCollectingPolynomials<Ristretto>,
        bob: &mut ParticipantCollectingPolynomials<Ristretto>,
        carol: &mut ParticipantCollectingPolynomials<Ristretto>,
    ) -> Result<(), Error> {
        let alice_info = alice.public_info().into_owned();
        let bob_info = bob.public_info().into_owned();
        let carol_info = carol.public_info().into_owned();

        alice.insert_public_polynomial(bob.index(), bob_info.clone())?;
        alice.insert_public_polynomial(carol.index(), carol_info.clone())?;
        bob.insert_public_polynomial(alice.index(), alice_info.clone())?;
        bob.insert_public_polynomial(carol.index(), carol_info)?;
        carol.insert_public_polynomial(alice.index(), alice_info)?;
        carol.insert_public_polynomial(bob.index(), bob_info)?;
        Ok(())
    }

    fn exchange_secret_shares(
        alice: &mut ParticipantExchangingSecrets<Ristretto>,
        bob: &mut ParticipantExchangingSecrets<Ristretto>,
        carol: &mut ParticipantExchangingSecrets<Ristretto>,
    ) -> Result<(), Error> {
        alice.insert_secret_share(bob.index(), bob.secret_share_for_participant(alice.index()))?;
        alice.insert_secret_share(
            carol.index(),
            carol.secret_share_for_participant(alice.index()),
        )?;

        bob.insert_secret_share(
            alice.index(),
            alice.secret_share_for_participant(bob.index()),
        )?;
        bob.insert_secret_share(
            carol.index(),
            carol.secret_share_for_participant(bob.index()),
        )?;

        carol.insert_secret_share(
            alice.index(),
            alice.secret_share_for_participant(carol.index()),
        )?;
        carol.insert_secret_share(bob.index(), bob.secret_share_for_participant(carol.index()))?;
        Ok(())
    }
}
