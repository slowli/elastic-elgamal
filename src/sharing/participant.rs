//! Types representing participant state.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use std::{collections::HashSet, iter};

#[cfg(feature = "serde")]
use crate::serde::{ElementHelper, VecHelper};
use crate::{
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession},
    sharing::{lagrange_coefficients, Error, Params, PartialPublicKeySet, PublicKeySet},
    Ciphertext, Keypair, PublicKey, SecretKey,
};

/// Personalized state of a participant of a threshold ElGamal encryption scheme
/// at the initial step of the protocol, before the [`PublicKeySet`] is determined.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct StartingParticipant<G: Group> {
    params: Params,
    index: usize,
    polynomial: Vec<Keypair<G>>,
    proof_of_possession: ProofOfPossession<G>,
}

impl<G: Group> StartingParticipant<G> {
    /// Creates participant information generating all necessary secrets and proofs.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds as per `params`.
    pub fn new<R>(params: Params, index: usize, rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        assert!(
            index < params.shares,
            "participant index {} is out of bounds; expected a value in 0..{}",
            index,
            params.shares
        );

        let polynomial: Vec<_> = (0..params.threshold)
            .map(|_| Keypair::<G>::generate(rng))
            .collect();

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", params.shares as u64);
        transcript.append_u64(b"t", params.threshold as u64);
        transcript.append_u64(b"i", index as u64);

        let proof_of_possession = ProofOfPossession::new(&polynomial, &mut transcript, rng);

        Self {
            params,
            index,
            polynomial,
            proof_of_possession,
        }
    }

    /// Returns public participant information: participant's public polynomial and proof
    /// of possession for the corresponding secret polynomial.
    pub fn public_info(&self) -> (Vec<G::Element>, &ProofOfPossession<G>) {
        let public_polynomial = self
            .polynomial
            .iter()
            .map(|pair| pair.public().element)
            .collect();
        (public_polynomial, &self.proof_of_possession)
    }

    /// Transforms the participant's state after collecting public info from all participants
    /// in `key_set`. Returns `None` if `key_set` does not have full public info from all
    /// participants.
    ///
    /// # Panics
    ///
    /// Panics if `key_set` has different parameters than [`Params`] supplied when creating
    /// this participant state.
    pub fn finalize_key_set(
        &self,
        key_set: &PartialPublicKeySet<G>,
    ) -> Option<ParticipantExchangingSecrets<G>> {
        assert_eq!(key_set.params, self.params);
        let participant_commitments = key_set.commitments_for_participant(self.index)?;
        let key_set = key_set.complete()?;

        let messages: Vec<_> = (0..self.params.shares)
            .map(|index| {
                let power = G::Scalar::from(index as u64 + 1);
                let mut poly_value = SecretKey::new(G::Scalar::from(0));
                for keypair in self.polynomial.iter().rev() {
                    poly_value = poly_value * &power + keypair.secret().clone();
                }
                poly_value
            })
            .collect();
        let starting_share = messages[self.index].clone();

        Some(ParticipantExchangingSecrets {
            key_set,
            index: self.index,
            secret_share: starting_share,
            messages_to_others: messages,
            participant_commitments,
            received_messages: HashSet::new(),
        })
    }
}

/// Personalized state of a participant of a threshold ElGamal encryption scheme
/// at the intermediate step of the protocol, after the [`PublicKeySet`] is determined
/// but before the participant gets messages from all other participants.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ParticipantExchangingSecrets<G: Group> {
    key_set: PublicKeySet<G>,
    index: usize,
    messages_to_others: Vec<SecretKey<G>>,
    secret_share: SecretKey<G>,
    #[cfg_attr(feature = "serde", serde(with = "VecHelper::<ElementHelper<G>, 1>"))]
    participant_commitments: Vec<G::Element>,
    received_messages: HashSet<usize>,
}

impl<G: Group> ParticipantExchangingSecrets<G> {
    /// Returns a message that should be sent to a scheme participant with the specified index.
    /// The message is not encrypted; it must be encrypted separately.
    pub fn message(&self, participant_index: usize) -> &SecretKey<G> {
        &self.messages_to_others[participant_index]
    }

    /// Checks whether we have received a message from a specific participant.
    pub fn has_message(&self, participant_index: usize) -> bool {
        self.index == participant_index || self.received_messages.contains(&participant_index)
    }

    /// Checks whether we have received messages from all other participants.
    pub fn is_complete(&self) -> bool {
        self.received_messages.len() == self.key_set.params.shares - 1
    }

    /// Completes the sharing protocol.
    ///
    /// # Panics
    ///
    /// Panics if the protocol cannot be completed at this element, i.e., [`Self::is_complete()`]
    /// returns `false`.
    pub fn complete(self) -> ActiveParticipant<G> {
        assert!(self.is_complete(), "cannot complete protocol at this point");
        debug_assert!(bool::from(
            G::mul_generator(&self.secret_share.0)
                .ct_eq(&self.key_set.participant_keys[self.index].element)
        ));

        ActiveParticipant {
            index: self.index,
            key_set: self.key_set,
            secret_share: self.secret_share,
        }
    }

    /// Processes a message from a participant with the specified index.
    ///
    /// # Errors
    ///
    /// Returns an error if the message does not correspond to the participant's commitment.
    ///
    /// # Panics
    ///
    /// Panics if `participant_index` is invalid, or if the message from this participant
    /// was already processed. (The latter can be checked via [`Self::has_message()`].)
    pub fn process_message(
        &mut self,
        participant_index: usize,
        message: SecretKey<G>,
    ) -> Result<(), Error> {
        assert!(
            participant_index < self.key_set.params.shares,
            "participant index {} out of bounds; expected value in 0..{}",
            participant_index,
            self.key_set.params.shares
        );
        assert!(
            !self.has_message(participant_index),
            "message from participant #{} was already processed",
            participant_index
        );

        // Check that the received value is valid.
        let expected_value = &self.participant_commitments[participant_index];
        if !bool::from(expected_value.ct_eq(&G::mul_generator(&message.0))) {
            return Err(Error::InvalidSecret);
        }

        self.received_messages.insert(participant_index);
        self.secret_share += message;
        Ok(())
    }
}

/// Personalized state of a participant of a threshold ElGamal encryption scheme once the participant
/// receives all necessary messages. At this point, the participant can produce
/// [`DecryptionShare`]s.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ActiveParticipant<G: Group> {
    key_set: PublicKeySet<G>,
    index: usize,
    secret_share: SecretKey<G>,
}

impl<G: Group> ActiveParticipant<G> {
    /// Creates the participant state based on readily available components. This is
    /// useful to restore previously persisted state.
    ///
    /// # Panics
    ///
    /// Panics if `secret_share` does not correspond to the participant's public key share
    /// in `key_set`.
    pub fn new(key_set: PublicKeySet<G>, index: usize, secret_share: SecretKey<G>) -> Self {
        assert!(
            bool::from(
                G::mul_generator(&secret_share.0).ct_eq(&key_set.participant_keys[index].element)
            ),
            "Secret key share does not correspond to public key share"
        );

        Self {
            key_set,
            index,
            secret_share,
        }
    }

    /// Returns the public key set for the threshold ElGamal encryption scheme this participant
    /// is a part of.
    pub fn key_set(&self) -> &PublicKeySet<G> {
        &self.key_set
    }

    /// Returns 0-based index of this participant.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns share of the secret key for this participant. This is secret information that
    /// must not be shared.
    pub fn secret_share(&self) -> &SecretKey<G> {
        &self.secret_share
    }

    /// Returns share of the public key for this participant.
    pub fn public_key_share(&self) -> &PublicKey<G> {
        &self.key_set.participant_keys[self.index]
    }

    /// Generates a [`ProofOfPossession`] of the participant's
    /// [`secret_share`](Self::secret_share()).
    pub fn proof_of_possession<R: CryptoRng + RngCore>(&self, rng: &mut R) -> ProofOfPossession<G> {
        let mut transcript = Transcript::new(b"elgamal_participant_pop");
        self.key_set.commit(&mut transcript);
        transcript.append_u64(b"i", self.index as u64);
        ProofOfPossession::from_keys(
            iter::once(&self.secret_share),
            iter::once(self.public_key_share()),
            &mut transcript,
            rng,
        )
    }

    /// Creates a [`DecryptionShare`] for the specified `ciphertext` together with a proof
    /// of its validity. `rng` is used to generate the proof.
    pub fn decrypt_share<R>(
        &self,
        ciphertext: Ciphertext<G>,
        rng: &mut R,
    ) -> (DecryptionShare<G>, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let dh_element = ciphertext.random_element * &self.secret_share.0;
        let our_public_key = self.key_set.participant_keys[self.index].element;
        let mut transcript = Transcript::new(b"elgamal_decryption_share");
        self.key_set.commit(&mut transcript);
        transcript.append_u64(b"i", self.index as u64);

        let proof = LogEqualityProof::new(
            &PublicKey::from_element(ciphertext.random_element),
            &self.secret_share,
            (our_public_key, dh_element),
            &mut transcript,
            rng,
        );
        (DecryptionShare { dh_element }, proof)
    }
}

/// Decryption share for a certain [`Ciphertext`] in a threshold ElGamal encryption scheme.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DecryptionShare<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    dh_element: G::Element,
}

impl<G: Group> DecryptionShare<G> {
    pub(super) fn new(dh_element: G::Element) -> Self {
        Self { dh_element }
    }

    /// Combines shares decrypting the specified `ciphertext`. The shares must be provided
    /// together with the 0-based indexes of the participants they are coming from.
    ///
    /// Returns the decrypted value, or `None` if the number of shares is insufficient.
    ///
    /// # Panics
    ///
    /// Panics if any index in `shares` exceeds the maximum participant's index as per `params`.
    pub fn combine(
        params: Params,
        ciphertext: Ciphertext<G>,
        shares: impl IntoIterator<Item = (usize, Self)>,
    ) -> Option<G::Element> {
        let (indexes, shares): (Vec<_>, Vec<_>) = shares
            .into_iter()
            .take(params.threshold)
            .map(|(index, share)| (index, share.dh_element))
            .unzip();
        if shares.len() < params.threshold {
            return None;
        }
        assert!(
            indexes.iter().all(|&index| index < params.shares),
            "Invalid share indexes {:?}; expected values in 0..{}",
            indexes.iter().copied(),
            params.shares
        );

        let (denominators, scale) = lagrange_coefficients::<G>(&indexes);
        let restored_value = G::vartime_multi_mul(&denominators, shares);
        let dh_element = restored_value * &scale;
        Some(ciphertext.blinded_element - dh_element)
    }

    /// Serializes this share into bytes.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
        G::serialize_element(&self.dh_element, &mut bytes);
        bytes
    }
}

/// Candidate for a [`DecryptionShare`] that is not yet verified using
/// [`PublicKeySet::verify_share()`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct CandidateShare<G: Group> {
    inner: DecryptionShare<G>,
}

impl<G: Group> CandidateShare<G> {
    /// Deserializes a share from `bytes`. Returns `None` if the share is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == G::ELEMENT_SIZE {
            let dh_element = G::deserialize_element(bytes)?;
            Some(Self {
                inner: DecryptionShare { dh_element },
            })
        } else {
            None
        }
    }

    pub(super) fn dh_element(self) -> G::Element {
        self.inner.dh_element
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;
    use rand::thread_rng;

    use super::*;
    use crate::group::Ristretto;

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
        let alice: StartingParticipant<Ristretto> = StartingParticipant::new(params, 0, &mut rng);
        let (alice_poly, alice_proof) = alice.public_info();
        assert_eq!(
            alice_poly,
            [Ristretto::mul_generator(&alice.polynomial[0].secret().0)]
        );
        let bob: StartingParticipant<Ristretto> = StartingParticipant::new(params, 1, &mut rng);
        let (bob_poly, bob_proof) = bob.public_info();
        assert_eq!(
            bob_poly,
            [Ristretto::mul_generator(&bob.polynomial[0].secret().0)]
        );

        let mut group_info = PartialPublicKeySet::new(params);
        group_info
            .add_participant(0, alice_poly, alice_proof)
            .unwrap();
        group_info.add_participant(1, bob_poly, bob_proof).unwrap();
        assert!(group_info.is_complete());

        let joint_secret = alice.polynomial[0].secret().0 + bob.polynomial[0].secret().0;
        let joint_pt = Ristretto::mul_generator(&joint_secret);

        let mut alice = alice.finalize_key_set(&group_info).unwrap();
        let a2b_message = alice.message(1).clone();
        let mut bob = bob.finalize_key_set(&group_info).unwrap();
        let b2a_message = bob.message(0).clone();
        bob.process_message(0, a2b_message).unwrap();
        alice.process_message(1, b2a_message).unwrap();

        let alice = alice.complete();
        let bob = bob.complete();
        assert_eq!(alice.secret_share.0, joint_secret);
        assert_eq!(bob.secret_share.0, joint_secret);

        let group_info = group_info.complete().unwrap();
        assert_eq!(group_info.shared_key.element, joint_pt);
        assert_eq!(
            group_info.participant_keys,
            vec![PublicKey::from_element(joint_pt); 2]
        );

        let ciphertext = group_info.shared_key.encrypt(5_u64, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(ciphertext, &mut rng);
        let alice_share = group_info
            .verify_share(alice_share.to_candidate(), ciphertext, 0, &proof)
            .unwrap();

        let (bob_share, proof) = bob.decrypt_share(ciphertext, &mut rng);
        let bob_share = group_info
            .verify_share(bob_share.to_candidate(), ciphertext, 1, &proof)
            .unwrap();

        let message = Ristretto::mul_generator(&Scalar25519::from(5_u64));
        assert_eq!(alice_share.dh_element, ciphertext.blinded_element - message);
        assert_eq!(alice_share.dh_element, bob_share.dh_element);
    }

    #[test]
    fn shared_2_of_3_key() {
        let mut rng = thread_rng();
        let params = Params::new(3, 2);

        let alice = StartingParticipant::<Ristretto>::new(params, 0, &mut rng);
        let (alice_poly, alice_proof) = alice.public_info();
        let bob = StartingParticipant::<Ristretto>::new(params, 1, &mut rng);
        let (bob_poly, bob_proof) = bob.public_info();
        let carol = StartingParticipant::<Ristretto>::new(params, 2, &mut rng);
        let (carol_poly, carol_proof) = carol.public_info();

        let mut key_set = PartialPublicKeySet::<Ristretto>::new(params);
        key_set.add_participant(0, alice_poly, alice_proof).unwrap();
        key_set.add_participant(1, bob_poly, bob_proof).unwrap();
        key_set.add_participant(2, carol_poly, carol_proof).unwrap();
        assert!(key_set.is_complete());

        let secret0 = alice.polynomial[0].secret().0
            + bob.polynomial[0].secret().0
            + carol.polynomial[0].secret().0;
        let pt0 = Ristretto::mul_generator(&secret0);
        let secret1 = alice.polynomial[1].secret().0
            + bob.polynomial[1].secret().0
            + carol.polynomial[1].secret().0;
        let pt1 = Ristretto::mul_generator(&secret1);

        let mut alice = alice.finalize_key_set(&key_set).unwrap();
        let mut bob = bob.finalize_key_set(&key_set).unwrap();
        let mut carol = carol.finalize_key_set(&key_set).unwrap();
        let mut actors = vec![&mut alice, &mut bob, &mut carol];
        for i in 0..3 {
            for j in 0..3 {
                if j != i {
                    let message = actors[i].message(j).clone();
                    actors[j].process_message(i, message).unwrap();
                }
            }
        }
        assert!(actors.iter().all(|actor| actor.is_complete()));

        let key_set = key_set.complete().unwrap();
        assert_eq!(key_set.shared_key.element, pt0);
        assert_eq!(
            key_set.participant_keys,
            vec![
                PublicKey::from_element(pt0 + pt1),
                PublicKey::from_element(pt0 + pt1 * Scalar25519::from(2_u32)),
                PublicKey::from_element(pt0 + pt1 * Scalar25519::from(3_u32)),
            ]
        );

        let alice = alice.complete();
        assert_eq!(alice.secret_share.0, secret0 + secret1);
        let bob = bob.complete();
        assert_eq!(
            bob.secret_share.0,
            secret0 + secret1 * Scalar25519::from(2_u32)
        );
        let carol = carol.complete();
        assert_eq!(
            carol.secret_share.0,
            secret0 + secret1 * Scalar25519::from(3_u32)
        );

        assert!(key_set.verify_participant(0, &alice.proof_of_possession(&mut rng)));
        assert!(key_set.verify_participant(1, &bob.proof_of_possession(&mut rng)));
        assert!(key_set.verify_participant(2, &carol.proof_of_possession(&mut rng)));
        assert!(!key_set.verify_participant(1, &alice.proof_of_possession(&mut rng)));

        let ciphertext = key_set.shared_key.encrypt(15_u64, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(ciphertext, &mut rng);
        assert!(key_set
            .verify_share(alice_share.to_candidate(), ciphertext, 0, &proof,)
            .is_some());

        let (bob_share, proof) = bob.decrypt_share(ciphertext, &mut rng);
        assert!(key_set
            .verify_share(bob_share.to_candidate(), ciphertext, 1, &proof,)
            .is_some());

        // We need to find `a0` from the following equations:
        // a0 +   a1 = alice_share.dh_element;
        // a0 + 2*a1 = bob_share.dh_element;
        let composite_dh_element =
            alice_share.dh_element * Scalar25519::from(2_u64) - bob_share.dh_element;
        let message = Ristretto::mul_generator(&Scalar25519::from(15_u64));
        assert_eq!(composite_dh_element, ciphertext.blinded_element - message);
    }
}
