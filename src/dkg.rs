//! Committed Pedersen's distributed key generation.
//!
//! DKG allows to securely generate shared secret without a need for a trusted
//! dealer.
//!
//! This implementation is based on [Pedersen's DKG], which was shown by [Gennaro et al.]
//! to contain flaw allowing an adversary to bias distribution of the shared public key.
//! We try to prevent this kind of possible attacks by forcing the parties to
//! commit to their public key shares before receiving public shares from other
//! parties.
//!
//! [Pedersen's DKG]: https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf
//! [Gennaro et al.]: https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf

use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::fmt;
use sha2::{Digest, Sha256};

use crate::{
    alloc::{vec, Vec},
    group::Group,
    proofs::ProofOfPossession,
    sharing::Dealer,
    sharing::{self, Params, PublicKeySet, PublicPolynomial},
    PublicKey, SecretKey,
};

/// Errors that can occur during the secret sharing protocol.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Secret received from the party does not correspond to their commitment via
    /// the public polynomial.
    InvalidSecret,
    /// Provided commitment does not correspond to the party's public key share.
    InvalidCommitment,
    /// Secret share for this participant was already provided.
    DuplicitShare,
    /// Secret shares from some parties are missing.
    MissingShares,
    /// Provided proof of possession or public polynomial is malformed.
    MalformedParticipantProof(sharing::Error),
    /// Public shares obtained from cumulated public polynomial are inconsistent
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
            Self::DuplicitShare => {
                formatter.write_str("secret share for this participant was already provided")
            }
            Self::MissingShares => {
                formatter.write_str("secret shares from some parties are missing")
            }
            Self::MalformedParticipantProof(err) => {
                write!(
                    formatter,
                    "provided proof of possession or public polynomial is malformed: {err}"
                )
            }
            Self::InconsistentPublicShares(err) => {
                write!(
                    formatter,
                    "public shares obtained from cumulated public polynomial are inconsistent: {err}"
                )
            }
        }
    }
}

/// Structure for collecting commitments of public share in committed Pedersen's
/// distributed key generation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DkgCommitmentsCollector<G: Group> {
    params: Params,
    index: usize,
    dealer: Dealer<G>,
    commitments: Vec<Option<[u8; 32]>>,
    decommitment: [u8; 32],
}

impl<G: Group> DkgCommitmentsCollector<G> {
    /// Instantiates a distributed key generation participant.
    ///
    /// # Panics
    ///
    /// Panics if `index` is greater or equal to number of shares.
    pub fn new<R: CryptoRng + RngCore>(params: Params, index: usize, rng: &mut R) -> Self {
        assert!(index < params.shares);
        let mut decommitment = [0u8; 32];
        rng.fill_bytes(&mut decommitment);
        Self {
            params,
            index,
            dealer: Dealer::new(params, rng),
            commitments: vec![None; params.shares],
            decommitment,
        }
    }

    /// Generates commitment of participant's share of a public key.
    pub fn commitment(&mut self) -> [u8; 32] {
        if let Some(c) = self.commitments[self.index] {
            c
        } else {
            let (public_poly, _) = self.dealer.public_info();
            let mut hasher = Sha256::new();
            let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
            G::serialize_element(&public_poly[0], &mut bytes);
            hasher.update(&bytes);
            hasher.update(self.decommitment);
            let c = hasher.finalize().into();
            self.commitments[self.index] = Some(c);
            c
        }
    }

    /// Inserts commitment from other participant with index `participant_index`.
    pub fn insert_commitment(&mut self, participant_index: usize, commitment: [u8; 32]) {
        self.commitments[participant_index] = Some(commitment);
    }

    /// Returns indices of parties whose commitments were not provided.
    pub fn missing_commitments(&self) -> Vec<usize> {
        self.commitments
            .iter()
            .enumerate()
            .filter_map(|(i, x)| if x.is_none() { Some(i) } else { None })
            .collect()
    }

    /// If all commiements were received returns DkgShareCollector
    /// otherwise returns None.
    pub fn finish_commitment_phase(&self) -> Option<DkgSharesCollector<G>> {
        if !self.missing_commitments().is_empty() {
            return None;
        }

        let mut shares_received = vec![false; self.params.shares];
        shares_received[self.index] = true;
        let (public_polynomial, _) = self.dealer.public_info();
        Some(DkgSharesCollector {
            params: self.params,
            index: self.index,
            dealer: self.dealer.clone(),
            decommitment: self.decommitment,
            commitments: self.commitments.iter().filter_map(|x| *x).collect(),
            cumulated_share: self.dealer.secret_share_for_participant(self.index),
            cumulated_public_poly: PublicPolynomial::<G>(public_polynomial),
            shares_received,
        })
    }
}

/// Structure for collecting secret shares in committed Pedersen's distributed
/// key generation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DkgSharesCollector<G: Group> {
    params: Params,
    index: usize,
    dealer: Dealer<G>,
    decommitment: [u8; 32],
    commitments: Vec<[u8; 32]>,
    cumulated_share: SecretKey<G>,
    cumulated_public_poly: PublicPolynomial<G>,
    shares_received: Vec<bool>,
}

impl<G: Group> DkgSharesCollector<G> {
    /// Returns a secret share for a participant with the specified `participant_index`.
    pub fn secret_share_for_participant(&self, participant_index: usize) -> SecretKey<G> {
        self.dealer.secret_share_for_participant(participant_index)
    }

    /// Returns public participant information: participant's public polynomial,
    /// proof of possession for the corresponding secret polynomial and decommitment.
    pub fn public_info(&self) -> (Vec<G::Element>, ProofOfPossession<G>, [u8; 32]) {
        let (public_polynomial, proof_of_possession) = self.dealer.public_info();
        (
            public_polynomial,
            proof_of_possession.clone(),
            self.decommitment,
        )
    }

    /// Returns indices of parties whose shares were not provided.
    pub fn missing_shares(&self) -> Vec<usize> {
        self.shares_received
            .iter()
            .enumerate()
            .filter_map(|(i, x)| if *x { None } else { Some(i) })
            .collect()
    }

    /// Inserts secret share from participant with index `participant_index` and
    /// checks if the share is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if provided secret share doesn't lie on given public
    /// polynomial or the polynomial doesn't correspond to the previous commitment.
    ///
    /// # Panics
    ///
    /// Panics if `self.index` is greater or equal to number of participants,
    /// which should never happen, unless DkgSharesCollector got corrupted.
    pub fn insert_secret_share(
        &mut self,
        participant_index: usize,
        secret_share: SecretKey<G>,
        public_polynomial: &[G::Element],
        proof_of_possession: &ProofOfPossession<G>,
        decommitment: &[u8; 32],
    ) -> Result<(), Error> {
        if self.shares_received[participant_index] {
            return Err(Error::DuplicitShare);
        }

        // verifies proof of possession of secret polynomial
        let keyset =
            match PublicKeySet::new(self.params, public_polynomial.to_vec(), proof_of_possession) {
                Ok(keyset) => keyset,
                Err(error) => return Err(Error::MalformedParticipantProof(error)),
            };

        let public_share = keyset.participant_key(self.index).unwrap();
        if public_share.as_element() != G::mul_generator(secret_share.expose_scalar()) {
            // point corresponding to the received secret share doesn't lie
            // on the public polynomial
            return Err(Error::InvalidSecret);
        }

        let mut hasher = Sha256::new();
        let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
        G::serialize_element(&public_polynomial[0], &mut bytes);
        hasher.update(&bytes);
        hasher.update(decommitment);
        let c: [u8; 32] = hasher.finalize().into();

        if self.commitments[participant_index] != c {
            // provided commitment doesn't match the given public key share
            return Err(Error::InvalidCommitment);
        }

        self.cumulated_public_poly += &PublicPolynomial::<G>(public_polynomial.to_vec());
        self.cumulated_share += secret_share;
        self.shares_received[participant_index] = true;
        Ok(())
    }

    /// If all secret shares are collected, returns combined secret share and
    /// PublicKeySet containing public keys of all participating parties.
    ///
    /// # Errors
    ///
    /// Returns error if secret shares from some parties were not provided, or
    /// PublicKeySet can not be created.
    pub fn keys(&self) -> Result<(SecretKey<G>, PublicKeySet<G>), Error> {
        if !self.shares_received.iter().all(|x| *x) {
            return Err(Error::MissingShares);
        }

        let participant_keys = (0..self.params.shares)
            .map(|idx| {
                PublicKey::from_element(
                    self.cumulated_public_poly.value_at((idx as u64 + 1).into()),
                )
            })
            .collect();
        let keyset = match PublicKeySet::from_participants(self.params, participant_keys) {
            Ok(keyset) => keyset,
            Err(error) => return Err(Error::InconsistentPublicShares(error)),
        };
        Ok((self.cumulated_share.clone(), keyset))
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{
        curve25519::scalar::Scalar as Scalar25519, group::Ristretto, sharing::ActiveParticipant,
    };
    #[test]
    fn dkg_shared_2_of_3_key() {
        let mut rng = thread_rng();
        let params = Params::new(3, 2);

        let mut commitments_alice = DkgCommitmentsCollector::<Ristretto>::new(params, 0, &mut rng);
        let mut commitments_bob = DkgCommitmentsCollector::<Ristretto>::new(params, 1, &mut rng);
        let mut commitments_carol = DkgCommitmentsCollector::<Ristretto>::new(params, 2, &mut rng);

        let comm_a = commitments_alice.commitment();
        let comm_b = commitments_bob.commitment();
        let comm_c = commitments_carol.commitment();

        assert!(commitments_alice.missing_commitments() == vec![1, 2]);
        commitments_alice.insert_commitment(1, comm_b);
        commitments_alice.insert_commitment(2, comm_c);
        commitments_bob.insert_commitment(0, comm_a);
        commitments_bob.insert_commitment(2, comm_c);
        commitments_carol.insert_commitment(0, comm_a);
        commitments_carol.insert_commitment(1, comm_b);

        let mut dkg_alice = commitments_alice.finish_commitment_phase().unwrap();
        let mut dkg_bob = commitments_bob.finish_commitment_phase().unwrap();
        let mut dkg_carol = commitments_carol.finish_commitment_phase().unwrap();

        let (public_poly_a, public_proof_a, decomm_a) = dkg_alice.public_info();
        let (public_poly_b, public_proof_b, decomm_b) = dkg_bob.public_info();
        let (public_poly_c, public_proof_c, decomm_c) = dkg_carol.public_info();

        assert!(dkg_alice.missing_shares() == vec![1, 2]);
        dkg_alice
            .insert_secret_share(
                1,
                dkg_bob.secret_share_for_participant(0),
                &public_poly_b,
                &public_proof_b,
                &decomm_b,
            )
            .unwrap();
        dkg_alice
            .insert_secret_share(
                2,
                dkg_carol.secret_share_for_participant(0),
                &public_poly_c,
                &public_proof_c,
                &decomm_c,
            )
            .unwrap();
        dkg_bob
            .insert_secret_share(
                0,
                dkg_alice.secret_share_for_participant(1),
                &public_poly_a,
                &public_proof_a,
                &decomm_a,
            )
            .unwrap();
        dkg_bob
            .insert_secret_share(
                2,
                dkg_carol.secret_share_for_participant(1),
                &public_poly_c,
                &public_proof_c,
                &decomm_c,
            )
            .unwrap();
        dkg_carol
            .insert_secret_share(
                0,
                dkg_alice.secret_share_for_participant(2),
                &public_poly_a,
                &public_proof_a,
                &decomm_a,
            )
            .unwrap();
        dkg_carol
            .insert_secret_share(
                1,
                dkg_bob.secret_share_for_participant(2),
                &public_poly_b,
                &public_proof_b,
                &decomm_b,
            )
            .unwrap();

        let (alice_share, _) = dkg_alice.keys().unwrap();

        let (bob_share, _) = dkg_bob.keys().unwrap();

        let (carol_share, key_set) = dkg_carol.keys().unwrap();

        let alice = ActiveParticipant::new(key_set.clone(), 0, alice_share).unwrap();
        let bob = ActiveParticipant::new(key_set.clone(), 1, bob_share).unwrap();
        let _carol = ActiveParticipant::new(key_set.clone(), 2, carol_share).unwrap();

        let ciphertext = key_set.shared_key().encrypt(15_u64, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(alice_share.into(), ciphertext, 0, &proof)
            .unwrap();

        let (bob_share, proof) = bob.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(bob_share.into(), ciphertext, 1, &proof)
            .unwrap();

        let composite_dh_element =
            *alice_share.as_element() * Scalar25519::from(2_u64) - *bob_share.as_element();
        let message = Ristretto::mul_generator(&Scalar25519::from(15_u64));
        assert_eq!(composite_dh_element, ciphertext.blinded_element - message);
    }
}
