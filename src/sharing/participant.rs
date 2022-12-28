//! Types representing participant state.

// TODO: Use a publicly verifiable scheme, e.g. Schoenmakers?
// https://www.win.tue.nl/~berry/papers/crypto99.pdf

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::iter;

use crate::{
    alloc::Vec,
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession},
    sharing::{Error, Params, PublicKeySet},
    Ciphertext, Keypair, PublicKey, SecretKey, VerifiableDecryption,
};

/// Dealer in a [Feldman verifiable secret sharing][feldman-vss] scheme.
///
/// [feldman-vss]: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Dealer<G: Group> {
    params: Params,
    polynomial: Vec<Keypair<G>>,
    proof_of_possession: ProofOfPossession<G>,
}

impl<G: Group> Dealer<G> {
    /// Instantiates a dealer.
    pub fn new<R: CryptoRng + RngCore>(params: Params, rng: &mut R) -> Self {
        let polynomial: Vec<_> = (0..params.threshold)
            .map(|_| Keypair::<G>::generate(rng))
            .collect();

        let mut transcript = Transcript::new(b"elgamal_share_poly");
        transcript.append_u64(b"n", params.shares as u64);
        transcript.append_u64(b"t", params.threshold as u64);

        let proof_of_possession = ProofOfPossession::new(&polynomial, &mut transcript, rng);

        Self {
            params,
            polynomial,
            proof_of_possession,
        }
    }

    /// Returns public participant information: dealer's public polynomial and proof
    /// of possession for the corresponding secret polynomial.
    pub fn public_info(&self) -> (Vec<G::Element>, &ProofOfPossession<G>) {
        let public_polynomial = self
            .polynomial
            .iter()
            .map(|pair| pair.public().as_element())
            .collect();
        (public_polynomial, &self.proof_of_possession)
    }

    /// Returns a secret share for a participant with the specified `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of allowed bounds.
    pub fn secret_share_for_participant(&self, index: usize) -> SecretKey<G> {
        assert!(
            index < self.params.shares,
            "participant index {index} out of bounds, expected a value in 0..{}",
            self.params.shares
        );

        let power = G::Scalar::from(index as u64 + 1);
        let mut poly_value = SecretKey::new(G::Scalar::from(0));
        for keypair in self.polynomial.iter().rev() {
            poly_value = poly_value * &power + keypair.secret().clone();
        }
        poly_value
    }
}

/// Personalized state of a participant of a threshold ElGamal encryption scheme
/// once the participant receives the secret share from the [`Dealer`].
/// At this point, the participant can produce [`VerifiableDecryption`]s.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct ActiveParticipant<G: Group> {
    key_set: PublicKeySet<G>,
    index: usize,
    secret_share: SecretKey<G>,
}

impl<G: Group> ActiveParticipant<G> {
    /// Creates the participant state based on readily available components.
    ///
    /// # Errors
    ///
    /// Returns an error if `secret_share` does not correspond to the participant's public key share
    /// in `key_set`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is greater or equal than the number of participants in `key_set`.
    pub fn new(
        key_set: PublicKeySet<G>,
        index: usize,
        secret_share: SecretKey<G>,
    ) -> Result<Self, Error> {
        let expected_element = key_set.participant_keys()[index].as_element();
        if G::mul_generator(secret_share.expose_scalar()) == expected_element {
            Ok(Self {
                key_set,
                index,
                secret_share,
            })
        } else {
            Err(Error::InvalidSecret)
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
        &self.key_set.participant_keys()[self.index]
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

    /// Creates a [`VerifiableDecryption`] for the specified `ciphertext` together with a proof
    /// of its validity. `rng` is used to generate the proof.
    pub fn decrypt_share<R>(
        &self,
        ciphertext: Ciphertext<G>,
        rng: &mut R,
    ) -> (VerifiableDecryption<G>, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let dh_element = ciphertext.random_element * self.secret_share.expose_scalar();
        let our_public_key = self.public_key_share().as_element();
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
        (VerifiableDecryption::from_element(dh_element), proof)
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{curve25519::scalar::Scalar as Scalar25519, group::Ristretto};

    #[test]
    fn shared_2_of_3_key() {
        let mut rng = thread_rng();
        let params = Params::new(3, 2);

        let dealer = Dealer::<Ristretto>::new(params, &mut rng);
        let (public_poly, public_poly_proof) = dealer.public_info();
        let key_set = PublicKeySet::new(params, public_poly, public_poly_proof).unwrap();

        let alice_share = dealer.secret_share_for_participant(0);
        let alice = ActiveParticipant::new(key_set.clone(), 0, alice_share).unwrap();
        let bob_share = dealer.secret_share_for_participant(1);
        let bob = ActiveParticipant::new(key_set.clone(), 1, bob_share).unwrap();
        let carol_share = dealer.secret_share_for_participant(2);
        let carol = ActiveParticipant::new(key_set.clone(), 2, carol_share).unwrap();

        key_set
            .verify_participant(0, &alice.proof_of_possession(&mut rng))
            .unwrap();
        key_set
            .verify_participant(1, &bob.proof_of_possession(&mut rng))
            .unwrap();
        key_set
            .verify_participant(2, &carol.proof_of_possession(&mut rng))
            .unwrap();
        assert!(key_set
            .verify_participant(1, &alice.proof_of_possession(&mut rng))
            .is_err());

        let ciphertext = key_set.shared_key().encrypt(15_u64, &mut rng);
        let (alice_share, proof) = alice.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(alice_share.into(), ciphertext, 0, &proof)
            .unwrap();

        let (bob_share, proof) = bob.decrypt_share(ciphertext, &mut rng);
        key_set
            .verify_share(bob_share.into(), ciphertext, 1, &proof)
            .unwrap();

        // We need to find `a0` from the following equations:
        // a0 +   a1 = alice_share.dh_element;
        // a0 + 2*a1 = bob_share.dh_element;
        let composite_dh_element =
            *alice_share.as_element() * Scalar25519::from(2_u64) - *bob_share.as_element();
        let message = Ristretto::mul_generator(&Scalar25519::from(15_u64));
        assert_eq!(composite_dh_element, ciphertext.blinded_element - message);
    }
}
