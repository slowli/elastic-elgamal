//! Types representing participant state.

// TODO: Use a publicly verifiable scheme, e.g. Schoenmakers?
// https://www.win.tue.nl/~berry/papers/crypto99.pdf

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use core::iter;

#[cfg(feature = "serde")]
use crate::serde::ElementHelper;
use crate::{
    alloc::{vec, Vec},
    group::Group,
    proofs::{LogEqualityProof, ProofOfPossession, TranscriptForGroup},
    sharing::{lagrange_coefficients, Error, Params, PublicKeySet},
    Ciphertext, Keypair, PublicKey, SecretKey, VerificationError,
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
            "participant index {} out of bounds, expected a value in 0..{}",
            index,
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
/// At this point, the participant can produce [`DecryptionShare`]s.
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
    pub fn new(
        key_set: PublicKeySet<G>,
        index: usize,
        secret_share: SecretKey<G>,
    ) -> Result<Self, Error> {
        let expected_element = key_set.participant_keys[index].as_element();
        let valid_share = G::mul_generator(secret_share.expose_scalar()).ct_eq(&expected_element);
        if bool::from(valid_share) {
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
        let dh_element = ciphertext.random_element * self.secret_share.expose_scalar();
        let our_public_key = self.key_set.participant_keys[self.index].as_element();
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
///
/// # Construction
///
/// The share is a single group element – the result of combining
/// participant's secret scalar with the random element of the ciphertext (i.e.,
/// the Diffie – Hellman construction). This element can retrieved using [`Self::as_element()`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct DecryptionShare<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    dh_element: G::Element,
}

impl<G: Group> DecryptionShare<G> {
    pub(super) fn from_element(dh_element: G::Element) -> Self {
        Self { dh_element }
    }

    /// Creates a decryption for the specified `ciphertext` under `keys` together with
    /// a zero-knowledge proof of validity.
    ///
    /// This is a lower-level counterpart to [`ActiveParticipant::decrypt_share()`].
    /// See [`CandidateShare::verify()`] for a verification counterpart.
    pub fn new<R: CryptoRng + RngCore>(
        ciphertext: Ciphertext<G>,
        keys: &Keypair<G>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> (Self, LogEqualityProof<G>) {
        // All inputs except from `ciphertext.blinded_element` are committed in the `proof`,
        // and it is not necessary to commit in order to allow iteratively recomputing
        // the ciphertext.
        transcript.start_proof(b"decryption_share_with_custom_key");

        let dh_element = ciphertext.random_element * keys.secret().expose_scalar();
        let proof = LogEqualityProof::new(
            &PublicKey::from_element(ciphertext.random_element),
            keys.secret(),
            (keys.public().as_element(), dh_element),
            transcript,
            rng,
        );

        (Self { dh_element }, proof)
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

    /// Returns the group element encapsulated in this share.
    pub fn as_element(&self) -> &G::Element {
        &self.dh_element
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

    /// Verifies this as a decryption share for `ciphertext` under `key` using the provided
    /// zero-knowledge `proof`.
    ///
    /// # Errors
    ///
    /// Returns an error if `proof` does not verify.
    pub fn verify(
        self,
        ciphertext: Ciphertext<G>,
        key: &PublicKey<G>,
        proof: &LogEqualityProof<G>,
        transcript: &mut Transcript,
    ) -> Result<DecryptionShare<G>, VerificationError> {
        transcript.start_proof(b"decryption_share_with_custom_key");

        let dh_element = self.dh_element();
        proof.verify(
            &PublicKey::from_element(ciphertext.random_element),
            (key.as_element(), dh_element),
            transcript,
        )?;
        Ok(self.inner)
    }

    /// Converts this candidate share into a [`DecryptionShare`] **without** verifying its validity.
    /// This only semantically correct if the share was verified in some other way.
    pub fn into_unchecked(self) -> DecryptionShare<G> {
        self.inner
    }
}

impl<G: Group> From<DecryptionShare<G>> for CandidateShare<G> {
    fn from(share: DecryptionShare<G>) -> Self {
        Self { inner: share }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar as Scalar25519;
    use rand::thread_rng;

    use super::*;
    use crate::group::Ristretto;

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

        let ciphertext = key_set.shared_key.encrypt(15_u64, &mut rng);
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
            alice_share.dh_element * Scalar25519::from(2_u64) - bob_share.dh_element;
        let message = Ristretto::mul_generator(&Scalar25519::from(15_u64));
        assert_eq!(composite_dh_element, ciphertext.blinded_element - message);
    }
}
