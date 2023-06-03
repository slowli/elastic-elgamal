//! Verifiable decryption.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::ElementHelper;
use crate::{
    alloc::{vec, Vec},
    group::Group,
    proofs::{LogEqualityProof, TranscriptForGroup},
    Ciphertext, DiscreteLogTable, Keypair, PublicKey, VerificationError,
};

/// Verifiable decryption for a certain [`Ciphertext`] in the ElGamal encryption scheme.
/// Usable both for standalone proofs and in threshold encryption.
///
/// # Construction
///
/// Decryption is represented by a single group element – the result of combining
/// a [`SecretKey`](crate::SecretKey) scalar `x` with the random element of the ciphertext `R`
/// (i.e., `D = [x]R`, the Diffie – Hellman construction).
/// This element can retrieved using [`Self::as_element()`] and applied to a ciphertext using
/// [`Self::decrypt()`] or [`Self::decrypt_to_element()`].
///
/// The decryption can be proven with the help of a standard [`LogEqualityProof`]. Indeed,
/// to prove the validity of decryption, it is sufficient to prove `dlog_R(D) = dlog_G(K)`,
/// where `G` is the conventional group generator and `K = [x]G` is the public key for encryption.
///
/// # Examples
///
/// `VerifiableDecryption` can be used either within the threshold encryption scheme provided by
/// the [`sharing`](crate::sharing) module, or independently (for example, if another approach
/// to secret sharing is used, or if the encryption key is not shared at all).
/// An example of standalone usage is outlined below:
///
/// ```
/// # use elastic_elgamal::{
/// #     group::Ristretto, CandidateDecryption, VerifiableDecryption, Keypair, DiscreteLogTable,
/// # };
/// # use merlin::Transcript;
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = thread_rng();
/// let keys = Keypair::<Ristretto>::generate(&mut rng);
/// // Suppose the `keys` holder wants to prove decryption
/// // of the following ciphertext:
/// let ciphertext = keys.public().encrypt(42_u64, &mut rng);
/// let (decryption, proof) = VerifiableDecryption::new(
///     ciphertext,
///     &keys,
///     &mut Transcript::new(b"decryption"),
///     &mut rng,
/// );
///
/// // This proof can then be universally verified:
/// let candidate_decryption = CandidateDecryption::from(decryption);
/// let decryption = candidate_decryption.verify(
///     ciphertext,
///     keys.public(),
///     &proof,
///     &mut Transcript::new(b"decryption"),
/// )?;
/// assert_eq!(
///     decryption.decrypt(ciphertext, &DiscreteLogTable::new(0..50)),
///     Some(42)
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct VerifiableDecryption<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    dh_element: G::Element,
}

impl<G: Group> VerifiableDecryption<G> {
    pub(crate) fn from_element(dh_element: G::Element) -> Self {
        Self { dh_element }
    }

    /// Creates a decryption for the specified `ciphertext` under `keys` together with
    /// a zero-knowledge proof of validity.
    ///
    /// See [`CandidateDecryption::verify()`] for the verification counterpart.
    pub fn new<R: CryptoRng + RngCore>(
        ciphertext: Ciphertext<G>,
        keys: &Keypair<G>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> (Self, LogEqualityProof<G>) {
        // All inputs except from `ciphertext.blinded_element` are committed in the `proof`,
        // and it is not necessary to commit in order to allow iteratively recomputing
        // the ciphertext.
        transcript.start_proof(b"decryption_with_custom_key");

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

    /// Returns the group element encapsulated in this decryption.
    pub fn as_element(&self) -> &G::Element {
        &self.dh_element
    }

    /// Serializes this decryption into bytes.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
        G::serialize_element(&self.dh_element, &mut bytes);
        bytes
    }

    /// Decrypts the provided ciphertext and returns the produced group element.
    ///
    /// As the ciphertext does not include a MAC or another way to assert integrity,
    /// this operation cannot fail. If the ciphertext is not produced properly (e.g., it targets
    /// another receiver), the returned group element will be garbage.
    pub fn decrypt_to_element(&self, encrypted: Ciphertext<G>) -> G::Element {
        encrypted.blinded_element - self.dh_element
    }

    /// Decrypts the provided ciphertext and returns the original encrypted value.
    ///
    /// `lookup_table` is used to find encrypted values based on the original decrypted
    /// group element. That is, it must contain all valid plaintext values. If the value
    /// is not in the table, this method will return `None`.
    pub fn decrypt(
        &self,
        encrypted: Ciphertext<G>,
        lookup_table: &DiscreteLogTable<G>,
    ) -> Option<u64> {
        lookup_table.get(&self.decrypt_to_element(encrypted))
    }
}

/// Candidate for a [`VerifiableDecryption`] that is not yet verified. This presentation should be
/// used for decryption data retrieved from an untrusted source.
///
/// Decryption data can be verified using [`Self::verify()`]. The threshold encryption scheme
/// implemented in the [`sharing`](crate::sharing) module has its own verification procedure
/// in [`PublicKeySet`].
///
/// [`PublicKeySet`]: crate::sharing::PublicKeySet
///
/// # Examples
///
/// See [`VerifiableDecryption`] for an example of usage.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent, bound = ""))]
pub struct CandidateDecryption<G: Group> {
    inner: VerifiableDecryption<G>,
}

impl<G: Group> CandidateDecryption<G> {
    /// Deserializes decryption data from `bytes`. Returns `None` if the data is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == G::ELEMENT_SIZE {
            let dh_element = G::deserialize_element(bytes)?;
            Some(Self {
                inner: VerifiableDecryption { dh_element },
            })
        } else {
            None
        }
    }

    pub(super) fn dh_element(self) -> G::Element {
        self.inner.dh_element
    }

    /// Verifies this as decryption for `ciphertext` under `key` using the provided
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
    ) -> Result<VerifiableDecryption<G>, VerificationError> {
        transcript.start_proof(b"decryption_with_custom_key");

        let dh_element = self.dh_element();
        proof.verify(
            &PublicKey::from_element(ciphertext.random_element),
            (key.as_element(), dh_element),
            transcript,
        )?;
        Ok(self.inner)
    }

    /// Converts this candidate decryption into a [`VerifiableDecryption`]
    /// **without** verifying it.
    /// This is only semantically correct if the data was verified in some other way.
    pub fn into_unchecked(self) -> VerifiableDecryption<G> {
        self.inner
    }
}

impl<G: Group> From<VerifiableDecryption<G>> for CandidateDecryption<G> {
    fn from(decryption: VerifiableDecryption<G>) -> Self {
        Self { inner: decryption }
    }
}
