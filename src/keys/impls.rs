//! Operations on public / secret keys.

use core::iter;

use elliptic_curve::rand_core::{CryptoRng, RngCore};
use merlin::Transcript;

use crate::{
    Ciphertext, DiscreteLogTable, LogEqualityProof, PreparedRange, PublicKey, RangeProof,
    RingProof, RingProofBuilder, SecretKey, VerificationError, alloc::vec,
    encryption::ExtendedCiphertext, group::Group,
};

impl<G: Group> PublicKey<G> {
    /// Encrypts a value for this key.
    pub fn encrypt<T, R: CryptoRng + RngCore>(&self, value: T, rng: &mut R) -> Ciphertext<G>
    where
        G::Scalar: From<T>,
    {
        let scalar = G::Scalar::from(value);
        let element = G::mul_generator(&scalar);
        ExtendedCiphertext::new(element, self, rng).inner
    }

    /// Encrypts a group element.
    pub fn encrypt_element<R: CryptoRng + RngCore>(
        &self,
        value: G::Element,
        rng: &mut R,
    ) -> Ciphertext<G> {
        ExtendedCiphertext::new(value, self, rng).inner
    }

    /// Encrypts zero value and provides a zero-knowledge proof of encryption correctness.
    pub fn encrypt_zero<R>(&self, rng: &mut R) -> (Ciphertext<G>, LogEqualityProof<G>)
    where
        R: CryptoRng + RngCore,
    {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let blinded_element = self.element * &random_scalar.0;
        let ciphertext = Ciphertext {
            random_element,
            blinded_element,
        };

        let proof = LogEqualityProof::new(
            self,
            &random_scalar,
            (random_element, blinded_element),
            &mut Transcript::new(b"zero_encryption"),
            rng,
        );

        (ciphertext, proof)
    }

    /// Verifies that this is an encryption of a zero value.
    ///
    /// # Errors
    ///
    /// Returns an error if the `proof` does not verify.
    pub fn verify_zero(
        &self,
        ciphertext: Ciphertext<G>,
        proof: &LogEqualityProof<G>,
    ) -> Result<(), VerificationError> {
        proof.verify(
            self,
            (ciphertext.random_element, ciphertext.blinded_element),
            &mut Transcript::new(b"zero_encryption"),
        )
    }

    /// Encrypts a boolean value (0 or 1) and provides a zero-knowledge proof of encryption
    /// correctness.
    ///
    /// # Examples
    ///
    /// See [`Ciphertext`] docs for an example of usage.
    pub fn encrypt_bool<R: CryptoRng + RngCore>(
        &self,
        value: bool,
        rng: &mut R,
    ) -> (Ciphertext<G>, RingProof<G>) {
        let mut transcript = Transcript::new(b"bool_encryption");
        let admissible_values = [G::identity(), G::generator()];
        let mut ring_responses = vec![G::Scalar::default(); 2];
        let mut builder = RingProofBuilder::new(self, 1, &mut ring_responses, &mut transcript, rng);
        let ciphertext = builder.add_value(&admissible_values, usize::from(value));
        let proof = RingProof::new(builder.build(), ring_responses);
        (ciphertext.inner, proof)
    }

    /// Verifies a proof of encryption correctness of a boolean value, which was presumably
    /// obtained via [`Self::encrypt_bool()`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `proof` does not verify.
    ///
    /// # Examples
    ///
    /// See [`Ciphertext`] docs for an example of usage.
    pub fn verify_bool(
        &self,
        ciphertext: Ciphertext<G>,
        proof: &RingProof<G>,
    ) -> Result<(), VerificationError> {
        let admissible_values = [G::identity(), G::generator()];
        proof.verify(
            self,
            iter::once(&admissible_values as &[_]),
            iter::once(ciphertext),
            &mut Transcript::new(b"bool_encryption"),
        )
    }

    /// Encrypts `value` and provides a zero-knowledge proof that it lies in the specified `range`.
    ///
    /// # Panics
    ///
    /// Panics if `value` is out of `range`.
    ///
    /// # Examples
    ///
    /// See [`Ciphertext`] docs for an example of usage.
    pub fn encrypt_range<R: CryptoRng + RngCore>(
        &self,
        range: &PreparedRange<G>,
        value: u64,
        rng: &mut R,
    ) -> (Ciphertext<G>, RangeProof<G>) {
        let mut transcript = Transcript::new(b"ciphertext_range");
        let (ciphertext, proof) = RangeProof::new(self, range, value, &mut transcript, rng);
        (ciphertext.into(), proof)
    }

    /// Verifies `proof` that `ciphertext` encrypts a value lying in `range`.
    ///
    /// The `proof` should be created with a call to [`Self::encrypt_range()`] with the same
    /// [`PreparedRange`]; otherwise, the proof will not verify.
    ///
    /// # Errors
    ///
    /// Returns an error if the `proof` does not verify.
    pub fn verify_range(
        &self,
        range: &PreparedRange<G>,
        ciphertext: Ciphertext<G>,
        proof: &RangeProof<G>,
    ) -> Result<(), VerificationError> {
        let mut transcript = Transcript::new(b"ciphertext_range");
        proof.verify(self, range, ciphertext, &mut transcript)
    }
}

impl<G: Group> SecretKey<G> {
    /// Decrypts the provided ciphertext and returns the produced group element.
    ///
    /// As the ciphertext does not include a MAC or another way to assert integrity,
    /// this operation cannot fail. If the ciphertext is not produced properly (e.g., it targets
    /// another receiver), the returned group element will be garbage.
    pub fn decrypt_to_element(&self, encrypted: Ciphertext<G>) -> G::Element {
        let dh_element = encrypted.random_element * &self.0;
        encrypted.blinded_element - dh_element
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
