//! Operations on public / secret keys.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

use core::{iter, ops};

use crate::{
    encryption::ExtendedCiphertext, group::Group, ChoiceVerificationError, Ciphertext,
    DiscreteLogTable, EncryptedChoice, LogEqualityProof, PreparedRange, PublicKey, RangeProof,
    RingProof, RingProofBuilder, SecretKey, VerificationError,
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
        let ciphertext = builder.add_value(&admissible_values, value as usize);
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

    /// Creates an [`EncryptedChoice`].
    ///
    /// # Panics
    ///
    /// Panics if `number_of_variants` is zero, or if `choice` is not in `0..number_of_variants`.
    ///
    /// # Examples
    ///
    /// See [`EncryptedChoice`] docs for an example of usage.
    pub fn encrypt_choice<R: CryptoRng + RngCore>(
        &self,
        number_of_variants: usize,
        choice: usize,
        rng: &mut R,
    ) -> EncryptedChoice<G> {
        assert!(
            number_of_variants > 0,
            "`number_of_variants` must be positive"
        );
        assert!(
            choice < number_of_variants,
            "invalid choice {}; expected a value in 0..{}",
            choice,
            number_of_variants
        );

        let admissible_values = [G::identity(), G::generator()];
        let mut ring_responses = vec![G::Scalar::default(); 2 * number_of_variants];
        let mut transcript = Transcript::new(b"encrypted_choice_ranges");
        let mut proof_builder = RingProofBuilder::new(
            self,
            number_of_variants,
            &mut ring_responses,
            &mut transcript,
            rng,
        );

        let variants: Vec<_> = (0..number_of_variants)
            .map(|i| proof_builder.add_value(&admissible_values, (i == choice) as usize))
            .collect();
        let range_proof = RingProof::new(proof_builder.build(), ring_responses);

        let mut sum_log = variants[0].random_scalar.clone();
        let mut sum_ciphertext = variants[0].inner;
        for variant in variants.iter().skip(1) {
            sum_log += variant.random_scalar.clone();
            sum_ciphertext += variant.inner;
        }

        let sum_proof = LogEqualityProof::new(
            self,
            &sum_log,
            (
                sum_ciphertext.random_element,
                sum_ciphertext.blinded_element - G::generator(),
            ),
            &mut Transcript::new(b"choice_encryption_sum"),
            rng,
        );

        EncryptedChoice {
            variants: variants.into_iter().map(|variant| variant.inner).collect(),
            range_proof,
            sum_proof,
        }
    }

    /// Verifies the zero-knowledge proofs in an [`EncryptedChoice`] and returns variant ciphertexts
    /// if they check out.
    ///
    /// # Errors
    ///
    /// Returns an error if the `choice` is malformed or its proofs fail verification.
    pub fn verify_choice<'a>(
        &self,
        choice: &'a EncryptedChoice<G>,
    ) -> Result<&'a [Ciphertext<G>], ChoiceVerificationError> {
        let sum_ciphertexts = choice.variants.iter().copied().reduce(ops::Add::add);
        let sum_ciphertexts = sum_ciphertexts.ok_or(ChoiceVerificationError::Empty)?;

        let powers = (
            sum_ciphertexts.random_element,
            sum_ciphertexts.blinded_element - G::generator(),
        );
        choice
            .sum_proof
            .verify(self, powers, &mut Transcript::new(b"choice_encryption_sum"))
            .map_err(ChoiceVerificationError::Sum)?;

        let admissible_values = [G::identity(), G::generator()];
        choice
            .range_proof
            .verify(
                self,
                iter::repeat(&admissible_values as &[_]).take(choice.variants.len()),
                choice.variants.iter().copied(),
                &mut Transcript::new(b"encrypted_choice_ranges"),
            )
            .map(|()| choice.variants.as_slice())
            .map_err(ChoiceVerificationError::Range)
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

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    use crate::{
        group::{Generic, Ristretto},
        Keypair,
    };

    fn test_bogus_encrypted_choice_does_not_work<G: Group>() {
        let mut rng = thread_rng();
        let keypair = Keypair::<G>::generate(&mut rng);

        let mut choice = keypair.public().encrypt_choice(5, 2, &mut rng);
        let (encrypted_one, _) = keypair.public().encrypt_bool(true, &mut rng);
        choice.variants[0] = encrypted_one;
        assert!(keypair.public().verify_choice(&choice).is_err());

        let mut choice = keypair.public().encrypt_choice(5, 4, &mut rng);
        let (encrypted_zero, _) = keypair.public().encrypt_bool(false, &mut rng);
        choice.variants[4] = encrypted_zero;
        assert!(keypair.public().verify_choice(&choice).is_err());

        let mut choice = keypair.public().encrypt_choice(5, 4, &mut rng);
        choice.variants[4].blinded_element =
            choice.variants[4].blinded_element + G::mul_generator(&G::Scalar::from(10));
        choice.variants[3].blinded_element =
            choice.variants[3].blinded_element - G::mul_generator(&G::Scalar::from(10));
        // These modifications leave `choice.sum_proof` correct, but the range proofs
        // for the last 2 variants should no longer verify.
        assert!(keypair.public().verify_choice(&choice).is_err());
    }

    #[test]
    fn bogus_encrypted_choice_does_not_work_for_edwards() {
        test_bogus_encrypted_choice_does_not_work::<Ristretto>();
    }

    #[test]
    fn bogus_encrypted_choice_does_not_work_for_k256() {
        test_bogus_encrypted_choice_does_not_work::<Generic<k256::Secp256k1>>();
    }
}
