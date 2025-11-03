//! Example showing how to use ElGamal ciphertext - Pedersen commitment equivalence proof
//! together with proofs on commitments (in this case, a range proof using [Bulletproofs]).
//!
//! Note that the example requires the non-default `curve25519-dalek-ng` crypto backend to run.
//!
//! [Bulletproofs]: https://crypto.stanford.edu/bulletproofs/

use base64ct::{Base64UrlUnpadded, Encoding};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;

use std::env;

use elastic_elgamal::{
    group::Ristretto, Ciphertext, CiphertextWithValue, CommitmentEquivalenceProof, Keypair,
    SecretKey,
};

const BULLETPROOFS_CAPACITY: usize = 64;

// The `bulletproofs` crate doesn't (yet?) support `rand` 0.9, hence, these awkward shims.

fn downgrade_scalar(x: curve25519_dalek::Scalar) -> bulletproofs_curve::Scalar {
    bulletproofs_curve::Scalar::from_bytes_mod_order(x.to_bytes())
}

fn upgrade_point(x: bulletproofs_curve::RistrettoPoint) -> curve25519_dalek::RistrettoPoint {
    let compressed = curve25519_dalek::ristretto::CompressedRistretto(x.compress().0);
    compressed.decompress().unwrap()
}

#[derive(Debug)]
struct CompatRng<R>(R);

impl<R: rand_core::RngCore> bulletproofs_rand_core::RngCore for CompatRng<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), bulletproofs_rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: rand_core::CryptoRng> bulletproofs_rand_core::CryptoRng for CompatRng<R> {}

fn main() {
    let mut rng = rand::rng();
    let (receiver, _) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
    let value = env::args().nth(1).map_or(424_242, |arg| {
        arg.parse().expect("cannot parse value as `u64` integer")
    });
    let ciphertext = CiphertextWithValue::new(value, &receiver, &mut rng).generalize();
    println!("Encrypted value: {value}");

    let commitment_gens = PedersenGens::default();
    let bulletproof_gens = BulletproofGens::new(BULLETPROOFS_CAPACITY, 1);
    let blinding = SecretKey::generate(&mut rng);
    let mut transcript = Transcript::new(b"equiv_and_bulletproof");
    let (equiv_proof, commitment) = CommitmentEquivalenceProof::new(
        &ciphertext,
        &receiver,
        &blinding,
        upgrade_point(commitment_gens.B_blinding),
        &mut transcript,
        &mut rng,
    );
    let (range_proof, same_commitment) = RangeProof::prove_single_with_rng(
        &bulletproof_gens,
        &commitment_gens,
        &mut transcript,
        value,
        &downgrade_scalar(*blinding.expose_scalar()),
        BULLETPROOFS_CAPACITY,
        &mut CompatRng(rng),
    )
    .expect("failed creating proof");

    // Commitments returned in both cases are equivalent.
    assert_eq!(commitment.compress().to_bytes(), same_commitment.to_bytes());
    let ciphertext = Ciphertext::from(ciphertext);

    let combined = serde_json::json!({
        "ciphertext": &ciphertext,
        "commitment": Base64UrlUnpadded::encode_string(same_commitment.as_bytes()),
        "equiv": equiv_proof,
        "range": Base64UrlUnpadded::encode_string(&range_proof.to_bytes()),
    });
    println!(
        "Created proof: {}",
        serde_json::to_string_pretty(&combined).unwrap()
    );

    // Check that proofs verify.
    let mut transcript = Transcript::new(b"equiv_and_bulletproof");
    equiv_proof
        .verify(
            &ciphertext,
            &receiver,
            commitment,
            upgrade_point(commitment_gens.B_blinding),
            &mut transcript,
        )
        .unwrap();
    range_proof
        .verify_single(
            &bulletproof_gens,
            &commitment_gens,
            &mut transcript,
            &same_commitment,
            BULLETPROOFS_CAPACITY,
        )
        .unwrap();
    println!("Proofs successfully verified!");
}
