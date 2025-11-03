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
        commitment_gens.B_blinding,
        &mut transcript,
        &mut rng,
    );
    let (range_proof, same_commitment) = RangeProof::prove_single_with_rng(
        &bulletproof_gens,
        &commitment_gens,
        &mut transcript,
        value,
        blinding.expose_scalar(),
        BULLETPROOFS_CAPACITY,
        &mut rng,
    )
    .expect("failed creating proof");

    // Commitments returned in both cases are equivalent.
    assert_eq!(commitment.compress(), same_commitment);
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
            commitment_gens.B_blinding,
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
