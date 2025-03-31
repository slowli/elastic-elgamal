//! Example for using `RangeProof`s.

use rand::{Rng, thread_rng};

use elastic_elgamal::{DiscreteLogTable, Keypair, RangeDecomposition, group::Ristretto};

/// Exclusive upper bound of the plaintext value range.
const UPPER_BOUND: u64 = 100;

fn main() {
    let range = RangeDecomposition::optimal(UPPER_BOUND);
    println!("Range decomposition: 0..{} = {range}", range.upper_bound());

    let mut rng = thread_rng();
    let receiver = Keypair::<Ristretto>::generate(&mut rng);
    let range = range.into();
    let lookup_table = DiscreteLogTable::<Ristretto>::new(0..UPPER_BOUND);

    for _ in 0..5 {
        let secret_value: u64 = rng.random_range(0..UPPER_BOUND);
        println!("\nEncrypting value: {secret_value}");
        let (ciphertext, proof) = receiver
            .public()
            .encrypt_range(&range, secret_value, &mut rng);

        println!(
            "Ciphertext: {}",
            serde_json::to_string_pretty(&ciphertext).unwrap()
        );
        println!(
            "Range proof: {}",
            serde_json::to_string_pretty(&proof).unwrap()
        );

        receiver
            .public()
            .verify_range(&range, ciphertext, &proof)
            .unwrap();
        let decrypted = receiver
            .secret()
            .decrypt(ciphertext, &lookup_table)
            .unwrap();
        assert_eq!(decrypted, secret_value);
    }
}
