//! Snapshot testing to check compatibility of `serde` and binary serializations of types.

use base64ct::{Base64UrlUnpadded, Encoding};
use insta::{assert_snapshot, assert_yaml_snapshot};
use rand_chacha::ChaChaRng;
use rand_core::{RngCore, SeedableRng};

use elastic_elgamal::{
    Ciphertext, CiphertextWithValue, CommitmentEquivalenceProof, Keypair, RangeDecomposition,
    SecretKey, SumOfSquaresProof,
    app::{ChoiceParams, EncryptedChoice, QuadraticVotingBallot, QuadraticVotingParams},
    group::{Generic, Group, Ristretto},
};
use merlin::Transcript;

trait Named {
    const NAME: &'static str;
}

impl Named for Ristretto {
    const NAME: &'static str = "ristretto";
}

impl Named for Generic<::k256::Secp256k1> {
    const NAME: &'static str = "k256";
}

fn stringify_bytes(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn test_ciphertext_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let ciphertext = public_key.encrypt(42, &mut rng);

    let full_name = format!("ciphertext-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ciphertext);
}

fn test_ciphertext_binary_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let ciphertext = public_key.encrypt(42, &mut rng);

    let full_name = format!("ciphertext-bin-{}", G::NAME);
    assert_snapshot!(full_name, stringify_bytes(&ciphertext.to_bytes()));
}

fn test_zero_encryption_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let (ciphertext, proof) = public_key.encrypt_zero(&mut rng);
    let ciphertext_with_proof = serde_json::json!({
        "ciphertext": ciphertext,
        "proof": proof,
    });
    let full_name = format!("zero-encryption-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ciphertext_with_proof);
}

fn test_zero_encryption_binary_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let (_, proof) = public_key.encrypt_zero(&mut rng);
    let full_name = format!("zero-encryption-bin-{}", G::NAME);
    assert_snapshot!(full_name, stringify_bytes(&proof.to_bytes()));
}

fn test_bool_encryption_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let (ciphertext, proof) = public_key.encrypt_bool(true, &mut rng);
    let ciphertext_with_proof = serde_json::json!({
        "ciphertext": ciphertext,
        "proof": proof,
    });
    let full_name = format!("bool-encryption-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ciphertext_with_proof);
}

fn test_bool_encryption_binary_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let (_, proof) = public_key.encrypt_bool(true, &mut rng);
    let full_name = format!("bool-encryption-bin-{}", G::NAME);
    assert_snapshot!(full_name, stringify_bytes(&proof.to_bytes()));
}

fn test_range_encryption_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let range = RangeDecomposition::optimal(100).into();

    let (ciphertext, proof) = public_key.encrypt_range(&range, 42, &mut rng);
    let ciphertext_with_proof = serde_json::json!({
        "ciphertext": ciphertext,
        "proof": proof,
    });
    let full_name = format!("range-encryption-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ciphertext_with_proof);
}

fn test_encrypted_choice_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let choice_params = ChoiceParams::single(public_key, 5);

    let choice = EncryptedChoice::single(&choice_params, 3, &mut rng);
    let full_name = format!("encrypted-choice-{}", G::NAME);
    assert_yaml_snapshot!(full_name, choice);
}

fn test_encrypted_multi_choice_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let choice_params = ChoiceParams::multi(public_key, 5);

    let choices = [false, true, true, false, true];
    let choices = EncryptedChoice::new(&choice_params, &choices, &mut rng);
    let full_name = format!("encrypted-multi-choice-{}", G::NAME);
    assert_yaml_snapshot!(full_name, choices);
}

fn test_sum_of_squares_proof_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let values = [1, 3, 3, 7, 5];
    let sum_of_squares = values.iter().map(|&x| x * x).sum::<u64>();
    let sum_of_squares =
        CiphertextWithValue::new(sum_of_squares, &public_key, &mut rng).generalize();
    let values: Vec<_> = values
        .iter()
        .map(|&x| CiphertextWithValue::new(x, &public_key, &mut rng).generalize())
        .collect();

    let proof = SumOfSquaresProof::new(
        values.iter(),
        &sum_of_squares,
        &public_key,
        &mut Transcript::new(b"test"),
        &mut rng,
    );
    let full_name = format!("sum-sq-proof-{}", G::NAME);
    assert_yaml_snapshot!(full_name, proof);
}

fn test_qv_ballot_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let vote_params = QuadraticVotingParams::new(public_key, 5, 15);

    let votes = [3, 0, 1, 0, 2];
    let ballot = QuadraticVotingBallot::new(&vote_params, &votes, &mut rng);
    let full_name = format!("qv-ballot-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ballot);
}

fn test_commitment_equivalence_snapshot<G: Group + Named>(blinding_base: G::Element) {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (receiver, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let value = 123_u64;
    let ciphertext = CiphertextWithValue::new(value, &receiver, &mut rng).generalize();
    let blinding = SecretKey::generate(&mut rng);

    let (proof, commitment) = CommitmentEquivalenceProof::new(
        &ciphertext,
        &receiver,
        &blinding,
        blinding_base,
        &mut Transcript::new(b"test"),
        &mut rng,
    );

    let mut commitment_bytes = vec![0_u8; G::ELEMENT_SIZE];
    G::serialize_element(&commitment, &mut commitment_bytes);
    let commitment_with_proof = serde_json::json!({
        "ciphertext": Ciphertext::from(ciphertext),
        "commitment": stringify_bytes(&commitment_bytes),
        "proof": proof,
    });

    let full_name = format!("commitment-equiv-proof-{}", G::NAME);
    assert_yaml_snapshot!(full_name, commitment_with_proof);
}

mod ristretto {
    use super::*;
    use elastic_elgamal::group::ElementOps;

    #[test]
    fn ciphertext_snapshot() {
        test_ciphertext_snapshot::<Ristretto>();
    }

    #[test]
    fn ciphertext_binary_snapshot() {
        test_ciphertext_binary_snapshot::<Ristretto>();
    }

    #[test]
    fn zero_encryption_snapshot() {
        test_zero_encryption_snapshot::<Ristretto>();
    }

    #[test]
    fn zero_encryption_binary_snapshot() {
        test_zero_encryption_binary_snapshot::<Ristretto>();
    }

    #[test]
    fn bool_encryption_snapshot() {
        test_bool_encryption_snapshot::<Ristretto>();
    }

    #[test]
    fn bool_encryption_binary_snapshot() {
        test_bool_encryption_binary_snapshot::<Ristretto>();
    }

    #[test]
    fn range_encryption_snapshot() {
        test_range_encryption_snapshot::<Ristretto>();
    }

    #[test]
    fn encrypted_choice_snapshot() {
        test_encrypted_choice_snapshot::<Ristretto>();
    }

    #[test]
    fn encrypted_multi_choice_snapshot() {
        test_encrypted_multi_choice_snapshot::<Ristretto>();
    }

    #[test]
    fn sum_of_squares_proof_snapshot() {
        test_sum_of_squares_proof_snapshot::<Ristretto>();
    }

    #[test]
    fn qv_ballot_snapshot() {
        test_qv_ballot_snapshot::<Ristretto>();
    }

    #[test]
    fn commitment_equivalence_snapshot() {
        // Blinding base used in Bulletproofs.
        const BLINDING_BASE: &[u8] = &[
            140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160,
            140, 219, 127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52,
        ];

        let blinding_base = Ristretto::deserialize_element(BLINDING_BASE).unwrap();
        test_commitment_equivalence_snapshot::<Ristretto>(blinding_base);
    }
}

mod k256 {
    use super::*;
    use elastic_elgamal::group::ElementOps;

    type K256 = Generic<::k256::Secp256k1>;

    #[test]
    fn ciphertext_snapshot() {
        test_ciphertext_snapshot::<K256>();
    }

    #[test]
    fn ciphertext_binary_snapshot() {
        test_ciphertext_binary_snapshot::<K256>();
    }

    #[test]
    fn zero_encryption_snapshot() {
        test_zero_encryption_snapshot::<K256>();
    }

    #[test]
    fn zero_encryption_binary_snapshot() {
        test_zero_encryption_binary_snapshot::<K256>();
    }

    #[test]
    fn bool_encryption_snapshot() {
        test_bool_encryption_snapshot::<K256>();
    }

    #[test]
    fn bool_encryption_binary_snapshot() {
        test_bool_encryption_binary_snapshot::<K256>();
    }

    #[test]
    fn range_encryption_snapshot() {
        test_range_encryption_snapshot::<K256>();
    }

    #[test]
    fn encrypted_choice_snapshot() {
        test_encrypted_choice_snapshot::<K256>();
    }

    #[test]
    fn encrypted_multi_choice_snapshot() {
        test_encrypted_multi_choice_snapshot::<K256>();
    }

    #[test]
    fn sum_of_squares_proof_snapshot() {
        test_sum_of_squares_proof_snapshot::<K256>();
    }

    #[test]
    fn qv_ballot_snapshot() {
        test_qv_ballot_snapshot::<K256>();
    }

    #[test]
    fn commitment_equivalence_snapshot() {
        // Very primitive, but generic way to generate a blinding base; do not use
        // in real apps!
        let mut rng = ChaChaRng::seed_from_u64(12345);
        let mut element_bytes = vec![0_u8; K256::ELEMENT_SIZE];
        let blinding_base = loop {
            element_bytes[0] = 2; // one of two allowed markers for compressed keys
            rng.fill_bytes(&mut element_bytes[1..]);
            if let Some(element) = K256::deserialize_element(&element_bytes) {
                break element;
            }
        };
        test_commitment_equivalence_snapshot::<K256>(blinding_base);
    }
}
