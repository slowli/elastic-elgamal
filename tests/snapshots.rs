//! Snapshot testing to check compatibility of `serde` serialization of types.

use insta::assert_yaml_snapshot;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice},
    group::{Generic, Group, Ristretto},
    Keypair, RangeDecomposition,
};

trait Named {
    const NAME: &'static str;
}

impl Named for Ristretto {
    const NAME: &'static str = "ristretto";
}

impl Named for Generic<::k256::Secp256k1> {
    const NAME: &'static str = "k256";
}

fn test_ciphertext_snapshot<G: Group + Named>() {
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let (public_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    let ciphertext = public_key.encrypt(42, &mut rng);

    let full_name = format!("ciphertext-{}", G::NAME);
    assert_yaml_snapshot!(full_name, ciphertext);
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

    let choice = EncryptedChoice::single(3, &choice_params, &mut rng);
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

mod ristretto {
    use super::*;

    #[test]
    fn ciphertext_snapshot() {
        test_ciphertext_snapshot::<Ristretto>();
    }

    #[test]
    fn zero_encryption_snapshot() {
        test_zero_encryption_snapshot::<Ristretto>();
    }

    #[test]
    fn bool_encryption_snapshot() {
        test_bool_encryption_snapshot::<Ristretto>();
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
}

mod k256 {
    use super::*;

    type K256 = Generic<::k256::Secp256k1>;

    #[test]
    fn ciphertext_snapshot() {
        test_ciphertext_snapshot::<K256>();
    }

    #[test]
    fn zero_encryption_snapshot() {
        test_zero_encryption_snapshot::<K256>();
    }

    #[test]
    fn bool_encryption_snapshot() {
        test_bool_encryption_snapshot::<K256>();
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
}
