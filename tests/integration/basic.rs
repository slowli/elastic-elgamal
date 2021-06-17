//! Basic tests.

use rand::{thread_rng, Rng};

use std::collections::HashMap;

use crate::assert_ct_eq;
use elastic_elgamal::{group::Group, Keypair, LogEqualityProof, RingProof};

fn test_encryption_roundtrip<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let message = 12_345_u64;
    let ciphertext = keypair.public().encrypt(message, &mut rng);
    let decryption = keypair.secret().decrypt_to_element(ciphertext);
    let message = G::mul_generator(&G::Scalar::from(message));
    assert_ct_eq(&decryption, &message);
}

fn test_zero_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let (zero_ciphertext, proof) = keypair.public().encrypt_zero(&mut rng);
    assert!(keypair.public().verify_zero(zero_ciphertext, &proof));
    let decrypted = keypair.secret().decrypt_to_element(zero_ciphertext);
    assert_ct_eq(&decrypted, &G::identity());

    // The proof should not verify for non-zero messages.
    let ciphertext = keypair.public().encrypt(123_u64, &mut rng);
    assert!(!keypair.public().verify_zero(ciphertext, &proof));

    // ...or for another receiver key
    let other_keypair = Keypair::generate(&mut rng);
    assert!(!other_keypair.public().verify_zero(ciphertext, &proof));

    // ...or for another secret scalar used.
    let (other_zero_ciphertext, other_proof) = keypair.public().encrypt_zero(&mut rng);
    assert!(!keypair.public().verify_zero(other_zero_ciphertext, &proof));
    assert!(!keypair.public().verify_zero(zero_ciphertext, &other_proof));

    let combined_ciphertext = other_zero_ciphertext + zero_ciphertext;
    assert!(!keypair.public().verify_zero(combined_ciphertext, &proof));
    assert!(!keypair
        .public()
        .verify_zero(combined_ciphertext, &other_proof));
}

fn test_zero_proof_serialization<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let mut ciphertexts = HashMap::new();

    for _ in 0..100 {
        let (zero_ciphertext, proof) = keypair.public().encrypt_zero(&mut rng);
        let bytes = proof.to_bytes();
        ciphertexts.insert(bytes.to_vec(), zero_ciphertext);
    }
    assert_eq!(ciphertexts.len(), 100);
    for (bytes, ciphertext) in ciphertexts {
        let proof = LogEqualityProof::<G>::from_slice(&bytes).unwrap();
        assert!(keypair.public().verify_zero(ciphertext, &proof));
    }
}

fn test_bool_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);

    let (ciphertext, proof) = keypair.public().encrypt_bool(false, &mut rng);
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(ciphertext),
        &G::identity(),
    );
    assert!(keypair.public().verify_bool(ciphertext, &proof));

    let (other_ciphertext, other_proof) = keypair.public().encrypt_bool(true, &mut rng);
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(other_ciphertext),
        &G::generator(),
    );
    assert!(keypair.public().verify_bool(other_ciphertext, &other_proof));

    // The proofs should not verify for another encryption.
    assert!(!keypair.public().verify_bool(other_ciphertext, &proof));
    assert!(!keypair.public().verify_bool(ciphertext, &other_proof));

    // ...even if the encryption is obtained from the "correct" value.
    let combined_ciphertext = ciphertext + other_ciphertext;
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(combined_ciphertext),
        &G::generator(),
    );
    assert!(!keypair.public().verify_bool(combined_ciphertext, &proof));
}

fn test_bool_proof_serialization<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let mut ciphertexts = HashMap::new();

    for _ in 0..100 {
        let (bool_ciphertext, proof) = keypair.public().encrypt_bool(rng.gen_bool(0.5), &mut rng);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 3 * G::SCALAR_SIZE);
        ciphertexts.insert(bytes, bool_ciphertext);
    }
    assert_eq!(ciphertexts.len(), 100);
    for (bytes, ciphertext) in ciphertexts {
        let proof = RingProof::<G>::from_slice(&bytes).unwrap();
        assert!(keypair.public().verify_bool(ciphertext, &proof));
    }
}

fn test_encrypted_choice_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);

    let choice = keypair.public().encrypt_choice(5, 2, &mut rng);
    let variants = keypair.public().verify_choice(&choice).unwrap();
    assert_eq!(variants.len(), 5);
    for (i, &variant) in variants.iter().enumerate() {
        let expected_plaintext = if i == 2 {
            G::generator()
        } else {
            G::identity()
        };
        assert_ct_eq(
            &keypair.secret().decrypt_to_element(variant),
            &expected_plaintext,
        );
    }
}

mod curve25519 {
    use super::*;
    use elastic_elgamal::group::Curve25519Subgroup;

    #[test]
    fn encryption_roundtrip() {
        test_encryption_roundtrip::<Curve25519Subgroup>();
    }

    #[test]
    fn zero_encryption_works() {
        test_zero_encryption_works::<Curve25519Subgroup>();
    }

    #[test]
    fn zero_proof_serialization() {
        test_zero_proof_serialization::<Curve25519Subgroup>();
    }

    #[test]
    fn bool_encryption_works() {
        test_bool_encryption_works::<Curve25519Subgroup>();
    }

    #[test]
    fn bool_proof_serialization() {
        test_bool_proof_serialization::<Curve25519Subgroup>();
    }

    #[test]
    fn encrypted_choice_works() {
        test_encrypted_choice_works::<Curve25519Subgroup>();
    }
}

mod ristretto {
    use super::*;
    use elastic_elgamal::group::Ristretto;

    #[test]
    fn encryption_roundtrip() {
        test_encryption_roundtrip::<Ristretto>();
    }

    #[test]
    fn zero_encryption_works() {
        test_zero_encryption_works::<Ristretto>();
    }

    #[test]
    fn zero_proof_serialization() {
        test_zero_proof_serialization::<Ristretto>();
    }

    #[test]
    fn bool_encryption_works() {
        test_bool_encryption_works::<Ristretto>();
    }

    #[test]
    fn bool_proof_serialization() {
        test_bool_proof_serialization::<Ristretto>();
    }

    #[test]
    fn encrypted_choice_works() {
        test_encrypted_choice_works::<Ristretto>();
    }
}

mod k256 {
    use super::*;
    use elastic_elgamal::group::Generic;

    type K256 = Generic<::k256::Secp256k1>;

    #[test]
    fn encryption_roundtrip() {
        test_encryption_roundtrip::<K256>();
    }

    #[test]
    fn zero_encryption_works() {
        test_zero_encryption_works::<K256>();
    }

    #[test]
    fn zero_proof_serialization() {
        test_zero_proof_serialization::<K256>();
    }

    #[test]
    fn bool_encryption_works() {
        test_bool_encryption_works::<K256>();
    }

    #[test]
    fn bool_proof_serialization() {
        test_bool_proof_serialization::<K256>();
    }

    #[test]
    fn encrypted_choice_works() {
        test_encrypted_choice_works::<K256>();
    }
}
