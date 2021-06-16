//! Basic tests.

use rand::{thread_rng, Rng};

use std::collections::HashMap;

use crate::assert_ct_eq;
use elgamal_with_sharing::{
    group::Group, EncryptedChoice, Encryption, Keypair, LogEqualityProof, RingProof,
};

fn test_encryption_roundtrip<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let message = 12_345_u64;
    let encrypted = Encryption::new(message, keypair.public(), &mut rng);
    let decryption = keypair.secret().decrypt_to_element(encrypted);
    let message = G::mul_generator(&G::Scalar::from(message));
    assert_ct_eq(&decryption, &message);
}

fn test_zero_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let (zero_encryption, proof) = Encryption::encrypt_zero(keypair.public(), &mut rng);
    assert!(zero_encryption.verify_zero(keypair.public(), &proof));
    let decrypted = keypair.secret().decrypt_to_element(zero_encryption);
    assert_ct_eq(&decrypted, &G::identity());

    // The proof should not verify for non-zero messages.
    let encryption = Encryption::new(123_u64, keypair.public(), &mut rng);
    assert!(!encryption.verify_zero(keypair.public(), &proof));

    // ...or for another receiver key
    let other_keypair = Keypair::generate(&mut rng);
    assert!(!encryption.verify_zero(other_keypair.public(), &proof));

    // ...or for another secret scalar used.
    let (other_zero_encryption, other_proof) = Encryption::encrypt_zero(keypair.public(), &mut rng);
    assert!(!other_zero_encryption.verify_zero(keypair.public(), &proof));
    assert!(!zero_encryption.verify_zero(keypair.public(), &other_proof));

    let combined_encryption = other_zero_encryption + zero_encryption;
    assert!(!combined_encryption.verify_zero(keypair.public(), &proof));
    assert!(!combined_encryption.verify_zero(keypair.public(), &other_proof));
}

fn test_zero_proof_serialization<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let mut encryptions = HashMap::new();

    for _ in 0..100 {
        let (zero_encryption, proof) = Encryption::encrypt_zero(keypair.public(), &mut rng);
        let bytes = proof.to_bytes();
        encryptions.insert(bytes.to_vec(), zero_encryption);
    }
    assert_eq!(encryptions.len(), 100);
    for (bytes, encryption) in encryptions {
        let proof = LogEqualityProof::<G>::from_slice(&bytes).unwrap();
        assert!(encryption.verify_zero(keypair.public(), &proof));
    }
}

fn test_bool_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);

    let (encryption, proof) = Encryption::encrypt_bool(false, keypair.public(), &mut rng);
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(encryption),
        &G::identity(),
    );
    assert!(encryption.verify_bool(keypair.public(), &proof));

    let (other_encryption, other_proof) =
        Encryption::encrypt_bool(true, keypair.public(), &mut rng);
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(other_encryption),
        &G::generator(),
    );
    assert!(other_encryption.verify_bool(keypair.public(), &other_proof));

    // The proofs should not verify for another encryption.
    assert!(!other_encryption.verify_bool(keypair.public(), &proof));
    assert!(!encryption.verify_bool(keypair.public(), &other_proof));

    // ...even if the encryption is obtained from the "correct" value.
    let combined_encryption = encryption + other_encryption;
    assert_ct_eq(
        &keypair.secret().decrypt_to_element(combined_encryption),
        &G::generator(),
    );
    assert!(!combined_encryption.verify_bool(keypair.public(), &proof));
}

fn test_bool_proof_serialization<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let mut encryptions = HashMap::new();

    for _ in 0..100 {
        let (bool_encryption, proof) =
            Encryption::encrypt_bool(rng.gen_bool(0.5), keypair.public(), &mut rng);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 3 * G::SCALAR_SIZE);
        encryptions.insert(bytes, bool_encryption);
    }
    assert_eq!(encryptions.len(), 100);
    for (bytes, encryption) in encryptions {
        let proof = RingProof::<G>::from_slice(&bytes).unwrap();
        assert!(encryption.verify_bool(keypair.public(), &proof));
    }
}

fn test_encrypted_choice_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);

    let choice = EncryptedChoice::new(5, 2, keypair.public(), &mut rng);
    assert!(choice.verify(keypair.public()).is_some());
    assert_eq!(choice.variants_unchecked().len(), 5);
    for (i, &variant) in choice.variants_unchecked().iter().enumerate() {
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
    use elgamal_with_sharing::group::Curve25519Subgroup;

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
    use elgamal_with_sharing::group::Ristretto;

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
    use elgamal_with_sharing::group::Generic;

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
