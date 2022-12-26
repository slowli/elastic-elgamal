//! Basic tests.

use merlin::Transcript;
use rand::{thread_rng, Rng};

use std::collections::HashMap;

use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice},
    group::Group,
    CandidateDecryption, Ciphertext, CiphertextWithValue, Keypair, LogEqualityProof, RingProof,
    SumOfSquaresProof, VerifiableDecryption, VerificationError,
};

fn test_encryption_roundtrip<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let message = 12_345_u64;
    let ciphertext = keypair.public().encrypt(message, &mut rng);
    let decryption = keypair.secret().decrypt_to_element(ciphertext);
    let message = G::mul_generator(&G::Scalar::from(message));
    assert_eq!(decryption, message);
}

fn test_zero_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);
    let (zero_ciphertext, proof) = keypair.public().encrypt_zero(&mut rng);
    keypair
        .public()
        .verify_zero(zero_ciphertext, &proof)
        .unwrap();
    let decrypted = keypair.secret().decrypt_to_element(zero_ciphertext);
    assert_eq!(decrypted, G::identity());

    // The proof should not verify for non-zero messages.
    let ciphertext = keypair.public().encrypt(123_u64, &mut rng);
    assert!(keypair.public().verify_zero(ciphertext, &proof).is_err());

    // ...or for another receiver key
    let other_keypair = Keypair::generate(&mut rng);
    assert!(other_keypair
        .public()
        .verify_zero(ciphertext, &proof)
        .is_err());

    // ...or for another secret scalar used.
    let (other_zero_ciphertext, other_proof) = keypair.public().encrypt_zero(&mut rng);
    assert!(keypair
        .public()
        .verify_zero(other_zero_ciphertext, &proof)
        .is_err());
    assert!(keypair
        .public()
        .verify_zero(zero_ciphertext, &other_proof)
        .is_err());

    let combined_ciphertext = other_zero_ciphertext + zero_ciphertext;
    assert!(keypair
        .public()
        .verify_zero(combined_ciphertext, &proof)
        .is_err());
    assert!(keypair
        .public()
        .verify_zero(combined_ciphertext, &other_proof)
        .is_err());
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
        let proof = LogEqualityProof::<G>::from_bytes(&bytes).unwrap();
        keypair.public().verify_zero(ciphertext, &proof).unwrap();
    }
}

fn test_bool_encryption_works<G: Group>() {
    let mut rng = thread_rng();
    let keypair = Keypair::<G>::generate(&mut rng);

    let (ciphertext, proof) = keypair.public().encrypt_bool(false, &mut rng);
    assert_eq!(
        keypair.secret().decrypt_to_element(ciphertext),
        G::identity(),
    );
    keypair.public().verify_bool(ciphertext, &proof).unwrap();

    let (other_ciphertext, other_proof) = keypair.public().encrypt_bool(true, &mut rng);
    assert_eq!(
        keypair.secret().decrypt_to_element(other_ciphertext),
        G::generator(),
    );
    keypair
        .public()
        .verify_bool(other_ciphertext, &other_proof)
        .unwrap();

    // The proofs should not verify for another encryption.
    assert!(keypair
        .public()
        .verify_bool(other_ciphertext, &proof)
        .is_err());
    assert!(keypair
        .public()
        .verify_bool(ciphertext, &other_proof)
        .is_err());

    // ...even if the encryption is obtained from the "correct" value.
    let combined_ciphertext = ciphertext + other_ciphertext;
    assert_eq!(
        keypair.secret().decrypt_to_element(combined_ciphertext),
        G::generator(),
    );
    assert!(keypair
        .public()
        .verify_bool(combined_ciphertext, &proof)
        .is_err());
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
        let proof = RingProof::<G>::from_bytes(&bytes).unwrap();
        keypair.public().verify_bool(ciphertext, &proof).unwrap();
    }
}

const OPTIONS_COUNTS: &[usize] = &[2, 3, 5, 10, 15];

fn test_encrypted_choice<G: Group>(options_count: usize) {
    let mut rng = thread_rng();
    let (pk, sk) = Keypair::<G>::generate(&mut rng).into_tuple();
    let choice_params = ChoiceParams::single(pk, options_count);

    let choice = rng.gen_range(0..options_count);
    let encrypted = EncryptedChoice::single(&choice_params, choice, &mut rng);
    let choices = encrypted.verify(&choice_params).unwrap();
    assert_eq!(choices.len(), options_count);
    for (i, &ciphertext) in choices.iter().enumerate() {
        let expected_plaintext = if i == choice {
            G::generator()
        } else {
            G::identity()
        };
        assert_eq!(sk.decrypt_to_element(ciphertext), expected_plaintext);
    }
}

fn test_encrypted_multi_choice<G: Group>(options_count: usize) {
    let mut rng = thread_rng();
    let (pk, sk) = Keypair::<G>::generate(&mut rng).into_tuple();
    let choice_params = ChoiceParams::multi(pk, options_count);

    let choices: Vec<_> = (0..options_count).map(|_| rng.gen()).collect();
    let encrypted = EncryptedChoice::new(&choice_params, &choices, &mut rng);
    let ciphertexts = encrypted.verify(&choice_params).unwrap();
    assert_eq!(ciphertexts.len(), options_count);
    for (i, &ciphertext) in ciphertexts.iter().enumerate() {
        let expected_plaintext = if choices[i] {
            G::generator()
        } else {
            G::identity()
        };
        assert_eq!(sk.decrypt_to_element(ciphertext), expected_plaintext);
    }
}

fn test_sum_of_squares_proof<G: Group>(squares_count: usize) {
    let mut rng = thread_rng();
    let (pk, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    let numbers: Vec<_> = (0..squares_count)
        .map(|_| rng.gen_range(0_u64..1_000))
        .collect();
    let sum_of_squares = numbers.iter().map(|&x| x * x).sum::<u64>();
    let numbers: Vec<_> = numbers
        .into_iter()
        .map(|x| CiphertextWithValue::new(x, &pk, &mut rng).generalize())
        .collect();
    let sum_of_squares = CiphertextWithValue::new(sum_of_squares, &pk, &mut rng).generalize();

    let proof = SumOfSquaresProof::new(
        numbers.iter(),
        &sum_of_squares,
        &pk,
        &mut Transcript::new(b"test_sum_of_squares"),
        &mut rng,
    );

    let numbers: Vec<_> = numbers.into_iter().map(Ciphertext::from).collect();
    let mut sum_of_squares = Ciphertext::from(sum_of_squares);
    proof
        .verify(
            numbers.iter(),
            &sum_of_squares,
            &pk,
            &mut Transcript::new(b"test_sum_of_squares"),
        )
        .unwrap();

    let (other_pk, _) = Keypair::<G>::generate(&mut rng).into_tuple();
    assert!(proof
        .verify(
            numbers.iter(),
            &sum_of_squares,
            &other_pk,
            &mut Transcript::new(b"test_sum_of_squares"),
        )
        .is_err());

    sum_of_squares += -Ciphertext::non_blinded(1);
    assert!(proof
        .verify(
            numbers.iter(),
            &sum_of_squares,
            &pk,
            &mut Transcript::new(b"test_sum_of_squares"),
        )
        .is_err());
}

fn test_verifiable_decryption<G: Group>() {
    let mut rng = thread_rng();
    let (bogus_key, _) = Keypair::<G>::generate(&mut rng).into_tuple();

    for _ in 0..20 {
        let keypair = Keypair::<G>::generate(&mut rng);
        let value = rng.gen_range(0_u64..100);
        let ciphertext = keypair.public().encrypt(value, &mut rng);

        let (decryption, proof) = VerifiableDecryption::new(
            ciphertext,
            &keypair,
            &mut Transcript::new(b"decryption_test"),
            &mut rng,
        );

        let candidate_decryption = CandidateDecryption::from(decryption);
        candidate_decryption
            .verify(
                ciphertext,
                keypair.public(),
                &proof,
                &mut Transcript::new(b"decryption_test"),
            )
            .unwrap();

        let err = candidate_decryption
            .verify(
                ciphertext,
                &bogus_key,
                &proof,
                &mut Transcript::new(b"decryption_test"),
            )
            .map(drop)
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let bogus_ciphertext = ciphertext + keypair.public().encrypt(0_u64, &mut rng);
        let err = candidate_decryption
            .verify(
                bogus_ciphertext,
                keypair.public(),
                &proof,
                &mut Transcript::new(b"decryption_test"),
            )
            .map(drop)
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));

        let err = candidate_decryption
            .verify(
                ciphertext,
                keypair.public(),
                &proof,
                &mut Transcript::new(b"other"),
            )
            .map(drop)
            .unwrap_err();
        assert!(matches!(err, VerificationError::ChallengeMismatch));
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
    fn encrypted_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing single choice with {options_count} options");
            test_encrypted_choice::<Curve25519Subgroup>(options_count);
        }
    }

    #[test]
    fn encrypted_multi_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing multi choice with {options_count} options");
            test_encrypted_multi_choice::<Curve25519Subgroup>(options_count);
        }
    }

    #[test]
    fn sum_of_squares_proof() {
        for &squares_count in OPTIONS_COUNTS {
            println!("testing sum of squares proof with {squares_count} squares");
            test_sum_of_squares_proof::<Curve25519Subgroup>(squares_count);
        }
    }

    #[test]
    fn verifiable_decryption() {
        test_verifiable_decryption::<Curve25519Subgroup>();
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
    fn encrypted_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing single choice with {options_count} options");
            test_encrypted_choice::<Ristretto>(options_count);
        }
    }

    #[test]
    fn encrypted_multi_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing multi choice with {options_count} options");
            test_encrypted_multi_choice::<Ristretto>(options_count);
        }
    }

    #[test]
    fn sum_of_squares_proof() {
        for &squares_count in OPTIONS_COUNTS {
            println!("testing sum of squares proof with {squares_count} squares");
            test_sum_of_squares_proof::<Ristretto>(squares_count);
        }
    }

    #[test]
    fn verifiable_decryption() {
        test_verifiable_decryption::<Ristretto>();
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
    fn encrypted_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing single choice with {options_count} options");
            test_encrypted_choice::<K256>(options_count);
        }
    }

    #[test]
    fn encrypted_multi_choice() {
        for &options_count in OPTIONS_COUNTS {
            println!("testing multi choice with {options_count} options");
            test_encrypted_multi_choice::<K256>(options_count);
        }
    }

    #[test]
    fn sum_of_squares_proof() {
        for &squares_count in OPTIONS_COUNTS {
            println!("testing sum of squares proof with {squares_count} squares");
            test_sum_of_squares_proof::<K256>(squares_count);
        }
    }

    #[test]
    fn verifiable_decryption() {
        test_verifiable_decryption::<K256>();
    }
}
