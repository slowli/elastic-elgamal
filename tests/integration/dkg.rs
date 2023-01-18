//! Tests focused on distributed key generation.

use rand::thread_rng;
use rand_core::{CryptoRng, RngCore};

use elastic_elgamal::{dkg::ParticipantCollectingCommitments, group::Group, sharing::Params};

fn complete_dkg<G: Group, R: RngCore + CryptoRng>(params: Params, rng: &mut R) {
    let participant_count = params.shares;
    let participants =
        (0..participant_count).map(|i| ParticipantCollectingCommitments::<G>::new(params, i, rng));
    let mut participants: Vec<_> = participants.collect();

    let commitments: Vec<_> = participants
        .iter()
        .map(|participant| participant.commitment())
        .collect();
    for (i, participant) in participants.iter_mut().enumerate() {
        for (j, &commitment) in commitments.iter().enumerate() {
            if i != j {
                participant.insert_commitment(j, commitment);
            }
        }
    }

    let mut participants: Vec<_> = participants
        .into_iter()
        .map(|participant| participant.finish_commitment_phase())
        .collect();
    let infos: Vec<_> = participants
        .iter()
        .map(|participant| participant.public_info().into_owned())
        .collect();
    for (i, participant) in participants.iter_mut().enumerate() {
        for (j, info) in infos.iter().enumerate() {
            if i != j {
                participant
                    .insert_public_polynomial(j, info.clone())
                    .unwrap();
            }
        }
    }

    let mut participants: Vec<_> = participants
        .into_iter()
        .map(|participant| participant.finish_polynomials_phase())
        .collect();
    for i in 0..participant_count {
        for j in 0..participant_count {
            if i == j {
                continue;
            }
            let share = participants[i].secret_share_for_participant(j);
            participants[j].insert_secret_share(i, share).unwrap();
        }
    }

    let participants: Vec<_> = participants
        .into_iter()
        .map(|participant| participant.complete().unwrap())
        .collect();
    // Check that the shared key is the same for all participants.
    let expected_key = participants[0].key_set().shared_key();
    for participant in &participants {
        assert_eq!(participant.key_set().shared_key(), expected_key);
    }
}

fn tiny_fuzz<G: Group>(params: Params) {
    let mut rng = thread_rng();
    for _ in 0..10 {
        complete_dkg::<G, _>(params, &mut rng);
    }
}

mod curve25519 {
    use super::*;
    use elastic_elgamal::group::Curve25519Subgroup;

    #[test]
    fn fuzz_3_of_5() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(5, 3));
    }

    #[test]
    fn fuzz_4_of_5() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(5, 4));
    }

    #[test]
    fn fuzz_5_of_5() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(5, 5));
    }

    #[test]
    fn fuzz_6_of_10() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(10, 6));
    }

    #[test]
    fn fuzz_7_of_10() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(10, 7));
    }

    #[test]
    fn fuzz_8_of_10() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(10, 8));
    }

    #[test]
    fn fuzz_9_of_10() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(10, 9));
    }

    #[test]
    fn fuzz_10_of_10() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(10, 10));
    }

    #[test]
    fn fuzz_10_of_15() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(15, 10));
    }

    #[test]
    fn fuzz_12_of_15() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(15, 12));
    }
}

mod ristretto {
    use super::*;
    use elastic_elgamal::group::Ristretto;

    #[test]
    fn fuzz_3_of_5() {
        tiny_fuzz::<Ristretto>(Params::new(5, 3));
    }

    #[test]
    fn fuzz_4_of_5() {
        tiny_fuzz::<Ristretto>(Params::new(5, 4));
    }

    #[test]
    fn fuzz_5_of_5() {
        tiny_fuzz::<Ristretto>(Params::new(5, 5));
    }

    #[test]
    fn fuzz_6_of_10() {
        tiny_fuzz::<Ristretto>(Params::new(10, 6));
    }

    #[test]
    fn fuzz_7_of_10() {
        tiny_fuzz::<Ristretto>(Params::new(10, 7));
    }

    #[test]
    fn fuzz_8_of_10() {
        tiny_fuzz::<Ristretto>(Params::new(10, 8));
    }

    #[test]
    fn fuzz_9_of_10() {
        tiny_fuzz::<Ristretto>(Params::new(10, 9));
    }

    #[test]
    fn fuzz_10_of_10() {
        tiny_fuzz::<Ristretto>(Params::new(10, 10));
    }

    #[test]
    fn fuzz_10_of_15() {
        tiny_fuzz::<Ristretto>(Params::new(15, 10));
    }

    #[test]
    fn fuzz_12_of_15() {
        tiny_fuzz::<Ristretto>(Params::new(15, 12));
    }
}

mod k256 {
    use super::*;
    use elastic_elgamal::group::Generic;

    type K256 = Generic<::k256::Secp256k1>;

    #[test]
    fn fuzz_3_of_5() {
        tiny_fuzz::<K256>(Params::new(5, 3));
    }

    #[test]
    fn fuzz_4_of_5() {
        tiny_fuzz::<K256>(Params::new(5, 4));
    }

    #[test]
    fn fuzz_5_of_5() {
        tiny_fuzz::<K256>(Params::new(5, 5));
    }

    #[test]
    fn fuzz_6_of_10() {
        tiny_fuzz::<K256>(Params::new(10, 6));
    }

    #[test]
    fn fuzz_7_of_10() {
        tiny_fuzz::<K256>(Params::new(10, 7));
    }

    #[test]
    fn fuzz_8_of_10() {
        tiny_fuzz::<K256>(Params::new(10, 8));
    }

    #[test]
    fn fuzz_9_of_10() {
        tiny_fuzz::<K256>(Params::new(10, 9));
    }

    #[test]
    fn fuzz_10_of_10() {
        tiny_fuzz::<K256>(Params::new(10, 10));
    }

    #[test]
    fn fuzz_10_of_15() {
        tiny_fuzz::<K256>(Params::new(15, 10));
    }

    #[test]
    fn fuzz_12_of_15() {
        tiny_fuzz::<K256>(Params::new(15, 12));
    }
}
