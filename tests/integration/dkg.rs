//! Tests focused on distributed key generation.

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
    let key_set = participants[0].key_set();
    let expected_key = key_set.shared_key();
    for (i, participant) in participants.iter().enumerate() {
        assert_eq!(participant.key_set().shared_key(), expected_key);
        assert_eq!(
            participant.public_key_share(),
            key_set.participant_key(i).unwrap()
        );
    }
}

fn tiny_fuzz<G: Group>(params: Params) {
    let mut rng = rand::rng();
    for _ in 0..10 {
        complete_dkg::<G, _>(params, &mut rng);
    }
}

const PARAMS_CASES: [Params; 10] = [
    Params::new(5, 3),
    Params::new(5, 4),
    Params::new(5, 5),
    Params::new(10, 6),
    Params::new(10, 7),
    Params::new(10, 8),
    Params::new(10, 9),
    Params::new(10, 10),
    Params::new(15, 10),
    Params::new(15, 12),
];

mod curve25519 {
    use test_casing::test_casing;

    use super::*;
    use elastic_elgamal::group::Curve25519Subgroup;

    #[test_casing(10, PARAMS_CASES)]
    fn fuzz(params: Params) {
        tiny_fuzz::<Curve25519Subgroup>(params);
    }
}

mod ristretto {
    use test_casing::test_casing;

    use super::*;
    use elastic_elgamal::group::Ristretto;

    #[test_casing(10, PARAMS_CASES)]
    fn fuzz(params: Params) {
        tiny_fuzz::<Ristretto>(params);
    }
}

mod k256 {
    use test_casing::test_casing;

    use super::*;
    use elastic_elgamal::group::Generic;

    type K256 = Generic<::k256::Secp256k1>;

    #[test_casing(10, PARAMS_CASES)]
    fn fuzz(params: Params) {
        tiny_fuzz::<K256>(params);
    }
}
