//! Tests focused on sharing.

use rand::{
    seq::{IteratorRandom, SliceRandom},
    thread_rng, Rng,
};
use rand_core::{CryptoRng, RngCore};

use crate::assert_ct_eq;
use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice, QuadraticVotingBallot, QuadraticVotingParams},
    group::Group,
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
    Ciphertext, DiscreteLogTable, VerifiableDecryption,
};

struct Rig<G: Group> {
    key_set: PublicKeySet<G>,
    participants: Vec<ActiveParticipant<G>>,
}

impl<G: Group> Rig<G> {
    fn new(params: Params, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let dealer = Dealer::<G>::new(params, rng);
        let (public_poly, public_poly_proof) = dealer.public_info();
        let key_set = PublicKeySet::new(params, public_poly, public_poly_proof).unwrap();

        let participants: Vec<_> = (0..params.shares)
            .map(|i| {
                ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i))
                    .unwrap()
            })
            .collect();

        Self {
            key_set,
            participants,
        }
    }

    fn decryption_shares(
        &self,
        ciphertext: Ciphertext<G>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<VerifiableDecryption<G>> {
        self.participants
            .iter()
            .map(|participant| participant.decrypt_share(ciphertext, rng).0)
            .collect()
    }

    fn assert_votes(
        &self,
        encrypted_totals: &[Ciphertext<G>],
        expected_totals: &[u64],
        rng: &mut (impl RngCore + CryptoRng),
    ) {
        let max_votes = expected_totals.iter().copied().max().unwrap();
        let lookup_table = DiscreteLogTable::<G>::new(0..=max_votes);
        let params = self.key_set.params();

        for (&option_totals, &expected) in encrypted_totals.iter().zip(expected_totals) {
            // Now, each counter produces a decryption share. We take 8 shares randomly
            // (slightly more than the necessary 7).
            let decryption_shares = self.decryption_shares(option_totals, rng);
            let decryption_shares = decryption_shares
                .into_iter()
                .enumerate()
                .choose_multiple(rng, 8);

            let combined_decryption = params.combine_shares(decryption_shares).unwrap();
            let option_totals = combined_decryption
                .decrypt(option_totals, &lookup_table)
                .unwrap();
            assert_eq!(option_totals, expected);
        }
    }
}

fn test_group_info_can_be_restored_from_participants<G: Group>(params: Params) {
    let rig: Rig<G> = Rig::new(params, &mut thread_rng());
    let expected_shared_key = rig.key_set.shared_key();
    let restored_info =
        PublicKeySet::from_participants(params, rig.key_set.participant_keys().to_vec()).unwrap();
    assert_eq!(restored_info.shared_key(), expected_shared_key);
}

fn tiny_fuzz<G: Group>(params: Params) {
    let mut rng = thread_rng();
    let rig: Rig<G> = Rig::new(params, &mut rng);
    for _ in 0..20 {
        let value = G::generate_scalar(&mut rng);
        let encrypted = rig.key_set.shared_key().encrypt(value, &mut rng);
        let shares = rig.decryption_shares(encrypted, &mut rng);
        for _ in 0..5 {
            let chosen_shares = shares
                .iter()
                .copied()
                .enumerate()
                .choose_multiple(&mut rng, params.threshold);
            let combined = params.combine_shares(chosen_shares).unwrap();
            let decrypted = combined.decrypt_to_element(encrypted);

            assert_ct_eq(&decrypted, &G::vartime_mul_generator(&value));
        }
    }
}

const OPTIONS_COUNT: usize = 5;
const VOTES: usize = 50;
const CREDIT_AMOUNT: u64 = 20;

fn test_simple_voting<G: Group>() {
    let mut rng = thread_rng();
    let params = Params::new(10, 7);
    let rig = Rig::<G>::new(params, &mut rng);
    let shared_key = rig.key_set.shared_key().clone();
    let choice_params = ChoiceParams::single(shared_key, OPTIONS_COUNT);

    let mut expected_totals = [0; OPTIONS_COUNT];
    let mut encrypted_totals = [Ciphertext::zero(); OPTIONS_COUNT];

    for _ in 0..VOTES {
        let choice = rng.gen_range(0..OPTIONS_COUNT);
        expected_totals[choice] += 1;
        let encrypted = EncryptedChoice::single(&choice_params, choice, &mut rng);
        let choices = encrypted.verify(&choice_params).unwrap();
        for (total, &choice) in encrypted_totals.iter_mut().zip(choices) {
            *total += choice;
        }
    }

    rig.assert_votes(&encrypted_totals, &expected_totals, &mut rng);
}

fn credit(votes: &[u64]) -> u64 {
    votes.iter().map(|&x| x * x).sum::<u64>()
}

fn gen_votes(rng: &mut impl Rng) -> [u64; OPTIONS_COUNT] {
    let mut votes = [0_u64; OPTIONS_COUNT];
    while rng.gen_bool(0.8) {
        let mut new_votes = votes;
        *new_votes.choose_mut(rng).unwrap() += 1;
        if credit(&new_votes) > CREDIT_AMOUNT {
            break;
        } else {
            votes = new_votes;
        }
    }
    votes
}

fn test_quadratic_voting<G: Group>() {
    let mut rng = thread_rng();
    let params = Params::new(10, 7);
    let rig = Rig::<G>::new(params, &mut rng);
    let shared_key = rig.key_set.shared_key().clone();
    let vote_params = QuadraticVotingParams::new(shared_key, OPTIONS_COUNT, CREDIT_AMOUNT);

    let mut expected_totals = [0_u64; OPTIONS_COUNT];
    let mut encrypted_totals = [Ciphertext::zero(); OPTIONS_COUNT];

    for _ in 0..VOTES {
        let votes = gen_votes(&mut rng);
        for (exp, vote) in expected_totals.iter_mut().zip(votes) {
            *exp += vote;
        }

        let encrypted = QuadraticVotingBallot::new(&vote_params, &votes, &mut rng);
        let votes = encrypted.verify(&vote_params).unwrap();
        for (total, vote) in encrypted_totals.iter_mut().zip(votes) {
            *total += vote;
        }
    }

    rig.assert_votes(&encrypted_totals, &expected_totals, &mut rng);
}

mod curve25519 {
    use super::*;
    use elastic_elgamal::group::Curve25519Subgroup;

    #[test]
    fn group_info_can_be_restored_from_participants() {
        test_group_info_can_be_restored_from_participants::<Curve25519Subgroup>(Params::new(10, 7));
        test_group_info_can_be_restored_from_participants::<Curve25519Subgroup>(Params::new(10, 8));
    }

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

    #[test]
    fn fuzz_12_of_20() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(20, 12));
    }

    #[test]
    fn fuzz_16_of_20() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(20, 16));
    }

    #[test]
    fn fuzz_18_of_20() {
        tiny_fuzz::<Curve25519Subgroup>(Params::new(20, 18));
    }

    #[test]
    fn simple_voting() {
        test_simple_voting::<Curve25519Subgroup>();
    }

    #[test]
    fn quadratic_voting() {
        test_quadratic_voting::<Curve25519Subgroup>();
    }
}

mod ristretto {
    use super::*;
    use elastic_elgamal::group::Ristretto;

    #[test]
    fn group_info_can_be_restored_from_participants() {
        test_group_info_can_be_restored_from_participants::<Ristretto>(Params::new(10, 7));
        test_group_info_can_be_restored_from_participants::<Ristretto>(Params::new(10, 8));
    }

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

    #[test]
    fn fuzz_12_of_20() {
        tiny_fuzz::<Ristretto>(Params::new(20, 12));
    }

    #[test]
    fn fuzz_16_of_20() {
        tiny_fuzz::<Ristretto>(Params::new(20, 16));
    }

    #[test]
    fn fuzz_18_of_20() {
        tiny_fuzz::<Ristretto>(Params::new(20, 18));
    }

    #[test]
    fn simple_voting() {
        test_simple_voting::<Ristretto>();
    }

    #[test]
    fn quadratic_voting() {
        test_quadratic_voting::<Ristretto>();
    }
}

mod k256 {
    use super::*;
    use elastic_elgamal::group::Generic;

    type K256 = Generic<::k256::Secp256k1>;

    #[test]
    fn group_info_can_be_restored_from_participants() {
        test_group_info_can_be_restored_from_participants::<K256>(Params::new(10, 7));
        test_group_info_can_be_restored_from_participants::<K256>(Params::new(10, 8));
    }

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

    #[test]
    fn fuzz_12_of_20() {
        tiny_fuzz::<K256>(Params::new(20, 12));
    }

    #[test]
    fn fuzz_16_of_20() {
        tiny_fuzz::<K256>(Params::new(20, 16));
    }

    #[test]
    fn fuzz_18_of_20() {
        tiny_fuzz::<K256>(Params::new(20, 18));
    }

    #[test]
    fn simple_voting() {
        test_simple_voting::<K256>();
    }

    #[test]
    fn quadratic_voting() {
        test_quadratic_voting::<K256>();
    }
}
