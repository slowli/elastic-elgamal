//! Simple universally verifiable crypto voting protocol using threshold ElGamal encryption.
//! Voter authentication is outside the protocol scope.
//!
//! See [*Simple Verifiable Elections*][elections] by Benaloh for an overview of a similar
//! voting protocol.
//!
//! [elections]: https://static.usenix.org/event/evt06/tech/full_papers/benaloh/benaloh.pdf

use rand::{seq::IteratorRandom, thread_rng, Rng};
use rand_core::{CryptoRng, RngCore};

use std::env;

use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice},
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
    sharing::{ActiveParticipant, CandidateShare, Dealer, DecryptionShare, Params, PublicKeySet},
    Ciphertext, DiscreteLogTable,
};

/// Number of options in the poll.
const OPTIONS_COUNT: usize = 3;
/// Number of votes to be cast.
const VOTES: usize = 30;
/// Number of talliers.
const TALLIER_PARAMS: Params = Params {
    shares: 5,
    threshold: 3,
};

fn initialize_talliers<G: Group, R: CryptoRng + RngCore>(
    params: Params,
    rng: &mut R,
) -> (PublicKeySet<G>, Vec<ActiveParticipant<G>>) {
    let dealer = Dealer::<G>::new(params, rng);
    let (public_poly, public_poly_proof) = dealer.public_info();
    let key_set = PublicKeySet::new(params, public_poly, public_poly_proof).unwrap();

    let talliers: Vec<_> = (0..params.shares)
        .map(|i| {
            ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i))
                .unwrap()
        })
        .collect();
    (key_set, talliers)
}

fn vote<G: Group>() {
    let mut rng = thread_rng();

    // Before polling is started, talliers agree on the shared encryption key.
    let (key_set, talliers) = initialize_talliers::<G, _>(TALLIER_PARAMS, &mut rng);
    let choice_params = ChoiceParams::single(key_set.shared_key().clone(), OPTIONS_COUNT);

    // During polling, voters submit votes together with the proof of correctness.
    let mut expected_totals = [0; OPTIONS_COUNT];
    let mut encrypted_totals = [Ciphertext::zero(); OPTIONS_COUNT];
    for i in 0..VOTES {
        let choice = rng.gen_range(0..OPTIONS_COUNT);
        println!("\nVoter #{} making choice #{}", i + 1, choice + 1);
        expected_totals[choice] += 1;
        let encrypted = EncryptedChoice::single(&choice_params, choice, &mut rng);

        println!(
            "Choice: {}",
            serde_json::to_string_pretty(&encrypted).unwrap()
        );

        let votes = encrypted.verify(&choice_params).unwrap();
        for (total, &vote) in encrypted_totals.iter_mut().zip(votes) {
            *total += vote;
        }
    }

    println!(
        "\nCumulative choices: {}",
        serde_json::to_string_pretty(&encrypted_totals).unwrap()
    );

    // After polling, talliers submit decryption shares together with a proof of their correctness.
    let lookup_table = DiscreteLogTable::<G>::new(0..=(VOTES as u64));
    for (i, (&option_totals, &expected)) in
        encrypted_totals.iter().zip(&expected_totals).enumerate()
    {
        println!("\nDecrypting cumulative total for option #{}", i + 1);

        let decryption_shares: Vec<_> = talliers
            .iter()
            .enumerate()
            .choose_multiple(&mut rng, TALLIER_PARAMS.threshold)
            .into_iter()
            .map(|(j, tallier)| (j, tallier.decrypt_share(option_totals, &mut rng)))
            .map(|(j, (share, proof))| {
                let share = share.to_bytes(); // Emulate transfer via network
                let candidate_share = CandidateShare::from_bytes(&share).unwrap();
                let share_with_proof = serde_json::json!({
                    "share": &candidate_share,
                    "proof": &proof,
                });

                println!(
                    "Share from tallier #{}: {}",
                    j + 1,
                    serde_json::to_string_pretty(&share_with_proof).unwrap()
                );

                let share = key_set
                    .verify_share(candidate_share, option_totals, j, &proof)
                    .unwrap();
                (j, share)
            })
            .collect();

        let option_tally =
            DecryptionShare::combine(TALLIER_PARAMS, option_totals, decryption_shares).unwrap();
        let option_tally = lookup_table.get(&option_tally).unwrap();
        println!("Variant #{} decrypted tally: {}", i + 1, option_tally);
        assert_eq!(option_tally, expected);
        println!("The decrypted number is as expected!");
    }
}

fn main() {
    match env::args().nth(1).as_deref() {
        None | Some("ristretto") => vote::<Ristretto>(),
        Some("curve25519") => vote::<Curve25519Subgroup>(),
        Some("k256") => vote::<Generic<k256::Secp256k1>>(),
        Some(other) => panic!(
            "Unknown group: {}; use one of `curve25519`, `ristretto` or `k256`",
            other
        ),
    }
}
