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
    group::{Curve25519Subgroup, Generic, Group, Ristretto},
    sharing::{
        ActiveParticipant, CandidateShare, DecryptionShare, Params, PartialPublicKeySet,
        PublicKeySet, StartingParticipant,
    },
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
    let talliers: Vec<_> = (0..params.shares)
        .map(|i| StartingParticipant::<G>::new(params, i, rng))
        .collect();
    println!(
        "Talliers: {}",
        serde_json::to_string_pretty(&talliers).unwrap()
    );

    // Public tallier parameters together with proofs may be shared publicly
    // (e.g., on a blockchain).
    let mut partial_info = PartialPublicKeySet::<G>::new(params);
    for (i, tallier) in talliers.iter().enumerate() {
        let (poly, proof) = tallier.public_info();
        partial_info
            .add_participant(i, poly.to_vec(), proof)
            .unwrap();
    }
    println!(
        "Partial public key set after receiving all commitments: {}",
        serde_json::to_string_pretty(&partial_info).unwrap()
    );

    let key_set = partial_info.complete().unwrap();

    println!(
        "Threshold encryption params: {}",
        serde_json::to_string_pretty(&key_set).unwrap()
    );

    let mut talliers: Vec<_> = talliers
        .into_iter()
        .map(|tallier| tallier.finalize_key_set(&partial_info).unwrap())
        .collect();
    println!(
        "Talliers after finalizing key set: {}",
        serde_json::to_string_pretty(&talliers).unwrap()
    );

    // Then, talliers exchange private shares with each other.
    // This is the only private / non-auditable part of the protocol, although it can be made
    // auditable as described in the `sharing` module docs.
    for i in 0..talliers.len() {
        for j in 0..talliers.len() {
            if j != i {
                let message = talliers[i].message(j).clone();
                talliers[j].process_message(i, message).unwrap();
            }
        }
    }

    let talliers = talliers
        .into_iter()
        .map(|tallier| tallier.complete())
        .collect();
    println!(
        "Active talliers: {}",
        serde_json::to_string_pretty(&talliers).unwrap()
    );
    (key_set, talliers)
}

fn vote<G: Group>() {
    let mut rng = thread_rng();

    // Before polling is started, talliers agree on the shared encryption key.
    let (key_set, talliers) = initialize_talliers::<G, _>(TALLIER_PARAMS, &mut rng);

    // During polling, voters submit votes together with the proof of correctness.
    let mut expected_totals = [0; OPTIONS_COUNT];
    let mut encrypted_totals = [Ciphertext::zero(); OPTIONS_COUNT];
    for i in 0..VOTES {
        let choice = rng.gen_range(0..OPTIONS_COUNT);
        println!("\nVoter #{} making choice #{}", i + 1, choice + 1);
        expected_totals[choice] += 1;
        let choice = key_set
            .shared_key()
            .encrypt_choice(OPTIONS_COUNT, choice, &mut rng);

        println!("Choice: {}", serde_json::to_string_pretty(&choice).unwrap());

        let variants = key_set.shared_key().verify_choice(&choice).unwrap();
        for (i, &variant) in variants.iter().enumerate() {
            encrypted_totals[i] += variant;
        }
    }

    println!(
        "\nCumulative choice variants: {}",
        serde_json::to_string_pretty(&encrypted_totals).unwrap()
    );

    // After polling, talliers submit decryption shares together with a proof of their correctness.
    let lookup_table = DiscreteLogTable::<G>::new(0..=(VOTES as u64));
    for (i, (&variant_totals, &expected)) in
        encrypted_totals.iter().zip(&expected_totals).enumerate()
    {
        println!("\nDecrypting cumulative total for option #{}", i + 1);

        let decryption_shares: Vec<_> = talliers
            .iter()
            .enumerate()
            .choose_multiple(&mut rng, TALLIER_PARAMS.threshold)
            .into_iter()
            .map(|(j, tallier)| (j, tallier.decrypt_share(variant_totals, &mut rng)))
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
                    .verify_share(candidate_share, variant_totals, j, &proof)
                    .unwrap();
                (j, share)
            })
            .collect();

        let variant_tally =
            DecryptionShare::combine(TALLIER_PARAMS, variant_totals, decryption_shares).unwrap();
        let variant_tally = lookup_table.get(&variant_tally).unwrap();
        println!("Variant #{} decrypted tally: {}", i + 1, variant_tally);
        assert_eq!(variant_tally, expected);
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
