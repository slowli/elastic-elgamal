use rand::{seq::IteratorRandom, thread_rng, Rng};
use rand_core::{CryptoRng, RngCore};

use std::{collections::HashMap, env, iter::FromIterator};

use elgamal_with_sharing::{
    sharing::{
        ActiveParticipant, CandidateShare, DecryptionShare, Params, PartialPublicKeySet,
        PublicKeySet, StartingParticipant,
    },
    DiscreteLogLookupTable, Edwards, EncryptedChoice, Encryption, Generic, Group, Ristretto,
};

/// Number of options in the poll.
const OPTIONS_COUNT: usize = 2;
/// Number of votes to be cast.
const VOTES: usize = 20;
/// Number of talliers.
const TALLIER_PARAMS: Params = Params {
    shares: 5,
    threshold: 3,
};

fn dump_group_info<G: Group>(info: &PublicKeySet<G>) {
    println!(
        "Shared public key: {}",
        hex::encode(info.shared_key().as_bytes())
    );
    for (i, key) in info.participant_keys().iter().enumerate() {
        println!(
            "Participant #{} key: {}",
            i + 1,
            hex::encode(key.as_bytes())
        );
    }
}

fn initialize_talliers<G: Group, R: CryptoRng + RngCore>(
    params: Params,
    rng: &mut R,
) -> (PublicKeySet<G>, Vec<ActiveParticipant<G>>) {
    let talliers: Vec<_> = (0..params.shares)
        .map(|i| StartingParticipant::<G>::new(params, i, rng))
        .collect();

    // Public tallier parameters together with proofs may be shared publicly
    // (e.g., on a blockchain).
    let mut partial_info = PartialPublicKeySet::<G>::new(params);
    for (i, tallier) in talliers.iter().enumerate() {
        let (poly, proof) = tallier.public_info();
        partial_info
            .add_participant(i, poly.to_vec(), proof)
            .unwrap();
    }
    let group = partial_info.complete().unwrap();

    println!("Threshold encryption params:");
    dump_group_info(&group);

    let mut talliers: Vec<_> = talliers
        .into_iter()
        .map(|tallier| tallier.finalize_key_set(&partial_info).unwrap())
        .collect();

    // Then, talliers exchange private shares with each other.
    // This is the only private / non-auditable part of the protocol, although it can be made
    // auditable as described in the `sharing` module docs.
    for i in 0..talliers.len() {
        for j in 0..talliers.len() {
            if j != i {
                let message = talliers[i].message(j);
                talliers[j].process_message(i, message).unwrap();
            }
        }
    }

    let talliers = talliers
        .into_iter()
        .map(|tallier| tallier.complete())
        .collect();
    (group, talliers)
}

fn vote<G: Group>() {
    let mut rng = thread_rng();

    // Before polling is started, talliers agree on the shared encryption key.
    let (key_set, talliers) = initialize_talliers::<G, _>(TALLIER_PARAMS, &mut rng);

    // During polling, voters submit votes together with the proof of correctness.
    let mut expected_totals = [0; OPTIONS_COUNT];
    let mut encrypted_totals = [Encryption::zero(); OPTIONS_COUNT];
    for i in 0..VOTES {
        let choice = rng.gen_range(0..OPTIONS_COUNT);
        println!("\nVoter #{} making choice #{}", i + 1, choice + 1);
        expected_totals[choice] += 1;
        let choice = EncryptedChoice::new(OPTIONS_COUNT, choice, key_set.shared_key(), &mut rng);

        println!(
            "Encrypted choice variants: {:#?}",
            choice
                .variants_unchecked()
                .iter()
                .map(|variant| hex::encode(&variant.to_bytes()[..]))
                .collect::<Vec<_>>()
        );
        println!(
            "Range proof: {}",
            hex::encode(&choice.range_proof().to_bytes())
        );
        println!(
            "Sum proof: {}",
            hex::encode(&choice.sum_proof().to_bytes()[..])
        );

        for (i, variant) in choice
            .verify(key_set.shared_key())
            .unwrap()
            .iter()
            .enumerate()
        {
            encrypted_totals[i] += *variant;
        }
    }

    println!(
        "\nCumulative choice variants: {:#?}",
        encrypted_totals
            .iter()
            .map(|variant| hex::encode(&variant.to_bytes()[..]))
            .collect::<Vec<_>>()
    );

    // After polling, talliers submit decryption shares together with proof of their correctness.
    let lookup_table = DiscreteLogLookupTable::<G>::new(0..=(VOTES as u64));
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
                println!(
                    "Share from tallier #{}: {:#?}",
                    j + 1,
                    HashMap::<_, _>::from_iter(vec![
                        ("decryption", hex::encode(&share)),
                        ("proof", hex::encode(&proof.to_bytes()[..])),
                    ])
                );

                let candidate_share = CandidateShare::from_bytes(&share).unwrap();
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
        None | Some("edwards") => vote::<Edwards>(),
        Some("ristretto") => vote::<Ristretto>(),
        Some("k256") => vote::<Generic<k256::Secp256k1>>(),
        Some(other) => panic!(
            "Unknown group: {}; use one of `edwards`, `ristretto` or `k256`",
            other
        ),
    }
}
