//! Simple universally verifiable crypto voting protocol using threshold ElGamal encryption.
//! Voter authentication is outside the protocol scope.
//!
//! See [*Simple Verifiable Elections*][elections] by Benaloh for an overview of a similar
//! voting protocol.
//!
//! [elections]: https://static.usenix.org/event/evt06/tech/full_papers/benaloh/benaloh.pdf

use clap::{Parser, ValueEnum};
use rand::{
    Rng,
    seq::{IndexedMutRandom, IteratorRandom},
};
use rand_core::{CryptoRng, RngCore};

use std::{error::Error as StdError, str::FromStr};

use elastic_elgamal::{
    CandidateDecryption, Ciphertext, DiscreteLogTable,
    app::{ChoiceParams, EncryptedChoice, QuadraticVotingBallot, QuadraticVotingParams},
    group::{Generic, Group, Ristretto},
    sharing::{ActiveParticipant, Dealer, Params, PublicKeySet},
};

type K256 = Generic<k256::Secp256k1>;

/// Simple universally verifiable crypto voting protocol using threshold ElGamal encryption.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of options in the poll.
    #[arg(name = "options", long, default_value = "3")]
    options_count: usize,
    /// Number of votes to be cast.
    #[arg(name = "votes", long, default_value = "30")]
    votes_count: usize,
    /// Tallier configuration specified as a `$threshold/$number`.
    #[arg(
        name = "talliers",
        long,
        short,
        default_value = "3/5",
        value_parser = Args::parse_talliers
    )]
    talliers: Params,
    /// Use quadratic voting instead of single-choice polling?
    #[arg(name = "qv", long, short = 'Q')]
    quadratic_voting: bool,
    /// Amount of credits in quadratic voting.
    #[arg(name = "credits", long, short = 'C', default_value = "10")]
    credit_amount: u64,
    /// EC group to use.
    #[arg(value_enum, default_value = "ristretto")]
    group: GroupName,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum GroupName {
    Ristretto,
    K256,
}

impl FromStr for GroupName {
    type Err = Box<dyn StdError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ristretto" => Ok(Self::Ristretto),
            "k256" => Ok(Self::K256),
            _ => Err("unexpected group name".into()),
        }
    }
}

impl Args {
    fn parse_talliers(s: &str) -> Result<Params, Box<dyn StdError + Send + Sync>> {
        let (threshold, count) = s
            .split_once('/')
            .ok_or("talliers specification must contain `/` char")?;
        Ok(Params {
            threshold: threshold.parse()?,
            shares: count.parse()?,
        })
    }

    fn run(self) {
        println!("Running with args {self:?}");
        match self.group {
            GroupName::Ristretto => {
                if self.quadratic_voting {
                    self.quadratic_vote::<Ristretto>();
                } else {
                    self.vote::<Ristretto>();
                }
            }
            GroupName::K256 => {
                if self.quadratic_voting {
                    self.quadratic_vote::<K256>();
                } else {
                    self.vote::<K256>();
                }
            }
        }
    }

    fn initialize_talliers<G: Group, R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
    ) -> (PublicKeySet<G>, Vec<ActiveParticipant<G>>) {
        let dealer = Dealer::<G>::new(self.talliers, rng);
        let (public_poly, public_poly_proof) = dealer.public_info();
        let key_set = PublicKeySet::new(self.talliers, public_poly, public_poly_proof).unwrap();

        let talliers: Vec<_> = (0..self.talliers.shares)
            .map(|i| {
                ActiveParticipant::new(key_set.clone(), i, dealer.secret_share_for_participant(i))
                    .unwrap()
            })
            .collect();
        (key_set, talliers)
    }

    fn tally<G: Group>(
        talliers: &[ActiveParticipant<G>],
        key_set: &PublicKeySet<G>,
        encrypted_totals: &[Ciphertext<G>],
        expected_totals: &[u64],
        max_votes: u64,
    ) {
        println!(
            "\nCumulative choices: {}",
            serde_json::to_string_pretty(encrypted_totals).unwrap()
        );

        // After polling, talliers submit decryption shares together with a proof of their correctness.
        let mut rng = rand::rng();
        let lookup_table = DiscreteLogTable::<G>::new(0..=max_votes);
        for (i, (&option_totals, &expected)) in
            encrypted_totals.iter().zip(expected_totals).enumerate()
        {
            println!("\nDecrypting cumulative total for option #{}", i + 1);

            let decryption_shares: Vec<_> = talliers
                .iter()
                .enumerate()
                .choose_multiple(&mut rng, key_set.params().threshold)
                .into_iter()
                .map(|(j, tallier)| (j, tallier.decrypt_share(option_totals, &mut rng)))
                .map(|(j, (share, proof))| {
                    let share = share.to_bytes(); // Emulate transfer via network
                    let candidate_share = CandidateDecryption::from_bytes(&share).unwrap();
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

            let combined_decryption = key_set.params().combine_shares(decryption_shares).unwrap();
            let option_tally = combined_decryption
                .decrypt(option_totals, &lookup_table)
                .unwrap();
            println!("Variant #{} decrypted tally: {option_tally}", i + 1);
            assert_eq!(option_tally, expected);
            println!("The decrypted number is as expected!");
        }
    }

    fn vote<G: Group>(&self) {
        let mut rng = rand::rng();

        // Before polling is started, talliers agree on the shared encryption key.
        let (key_set, talliers) = self.initialize_talliers::<G, _>(&mut rng);
        let choice_params = ChoiceParams::single(key_set.shared_key().clone(), self.options_count);

        // During polling, voters submit votes together with the proof of correctness.
        let mut expected_totals = vec![0; self.options_count];
        let mut encrypted_totals = vec![Ciphertext::zero(); self.options_count];
        for i in 0..self.votes_count {
            let choice = rng.random_range(0..self.options_count);
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

        Self::tally(
            &talliers,
            &key_set,
            &encrypted_totals,
            &expected_totals,
            self.votes_count as u64,
        );
    }

    fn credit(votes: &[u64]) -> u64 {
        votes.iter().map(|&x| x * x).sum::<u64>()
    }

    fn quadratic_vote<G: Group>(&self) {
        let mut rng = rand::rng();

        // Before polling is started, talliers agree on the shared encryption key.
        let (key_set, talliers) = self.initialize_talliers::<G, _>(&mut rng);
        let vote_params = QuadraticVotingParams::new(
            key_set.shared_key().clone(),
            self.options_count,
            self.credit_amount,
        );

        // During polling, voters submit votes together with the proof of correctness.
        let mut expected_totals = vec![0; self.options_count];
        let mut encrypted_totals = vec![Ciphertext::zero(); self.options_count];
        for i in 0..self.votes_count {
            let mut votes = vec![0_u64; self.options_count];
            while rng.random_bool(0.8) {
                let mut new_votes = votes.clone();
                *new_votes.choose_mut(&mut rng).unwrap() += 1;
                if Self::credit(&new_votes) > self.credit_amount {
                    break;
                } else {
                    votes = new_votes;
                }
            }

            println!("\nVoter #{} casting votes {votes:?}", i + 1);
            for (exp_total, &vote) in expected_totals.iter_mut().zip(&votes) {
                *exp_total += vote;
            }
            let encrypted = QuadraticVotingBallot::new(&vote_params, &votes, &mut rng);
            println!(
                "Encrypted ballot: {}",
                serde_json::to_string_pretty(&encrypted).unwrap()
            );

            let votes = encrypted.verify(&vote_params).unwrap();
            for (total, vote) in encrypted_totals.iter_mut().zip(votes) {
                *total += vote;
            }
        }

        let max_votes = self.votes_count as u64 * vote_params.max_votes();
        Self::tally(
            &talliers,
            &key_set,
            &encrypted_totals,
            &expected_totals,
            max_votes,
        );
    }
}

fn main() {
    let args = Args::parse();
    args.run();
}
