//! High-level applications for proofs defined in this crate.

mod choice;
mod quadratic_voting;

pub use self::{
    choice::{
        ChoiceParams, ChoiceVerificationError, EncryptedChoice, ProveSum, MultiChoice,
        SingleChoice,
    },
    quadratic_voting::{QuadraticVotingBallot, QuadraticVotingError, QuadraticVotingParams},
};
