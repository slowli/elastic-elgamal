//! High-level applications for proofs defined in this crate.
//!
//! For now, the applications are:
//!
//! - [`EncryptedChoice`]. Single-choice or multi-choice selection from a predefined
//!   list of options, with summable selection ciphertexts.
//! - [`QuadraticVotingBallot`]. [Quadratic voting] on a predefined list of options,
//!   with summable selection ciphertexts.
//!
//! [Quadratic voting]: https://en.wikipedia.org/wiki/Quadratic_voting

mod choice;
mod quadratic_voting;

pub use self::{
    choice::{
        ChoiceParams, ChoiceVerificationError, EncryptedChoice, MultiChoice, ProveSum, SingleChoice,
    },
    quadratic_voting::{QuadraticVotingBallot, QuadraticVotingError, QuadraticVotingParams},
};
