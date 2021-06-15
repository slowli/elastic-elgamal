//! [ElGamal encryption] on elliptic curves with pluggable crypto backends.
//!
//! [ElGamal encryption]: https://en.wikipedia.org/wiki/ElGamal_encryption

// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::doc_markdown
)]

mod encryption;
mod group;
mod keys;
mod proofs;
pub mod sharing;

pub use crate::{
    encryption::{DiscreteLogLookupTable, EncryptedChoice, Encryption},
    group::{Edwards, Generic, Group, PointOps, Ristretto, ScalarOps},
    keys::{Keypair, PublicKey, SecretKey},
    proofs::{LogEqualityProof, ProofOfPossession, RingProof, RingProofBuilder},
};
