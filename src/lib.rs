//! [ElGamal encryption] and related cryptographic protocols with pluggable crypto backend.
//!
//! # ⚠ Warnings
//!
//! While the logic in this crate relies on standard cryptographic assumptions
//! (complexity of discrete log and computational / decisional Diffie–Hellman problems
//! in certain groups), it has not been independently verified for correctness or absence
//! of side-channel attack vectors. **Use at your own risk.**
//!
//! ElGamal encryption is not a good choice for general-purpose public-key encryption
//! since it is vulnerable to [chosen-ciphertext attacks][CCA]. For security,
//! decryption operations should be limited on the application level.
//!
//! # Overview
//!
//! - [`Ciphertext`] provides ElGamal encryption. This and other protocols use
//!   [`PublicKey`], [`SecretKey`] and [`Keypair`] to represent participants' keys.
//! - Besides basic encryption, `PublicKey` also provides zero-knowledge proofs of
//!   [zero encryption](PublicKey::encrypt_zero()) and of
//!   [Boolean value encryption](PublicKey::encrypt_bool()). These are useful in higher-level
//!   protocols, e.g., re-encryption.
//! - Zero-knowledge range proofs for ElGamal ciphertexts are provided via [`RangeProof`]s
//!   and a high-level [`PublicKey` method](PublicKey::encrypt_range()).
//! - Proof of equivalence between an ElGamal ciphertext and a Pedersen commitment
//!   is available as [`CommitmentEquivalenceProof`].
//! - [`sharing`] module exposes a threshold encryption scheme based
//!   on [Feldman's verifiable secret sharing][feldman-vss], including verifiable distributed
//!   decryption.
//! - [`dkg`] module implements distributed key generation using [Pedersen's scheme][pedersen-dkg]
//!   with hash commitments.
//! - [`app`] module provides higher-level protocols utilizing zero-knowledge proofs
//!   and ElGamal encryption, such as provable encryption of m-of-n choice and a simple version
//!   of [quadratic voting].
//!
//! # Backends
//!
//! [`group`] module exposes a generic framework for plugging a [`Group`]
//! implementation into crypto primitives. It also provides several implementations:
//!
//! - [`Ristretto`] and [`Curve25519Subgroup`] implementations based on Curve25519.
//! - [`Generic`] implementation allowing to plug in any elliptic curve group conforming to
//!   the traits specified by the [`elliptic-curve`] crate. For example,
//!   the secp256k1 curve can be used via the [`k256`] crate.
//!
//! # Crate features
//!
//! ## `std`
//!
//! *(on by default)*
//!
//! Enables support of types from `std`, such as the `Error` trait and the `HashMap` collection.
//!
//! ## `hashbrown`
//!
//! *(off by default)*
//!
//! Imports hash maps and sets from the [eponymous crate][`hashbrown`]
//! instead of using ones from the Rust std library. This feature is necessary
//! if the `std` feature is disabled.
//!
//! ## `curve25519-dalek`
//!
//! *(on by default)*
//!
//! Implements [`Group`] for two prime groups based on Curve25519 using the [`curve25519-dalek`]
//! crate: its prime subgroup, and the Ristretto transform of Curve25519 (aka ristretto255).
//!
//! ## `curve25519-dalek-ng`
//!
//! *(off by default)*
//!
//! Same in terms of functionality as `curve25519-dalek`, but uses the [`curve25519-dalek-ng`]
//! crate instead of [`curve25519-dalek`]. This may be beneficial for applications that use
//! [`bulletproofs`] or other libraries depending on `curve25519-dalek-ng`.
//!
//! The `curve25519-dalek-ng` crate does not compile unless some crypto backend is selected.
//! You may select the backend by specifying `curve25519-dalek-ng` as a direct dependency as follows:
//!
//! ```toml
//! [dependencies.elastic-elgamal]
//! version = "..."
//! default-features = false
//! features = ["std", "curve25519-dalek-ng"]
//!
//! [dependencies.curve25519-dalek-ng]
//! version = "4"
//! features = ["u64_backend"] # or other backend
//! ```
//!
//! This feature is mutually exclusive with `curve25519-dalek`.
//!
//! ## `serde`
//!
//! *(off by default)*
//!
//! Enables [`Serialize`](::serde::Serialize) / [`Deserialize`](::serde::Deserialize)
//! implementations for most types in the crate.
//! Group scalars, elements and wrapper key types are serialized to human-readable formats
//! (JSON, YAML, TOML, etc.) as strings that represent corresponding byte buffers using
//! base64-url encoding without padding. For binary formats, byte buffers are serialized directly.
//!
//! For complex types (e.g., participant states from the [`sharing`] module), self-consistency
//! checks are **not** performed on deserialization. That is, deserialization of such types
//! should only be performed from a trusted source or in the presence of additional integrity
//! checks.
//!
//! # Crate naming
//!
//! "Elastic" refers to pluggable backends, configurable params for threshold encryption,
//! and the construction of zero-knowledge [`RingProof`]s (a proof consists of
//! a variable number of rings, each of which consists of a variable number of admissible values).
//! `elastic_elgamal` is also one of [autogenerated Docker container names][docker-rng].
//!
//! [ElGamal encryption]: https://en.wikipedia.org/wiki/ElGamal_encryption
//! [CCA]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
//! [feldman-vss]: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
//! [pedersen-dkg]: https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf
//! [`Group`]: group::Group
//! [`Ristretto`]: group::Ristretto
//! [`Curve25519Subgroup`]: group::Curve25519Subgroup
//! [`curve25519-dalek`]: https://docs.rs/curve25519-dalek/
//! [`curve25519-dalek-ng`]: https://docs.rs/curve25519-dalek-ng/
//! [`bulletproofs`]: https://docs.rs/bulletproofs/
//! [`Generic`]: group::Generic
//! [`elliptic-curve`]: https://docs.rs/elliptic-curve/
//! [`k256`]: https://docs.rs/k256/
//! [`hashbrown`]: https://docs.rs/hashbrown/
//! [docker-rng]: https://github.com/moby/moby/blob/master/pkg/namesgenerator/names-generator.go
//! [quadratic voting]: https://en.wikipedia.org/wiki/Quadratic_voting

#![cfg_attr(not(feature = "std"), no_std)]
// Documentation settings.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/elastic-elgamal/0.3.0-beta.1")]
// Linter settings.
#![warn(missing_debug_implementations, missing_docs, bare_trait_objects)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::module_name_repetitions,
    clippy::doc_markdown
)]

pub mod app;
mod decryption;
pub mod dkg;
mod encryption;
pub mod group;
mod keys;
mod proofs;
#[cfg(feature = "serde")]
mod serde;
pub mod sharing;

// Polyfill for `alloc` types.
mod alloc {
    #[cfg(not(feature = "std"))]
    extern crate alloc as std;

    pub use std::{borrow::Cow, string::ToString, vec, vec::Vec};

    #[cfg(all(not(feature = "std"), not(feature = "hashbrown")))]
    compile_error!(
        "One of `std` or `hashbrown` features must be enabled in order \
         to get a hash map implementation"
    );

    #[cfg(feature = "hashbrown")]
    pub use hashbrown::HashMap;
    #[cfg(not(feature = "hashbrown"))]
    pub use std::collections::HashMap;
}

// Polyfill for Curve25519 types.
#[cfg(any(feature = "curve25519-dalek-ng", feature = "curve25519-dalek"))]
mod curve25519 {
    #[cfg(all(feature = "curve25519-dalek-ng", feature = "curve25519-dalek"))]
    compile_error!("`curve25519-dalek-ng` and `curve25519-dalek` features are mutually exclusive");

    #[cfg(feature = "curve25519-dalek")]
    pub use curve25519_dalek::*;
    #[cfg(feature = "curve25519-dalek-ng")]
    pub use curve25519_dalek_ng::*;
}

mod sealed {
    pub trait Sealed {}
}

pub use crate::{
    decryption::{CandidateDecryption, VerifiableDecryption},
    encryption::{Ciphertext, CiphertextWithValue, DiscreteLogTable},
    keys::{Keypair, PublicKey, PublicKeyConversionError, SecretKey},
    proofs::{
        CommitmentEquivalenceProof, LogEqualityProof, PreparedRange, ProofOfPossession,
        RangeDecomposition, RangeProof, RingProof, RingProofBuilder, SumOfSquaresProof,
        VerificationError,
    },
};

#[cfg(doctest)]
doc_comment::doctest!("../README.md");
