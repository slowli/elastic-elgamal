# ElGamal Encryption and Related Zero-Knowledge Proofs

[![Build Status](https://github.com/slowli/elastic-elgamal/workflows/CI/badge.svg?branch=main)](https://github.com/slowli/elastic-elgamal/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](https://github.com/slowli/elastic-elgamal#license)
![rust 1.65+ required](https://img.shields.io/badge/rust-1.65+-blue.svg?label=Required%20Rust)
![no_std supported](https://img.shields.io/badge/no__std-tested-green.svg)

**Documentation:** [![Docs.rs](https://docs.rs/elastic-elgamal/badge.svg)](https://docs.rs/elastic-elgamal/)
[![crate docs (main)](https://img.shields.io/badge/main-yellow.svg?label=docs)](https://slowli.github.io/elastic-elgamal/elastic_elgamal/)

Implementation of [ElGamal encryption] and related zero-knowledge proofs
with pluggable crypto backend.

The following protocols and high-level applications are included:

- Additively homomorphic ElGamal encryption
- Zero-knowledge proofs of zero encryption and Boolean value encryption
- Zero-knowledge range proofs for ElGamal ciphertexts
- Zero-knowledge proof of equivalence between an ElGamal ciphertext and
  a Pedersen commitment in the same group
- Additively homomorphic m-of-n choice encryption with a zero-knowledge
  proof of correctness
- Additively homomorphic [quadratic voting] with a zero-knowledge
  proof of correctness
- Threshold ElGamal encryption via [Feldman's verifiable secret sharing][feldman-vss],
  including verifiable distributed decryption.
- As an alternative method to generate a shared key for threshold encryption, 
  there is [Pedersen's distributed key generation][pedersen-dkg]
  with prior key commitments by participants. (Beware that this method can theoretically
  lead to skewed public key distribution as shown by [Gennaro et al.])

## ⚠ Warnings

While the logic in this crate relies on standard cryptographic assumptions
(complexity of [decisional Diffie–Hellman][DDH], [computational Diffie–Hellman][CDH]
and [discrete log][DLP] problems in certain groups),
it has not been independently verified for correctness or absence of side-channel attack
vectors. **Use at your own risk.**

ElGamal encryption is not a good choice for general-purpose public-key encryption
since it is vulnerable to [chosen-ciphertext attacks][CCA]. For security,
decryption operations should be limited on the application level.

## Usage

Add this to your `Crate.toml`:

```toml
[dependencies]
elastic-elgamal = "0.3.1"
```

### Single-choice polling

```rust
use elastic_elgamal::app::{ChoiceParams, EncryptedChoice};
use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Keypair};
use rand::thread_rng;

let mut rng = thread_rng();
// Generate a keypair for encrypting ballots. In more realistic setup,
// this keypair would be distributed among multiple talliers.
let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
let choice_params = ChoiceParams::single(pk, 5);
// ^ single-choice polling with 5 options encrypted for `pk`

let choice = 2; // voter's choice
let enc = EncryptedChoice::single(&choice_params, choice, &mut rng);
let choices = enc.verify(&choice_params).unwrap();
// ^ 5 Boolean value ciphertexts that can be homomorphically added
// across ballots

// Decrypt a separate ballot for demo purposes.
let lookup_table = DiscreteLogTable::new(0..=1);
for (idx, &v) in choices.iter().enumerate() {
    assert_eq!(
        sk.decrypt(v, &lookup_table),
        Some((idx == choice) as u64)
    );
}
```

### Quadratic voting

```rust
use elastic_elgamal::app::{QuadraticVotingParams, QuadraticVotingBallot};
use elastic_elgamal::{group::Ristretto, Keypair, DiscreteLogTable};
use rand::thread_rng;

let mut rng = thread_rng();
let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
let params = QuadraticVotingParams::new(pk, 5, 20);
// ^ 5 options, 20 credits (= 4 max votes per option)
assert_eq!(params.max_votes(), 4);

let votes = [4, 0, 0, 1, 1]; // voter's votes
let ballot = QuadraticVotingBallot::new(&params, &votes, &mut rng);
let encrypted = ballot.verify(&params).unwrap();
// ^ 5 vote ciphertexts that can be homomorphically added across ballots

// Decrypt a separate ballot for demo purposes.
let lookup = DiscreteLogTable::new(0..=params.max_votes());
let decrypted: Vec<_> = encrypted
    .map(|vote| sk.decrypt(vote, &lookup).unwrap())
    .collect();
assert_eq!(decrypted, votes);
```

See the crate docs for more examples of usage.

## Naming

"Elastic" refers to pluggable backends, encryption with a key shared
among a variable number of participants, and the construction of zero-knowledge ring proofs
(a proof consists of a variable number of rings, each of which consists of a variable number
of admissible values).
`elastic_elgamal` is also one of [autogenerated Docker container names][docker-rng].

## Alternatives and similar tools

There are [several Rust crates][crates-elgamal] implementing ElGamal encryption
on elliptic curves, such as [`elgamal_ristretto`] (this one features zero-knowledge proofs
of correct decryption and knowledge of the secret key).

As mentioned in the *Warnings* section, ElGamal is not a good choice for general-purpose
public-key encryption. RSA or [ECIES] schemes (such as the [`box`] primitive from NaCl / libsodium)
can be used instead.

## See also

- [elasticpoll.app](https://elasticpoll.app/) – an [open-source][elasticpoll-src] web app
  that uses this library to implement universally verifiable voting. (Like this library,
  the website is not audited and should not be used for serious votes.)

## Contributing

All contributions are welcome! See [the contributing guide](CONTRIBUTING.md) to help
you get involved.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE)
or [MIT license](LICENSE-MIT) at your option.

<small>Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `elastic-elgamal` by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.</small>

[ElGamal encryption]: https://en.wikipedia.org/wiki/ElGamal_encryption
[quadratic voting]: https://en.wikipedia.org/wiki/Quadratic_voting
[feldman-vss]: https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf
[pedersen-dkg]: https://link.springer.com/content/pdf/10.1007/3-540-46416-6_47.pdf
[Gennaro et al.]: https://link.springer.com/content/pdf/10.1007/3-540-48910-X_21.pdf
[DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
[CDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
[DLP]: https://en.wikipedia.org/wiki/Discrete_logarithm
[CCA]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
[docker-rng]: https://github.com/moby/moby/blob/master/pkg/namesgenerator/names-generator.go
[crates-elgamal]: https://crates.io/search?q=elgamal
[`elgamal_ristretto`]: https://docs.rs/elgamal_ristretto/0.2.3/elgamal_ristretto/index.html
[ECIES]: https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
[`box`]: https://doc.libsodium.org/public-key_cryptography/sealed_boxes
[elasticpoll-src]: https://github.com/slowli/elasticpoll.app
