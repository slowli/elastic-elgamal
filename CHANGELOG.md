# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.3.0-beta.1 - 2023-02-03

### Added

- Make `curve25519-dalek` dependency optional and do not force the choice of its math backend.
  The dependency is still enabled by default.

- Allow for the `curve25519-dalek-ng` crypto backend as an alternative to `curve25519-dalek`.
  This may be beneficial for applications that use [`bulletproofs`] or other libraries 
  depending on `curve25519-dalek-ng`.

- Implement zero-knowledge proof of equivalence between an ElGamal ciphertext and
  a Pedersen commitment in the same group. This proof can be used to switch 
  from frameworks applicable to ElGamal ciphertexts, to ones applicable to Pedersen commitments 
  (e.g., Bulletproofs for range proofs).

- Implement distributed key generation (DKG) for threshold encryption based on Pedersen's scheme
  with commitments of participants' keys.

### Changed

- Update `hashbrown` dependency.

- Bump minimum supported Rust version to 1.62.

## 0.2.1 - 2022-07-04

### Fixed

- Fix `serde` feature. The `serde` dependency requires the `alloc` feature enabled,
  but this was not declared previously.

## 0.2.0 - 2022-06-13

### Added

- Generalize `EncryptedChoice` to handle multi-choice polling.

- Add quadratic voting with a zero-knowledge proof of correctness.

- Encapsulate ciphertext + original value in `CiphertextWithValue`. Allow using this type
  to create `RangeProof`s.

- Extend supported operations for `Ciphertext`s, e.g. negation. 

- Expose ciphertext components via getters.

### Changed

- Update `elliptic-curve` dependency.

- Return new error types (`VerificationError` and `ChoiceVerificationError`) on proof
  verification failure instead of signalling failure via `bool` or `Option` values.

- Move `EncryptedChoice` to a separate `app` module. Introduce `EncryptedChoiceParams`
  to encapsulate all parameters related to `EncryptedChoice` creation / verification.

- Generalize `DecryptionShare`s as `VerifiableDecryption`, which can be applied not only
  with threshold encryption with Shamir's secret sharing, but in other sharing schemes
  or independently.

- Make `hashbrown` an optional dependency, which is only necessary if the std library
  is not available.

### Fixed

- Remove unused `byteorder` and `smallvec` dependencies.

- Avoid extra allocations when constructing ring proofs, which could leak
  information via side channels.

### Security

- Fix zeroing `SecretKey` contents on drop.

## 0.1.0 - 2021-06-28

The initial release of `elastic-elgamal`.

[`bulletproofs`]: https://crates.io/crates/bulletproofs
