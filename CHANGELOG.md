# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
