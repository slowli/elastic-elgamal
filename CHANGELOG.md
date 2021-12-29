# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Generalize `EncryptedChoice` to handle multi-choice polling.

- Add quadratic voting with a zero-knowledge proof of correctness.

- Encapsulate ciphertext + original value in `CiphertextWithValue`. Allow using this type
  to create `RangeProof`s.

- Extend supported operations for `Ciphertext`s, e.g. negation. 

### Changed

- Update `elliptic-curve` dependency.

- Return new error types (`VerificationError` and `ChoiceVerificationError`) on proof
  verification failure instead of signalling failure via `bool` or `Option` values.

- Move `EncryptedChoice` to a separate `app` module. Introduce `EncryptedChoiceParams`
  to encapsulate all parameters related to `EncryptedChoice` creation / verification.

### Fixed

- Remove unused `byteorder` and `smallvec` dependencies.

- Avoid extra allocations when constructing ring proofs, which could leak
  information via side channels.

### Security

- Fix zeroing `SecretKey` contents on drop.

## 0.1.0 - 2021-06-28

The initial release of `elastic-elgamal`.
