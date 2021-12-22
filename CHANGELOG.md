# Changelog

All notable changes to this project will be documented in this file.
The project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Update `elliptic-curve` dependency.

- Return new error types (`VerificationError` and `ChoiceVerificationError`) on proof
  verification failure instead of signalling failure via `bool` or `Option` values.

### Fixed

- Remove unused `byteorder` and `smallvec` dependencies.

- Avoid extra allocations when constructing ring proofs, which could leak
  information via side channels.

## 0.1.0 - 2021-06-28

The initial release of `elastic-elgamal`.
