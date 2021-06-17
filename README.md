# ElGamal Encryption and Zero-Knowledge Proofs

Implementation of [ElGamal encryption] and related cryptographic protocols
with pluggable crypto backend.

The following protocols are included:

- Additively homomorphic ElGamal encryption
- Zero-knowledge proofs of zero encryption and Boolean value encryption
- Additively homomorphic 1-of-n choice encryption and the corresponding
  zero-knowledge proof of correctness
- Shared ElGamal encryption, including distributed key generation
  and provable distributed decryption.

## ⚠ Warnings

While the logic in this crate relies on standard cryptographic assumptions
(complexity of [decisional Diffie–Hellman][DDH], [computational Diffie–Hellman][coDH]
and [discrete log][DLP] problems in certain groups),
it has not been independently verified for correctness or absence of side-channel attack
vectors. **Use at your own risk.**

ElGamal encryption is not a good choice for general-purpose public-key encryption
since it is vulnerable to [chosen-ciphertext attacks][CCA]. For security,
decryption operations should be limited on the application level.

## Usage

See the crate docs for the examples of usage.

[ElGamal encryption]: https://en.wikipedia.org/wiki/ElGamal_encryption
[DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
[coDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
[dlp]: https://en.wikipedia.org/wiki/Discrete_logarithm
[CCA]: https://en.wikipedia.org/wiki/Chosen-ciphertext_attack
