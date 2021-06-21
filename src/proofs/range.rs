//! Range proofs for ElGamal ciphertexts.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use std::{collections::HashMap, fmt};

use crate::{
    group::Group,
    proofs::{RingProof, RingProofBuilder, TranscriptForGroup},
    Ciphertext, PublicKey,
};

#[derive(Debug, Clone, Copy, PartialEq)]
struct RingSpec {
    size: u64,
    step: u64,
}

/// Decomposition of an integer range `0..n`.
// TODO: non-recursive form? (0..3 + 3 * 0..5 + 15 * 0..6)
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RangeDecomposition {
    /// Just a range `0..n`, where `n` is the enclosed value.
    Just(u64),
    /// Additive decomposition.
    Add {
        /// Left-hand side of the decomposition.
        lhs: Box<RangeDecomposition>,
        /// Right-hand side of the decomposition.
        rhs: Box<RangeDecomposition>,
    },
    /// Multiplicative decomposition.
    Mul {
        /// Left-hand side of the decomposition.
        lhs: Box<RangeDecomposition>,
        /// Right-hand side of the decomposition.
        rhs: Box<RangeDecomposition>,
    },
}

impl fmt::Display for RangeDecomposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Just(bound) => write!(formatter, "0..{}", bound),

            Self::Add { lhs, rhs } => write!(formatter, "{} + {}", lhs, rhs),

            Self::Mul { lhs, rhs } => {
                if matches!(lhs.as_ref(), Self::Add { .. }) {
                    write!(formatter, "({})", lhs)?;
                } else {
                    fmt::Display::fmt(lhs, formatter)?;
                }

                formatter.write_str(" * ")?;

                if matches!(rhs.as_ref(), Self::Add { .. }) {
                    write!(formatter, "({})", rhs)?;
                } else {
                    fmt::Display::fmt(rhs, formatter)?;
                }
                Ok(())
            }
        }
    }
}

/// `RangeDecomposition` together with optimized parameters.
#[derive(Debug, Clone)]
struct OptimalDecomposition {
    decomposition: RangeDecomposition,
    optimal_len: u64,
    ring_count: u64,
    skipped_add_decomposition: bool,
}

impl OptimalDecomposition {
    fn maybe_replace_by_product(&mut self, x_opt: Self, y_opt: Self) {
        let new_len = x_opt.optimal_len + y_opt.optimal_len;
        let new_ring_count = x_opt.ring_count + y_opt.ring_count;
        if new_len < self.optimal_len
            || (new_len == self.optimal_len && new_ring_count < self.ring_count)
        {
            self.optimal_len = x_opt.optimal_len + y_opt.optimal_len;
            self.ring_count = new_ring_count;
            self.decomposition = RangeDecomposition::Mul {
                lhs: Box::new(x_opt.decomposition),
                rhs: Box::new(y_opt.decomposition),
            };
        }
    }

    fn maybe_replace_by_sum(&mut self, x_opt: Self, y_opt: Self) {
        let new_len = x_opt.optimal_len + y_opt.optimal_len;
        let new_ring_count = x_opt.ring_count + y_opt.ring_count;
        if new_len < self.optimal_len
            || (new_len == self.optimal_len && new_ring_count < self.ring_count)
        {
            self.optimal_len = x_opt.optimal_len + y_opt.optimal_len;
            self.ring_count = new_ring_count;
            self.decomposition = RangeDecomposition::Add {
                lhs: Box::new(x_opt.decomposition),
                rhs: Box::new(y_opt.decomposition),
            };
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
impl RangeDecomposition {
    /// Creates an optimal decomposition of the range with the given `upper_bound` in terms
    /// of space of the range proof.
    ///
    /// # Panics
    ///
    /// Panics if `upper_bound` is less than 2.
    pub fn optimal(upper_bound: u64) -> Self {
        assert!(upper_bound >= 2, "`upper_bound` must be greater than 1");

        let mut optimal_values = HashMap::new();
        Self::optimize(upper_bound, false, &mut optimal_values).decomposition
    }

    /// Returns the capacity of this decomposition.
    fn walk(
        &self,
        multiplier: u64,
        ring_specs: &mut Vec<RingSpec>,
        lhs_capacities: &mut Vec<u64>,
    ) -> u64 {
        match self {
            Self::Just(bound) => {
                ring_specs.push(RingSpec {
                    size: *bound,
                    step: multiplier,
                });
                *bound
            }
            Self::Mul { lhs, rhs } => {
                let lhs_capacity = lhs.walk(multiplier, ring_specs, lhs_capacities);
                lhs_capacities.push(lhs_capacity);
                lhs_capacity * rhs.walk(multiplier * lhs_capacity, ring_specs, lhs_capacities)
            }
            Self::Add { lhs, rhs } => {
                let lhs_capacity = lhs.walk(multiplier, ring_specs, lhs_capacities);
                lhs_capacities.push(lhs_capacity);
                lhs_capacity + rhs.walk(multiplier, ring_specs, lhs_capacities) - 1
            }
        }
    }

    fn decompose(&self, value_indexes: &mut Vec<usize>, secret_value: u64, lhs_capacities: &[u64]) {
        match self {
            Self::Just(_) => value_indexes.push(secret_value as usize),
            Self::Mul { lhs, rhs } => {
                let lhs_capacity = lhs_capacities[0];
                lhs.decompose(
                    value_indexes,
                    secret_value % lhs_capacity,
                    &lhs_capacities[1..],
                );
                rhs.decompose(
                    value_indexes,
                    secret_value / lhs_capacity,
                    &lhs_capacities[1..],
                );
            }
            Self::Add { lhs, rhs } => {
                let lhs_capacity = lhs_capacities[0];
                // TODO: is `saturating_sub` constant-time?
                let to_rhs = secret_value.saturating_sub(lhs_capacity - 1);
                lhs.decompose(value_indexes, secret_value - to_rhs, &lhs_capacities[1..]);
                rhs.decompose(value_indexes, to_rhs, &lhs_capacities[1..]);
            }
        }
    }

    fn optimize(
        upper_bound: u64,
        skip_add_decomposition: bool,
        optimal_values: &mut HashMap<u64, OptimalDecomposition>,
    ) -> OptimalDecomposition {
        let (mut opt, skip_mul) = if let Some(opt) = optimal_values.get(&upper_bound).cloned() {
            if skip_add_decomposition || !opt.skipped_add_decomposition {
                // We know that `opt` is fully optimized.
                return opt;
            }
            // Here, `opt` is partially optimized (using mul decomposition, but not
            // add one).
            (opt, true)
        } else {
            // Single ring of `upper_bound` elements.
            let opt = OptimalDecomposition {
                optimal_len: upper_bound + 2,
                ring_count: 1,
                decomposition: RangeDecomposition::Just(upper_bound),
                skipped_add_decomposition: skip_add_decomposition,
            };
            (opt, false)
        };

        if !skip_mul {
            // Multiplicative decomposition.
            for x in Self::divisors(upper_bound) {
                let y = upper_bound / x;

                let x_estimate = Self::lower_len_estimate(x);
                let y_estimate = Self::lower_len_estimate(y);
                if x_estimate + y_estimate > opt.optimal_len {
                    continue;
                }

                let x_opt = Self::optimize(x, false, optimal_values);
                if x_opt.optimal_len + y_estimate > opt.optimal_len {
                    continue;
                }
                let y_opt = Self::optimize(y, false, optimal_values);

                opt.maybe_replace_by_product(x_opt, y_opt);
            }
        }

        // Additive decomposition.
        if !skip_add_decomposition {
            opt.skipped_add_decomposition = false;

            for x in 2..=(upper_bound / 2) {
                let y = upper_bound + 1 - x;

                let x_estimate = Self::lower_len_estimate(x);
                let y_estimate = Self::lower_len_estimate(y);
                if x_estimate + y_estimate >= opt.optimal_len {
                    // Here, lower boundaries are monotonically increasing w.r.t. `x`,
                    // so, once we hit the current `optimal_len` as the theoretical lower boundary,
                    // we're done.
                    break;
                }

                let x_opt = Self::optimize(x, true, optimal_values);
                if x_opt.optimal_len + y_estimate >= opt.optimal_len {
                    continue;
                }
                let y_opt = Self::optimize(y, true, optimal_values);

                opt.maybe_replace_by_sum(x_opt, y_opt);
            }
        }

        debug_assert!(
            opt.optimal_len >= Self::lower_len_estimate(upper_bound),
            "Lower len estimate {est} is invalid for {bound}: {opt:?}",
            est = Self::lower_len_estimate(upper_bound),
            bound = upper_bound,
            opt = opt
        );
        optimal_values.insert(upper_bound, opt.clone());
        opt
    }

    fn lower_len_estimate(upper_bound: u64) -> u64 {
        ((upper_bound as f64).log2() * 3.0).ceil() as u64
    }

    fn divisors(value: u64) -> impl Iterator<Item = u64> {
        let upper_bound = (value as f64).sqrt().floor() as u64;
        (2..=upper_bound).filter(move |&x| value % x == 0)
    }
}

#[derive(Debug, Clone)]
pub struct PreparedRangeDecomposition<G: Group> {
    inner: RangeDecomposition,
    capacity: u64,
    lhs_capacities: Vec<u64>,
    admissible_values: Vec<Vec<G::Element>>,
}

impl<G: Group> From<RangeDecomposition> for PreparedRangeDecomposition<G> {
    fn from(decomposition: RangeDecomposition) -> Self {
        Self::new(decomposition)
    }
}

impl<G: Group> PreparedRangeDecomposition<G> {
    fn new(inner: RangeDecomposition) -> Self {
        let mut ring_specs = vec![];
        let mut lhs_capacities = vec![];
        let capacity = inner.walk(1, &mut ring_specs, &mut lhs_capacities);

        let admissible_values = Vec::with_capacity(ring_specs.len());
        let admissible_values = ring_specs
            .into_iter()
            .fold(admissible_values, |mut acc, spec| {
                let ring_values: Vec<_> = (0..spec.size)
                    .map(|i| G::vartime_mul_generator(&(i * spec.step).into()))
                    .collect();
                acc.push(ring_values);
                acc
            });

        Self {
            inner,
            capacity,
            lhs_capacities,
            admissible_values,
        }
    }

    /// Decomposes the provided `secret_value` into value indexes in constituent rings.
    fn decompose(&self, secret_value: u64) -> Zeroizing<Vec<usize>> {
        assert!(
            secret_value < self.capacity,
            "Secret value must be in range 0..{}",
            self.capacity
        );
        // We immediately allocate the necessary capacity for `decomposition`.
        let mut decomposition = Zeroizing::new(Vec::with_capacity(self.admissible_values.len()));
        self.inner
            .decompose(&mut decomposition, secret_value, &self.lhs_capacities);
        decomposition
    }
}

/// Zero-knowledge proof that an ElGamal ciphertext encrypts a value into a certain range `0..n`.
#[derive(Debug, Clone)]
pub struct RangeProof<G: Group> {
    partial_ciphertexts: Vec<Ciphertext<G>>,
    inner: RingProof<G>,
}

impl<G: Group> RangeProof<G> {
    /// Creates a new proof. This is a lower-level operation.
    ///
    /// # Panics
    ///
    /// Panics if `value` is outside the range specified by `decomposition`.
    pub fn new<R: RngCore + CryptoRng>(
        receiver: &PublicKey<G>,
        decomposition: &PreparedRangeDecomposition<G>,
        value: u64,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> (Ciphertext<G>, Self) {
        let value_indexes = decomposition.decompose(value);
        debug_assert_eq!(value_indexes.len(), decomposition.admissible_values.len());
        transcript.start_proof(b"encryption_range_proof");
        transcript.append_message(b"range", decomposition.inner.to_string().as_bytes());

        let mut proof_builder = RingProofBuilder::new(
            receiver,
            decomposition.admissible_values.len(),
            transcript,
            rng,
        );
        let partial_ciphertexts = value_indexes
            .iter()
            .zip(&decomposition.admissible_values)
            .map(|(value_index, admissible_values)| {
                proof_builder
                    .add_value(admissible_values, *value_index)
                    .inner
            })
            .collect();

        let mut proof = Self {
            partial_ciphertexts,
            inner: proof_builder.build(),
        };
        let ciphertext = proof.extract_cumulative_ciphertext();
        (ciphertext, proof)
    }

    fn extract_cumulative_ciphertext(&mut self) -> Ciphertext<G> {
        let ciphertext_sum = self
            .partial_ciphertexts
            .iter()
            .fold(Ciphertext::zero(), |acc, ciphertext| acc + *ciphertext);
        self.partial_ciphertexts.pop();
        ciphertext_sum
    }

    /// Verifies this proof.
    pub fn verify(
        &self,
        receiver: &PublicKey<G>,
        decomposition: &PreparedRangeDecomposition<G>,
        ciphertext: Ciphertext<G>,
        transcript: &mut Transcript,
    ) -> bool {
        // Check decomposition / proof consistency.
        if decomposition.admissible_values.len() != self.partial_ciphertexts.len() + 1 {
            return false;
        }

        transcript.start_proof(b"encryption_range_proof");
        transcript.append_message(b"range", decomposition.inner.to_string().as_bytes());

        let ciphertext_sum = self
            .partial_ciphertexts
            .iter()
            .fold(Ciphertext::zero(), |acc, ciphertext| acc + *ciphertext);
        let ciphertexts = self
            .partial_ciphertexts
            .iter()
            .copied()
            .chain(Some(ciphertext - ciphertext_sum));

        let admissible_values = decomposition.admissible_values.iter().map(Vec::as_slice);
        self.inner
            .verify(receiver, admissible_values, ciphertexts, transcript)
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::{
        group::{ElementOps, Ristretto},
        Keypair,
    };

    #[test]
    fn getting_divisors() {
        let divisors: Vec<_> = RangeDecomposition::divisors(10).collect();
        assert_eq!(divisors, [2]);
        let divisors: Vec<_> = RangeDecomposition::divisors(100).collect();
        assert_eq!(divisors, [2, 4, 5, 10]);
    }

    #[test]
    fn optimal_value_small() {
        let value = RangeDecomposition::optimal(5);
        assert_eq!(value, RangeDecomposition::Just(5));

        let value = RangeDecomposition::optimal(16);
        assert_eq!(
            value,
            RangeDecomposition::Mul {
                lhs: Box::new(RangeDecomposition::Just(4)),
                rhs: Box::new(RangeDecomposition::Just(4)),
            }
        );

        let value = RangeDecomposition::optimal(60);
        assert_eq!(
            value,
            RangeDecomposition::Mul {
                lhs: Box::new(RangeDecomposition::Just(3)),
                rhs: Box::new(RangeDecomposition::Mul {
                    lhs: Box::new(RangeDecomposition::Just(4)),
                    rhs: Box::new(RangeDecomposition::Just(5)),
                }),
            }
        );

        let value = RangeDecomposition::optimal(1_000);
        assert_eq!(value.to_string(), "0..5 * 0..5 * 0..5 * 0..8");
    }

    #[test]
    fn large_optimal_values() {
        let value = RangeDecomposition::optimal(12_345);
        assert_eq!(
            value.to_string(),
            "0..3 * 0..5 * (0..2 + 0..6 * (0..3 + 0..3 * 0..3 * 0..3 * 0..5))"
        );

        let value = RangeDecomposition::optimal(777_777);
        assert_eq!(
            value.to_string(),
            "0..3 * 0..7 * 0..7 * 0..11 * (0..2 + 0..4 * 0..4 * 0..5 * 0..6)"
        );

        let value = RangeDecomposition::optimal(12_345_678);
        assert_eq!(
            value.to_string(),
            "0..6 * (0..2 + 0..4 * 0..5 * 0..7) * \
             (0..2 + 0..3 * 0..4 * 0..4 * 0..4 * 0..4 * (0..2 + 0..3 * 0..6))"
        );
    }

    fn test_range_decomposition(decomposition: &RangeDecomposition, upper_bound: u64) {
        let mut ring_specs = vec![];
        let mut lhs_capacities = vec![];
        decomposition.walk(1, &mut ring_specs, &mut lhs_capacities);

        let mut rng = thread_rng();
        for _ in 0..100 {
            let secret_value = rng.gen_range(0..upper_bound);
            let mut value_indexes = vec![];
            decomposition.decompose(&mut value_indexes, secret_value, &lhs_capacities);

            let restored = value_indexes
                .iter()
                .zip(&ring_specs)
                .fold(0, |acc, (&idx, spec)| acc + idx as u64 * spec.step);
            assert_eq!(
                restored, secret_value,
                "Cannot restore secret value {}; decomposed as {:?}",
                secret_value, value_indexes
            );
        }
    }

    #[test]
    fn applying_range() {
        let decomposition = RangeDecomposition::optimal(1_000);
        let mut ring_specs = vec![];
        let mut lhs_capacities = vec![];
        decomposition.walk(1, &mut ring_specs, &mut lhs_capacities);

        assert_eq!(
            ring_specs,
            [
                RingSpec { size: 5, step: 1 },
                RingSpec { size: 5, step: 5 },
                RingSpec { size: 5, step: 25 },
                RingSpec { size: 8, step: 125 },
            ]
        );
        assert_eq!(lhs_capacities, [5, 5, 5]);

        let mut value_indexes = vec![];
        decomposition.decompose(&mut value_indexes, 567, &lhs_capacities);
        assert_eq!(value_indexes, [2, 3, 2, 4]);
        // 2 + 3 * 5 + 2 * 25 + 4 * 125 = 567

        test_range_decomposition(&decomposition, 1_000);
    }

    #[test]
    fn applying_larger_range() {
        let decomposition = RangeDecomposition::optimal(9_999);
        test_range_decomposition(&decomposition, 9_999);

        let decomposition = RangeDecomposition::optimal(12_345);
        test_range_decomposition(&decomposition, 12_345);

        let decomposition = RangeDecomposition::optimal(54_321);
        test_range_decomposition(&decomposition, 54_321);
    }

    #[test]
    fn range_proof_basics() {
        let decomposition = RangeDecomposition::optimal(15).into();

        let mut rng = thread_rng();
        let receiver = Keypair::<Ristretto>::generate(&mut rng);
        let (ciphertext, proof) = RangeProof::new(
            receiver.public(),
            &decomposition,
            10,
            &mut Transcript::new(b"test"),
            &mut rng,
        );

        assert!(proof.verify(
            receiver.public(),
            &decomposition,
            ciphertext,
            &mut Transcript::new(b"test"),
        ));

        // Should not verify with another transcript context
        assert!(!proof.verify(
            receiver.public(),
            &decomposition,
            ciphertext,
            &mut Transcript::new(b"other"),
        ));

        // ...or with another receiver
        let other_receiver = Keypair::<Ristretto>::generate(&mut rng);
        assert!(!proof.verify(
            other_receiver.public(),
            &decomposition,
            ciphertext,
            &mut Transcript::new(b"test"),
        ));

        // ...or with another ciphertext
        let other_ciphertext = receiver.public().encrypt(10_u64, &mut rng);
        assert!(!proof.verify(
            receiver.public(),
            &decomposition,
            other_ciphertext,
            &mut Transcript::new(b"test"),
        ));

        let mut mangled_ciphertext = ciphertext;
        mangled_ciphertext.blinded_element =
            mangled_ciphertext.blinded_element + Ristretto::generator();
        assert!(!proof.verify(
            receiver.public(),
            &decomposition,
            mangled_ciphertext,
            &mut Transcript::new(b"test"),
        ));

        // ...or with another decomposition
        let other_decomposition = RangeDecomposition::Just(15).into();
        assert!(!proof.verify(
            receiver.public(),
            &other_decomposition,
            ciphertext,
            &mut Transcript::new(b"test"),
        ));
    }
}
