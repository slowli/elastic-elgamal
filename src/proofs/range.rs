//! Range proofs for ElGamal ciphertexts.

use zeroize::{DefaultIsZeroes, Zeroizing};

use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, Copy, Default)]
struct RingSpec {
    size: u64,
    step: u64,
    value_index: u64,
}

impl DefaultIsZeroes for RingSpec {}

/// Decomposition of an integer range `0..n`.
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

    /// Computes upper bound of this decomposition and pushes upper bounds for LHSs
    /// of the inner decompositions into `bounds` in the DFS order.
    fn upper_bound(&self, bounds: &mut Vec<u64>) -> u64 {
        match self {
            Self::Just(bound) => *bound,
            Self::Mul { lhs, rhs } => {
                let lhs_size = lhs.upper_bound(bounds);
                bounds.push(lhs_size);
                lhs_size * rhs.upper_bound(bounds)
            }
            Self::Add { lhs, rhs } => {
                let lhs_size = lhs.upper_bound(bounds);
                bounds.push(lhs_size);
                lhs_size + rhs.upper_bound(bounds) - 1
            }
        }
    }

    /// Decomposes the provided `secret_value` into the constituent rings. `app_fn` is called
    /// for each of the rings.
    fn decompose(&self, secret_value: u64) -> Zeroizing<Vec<RingSpec>> {
        let mut upper_bounds = vec![];
        let upper_bound = self.upper_bound(&mut upper_bounds);
        upper_bounds.reverse();

        assert!(
            secret_value < upper_bound,
            "Secret value must be in range 0..{}",
            upper_bound
        );
        // We immediately allocate the necessary capacity for `decomposition`.
        let mut decomposition = Zeroizing::new(Vec::with_capacity(upper_bounds.len()));
        self.decompose_inner(&mut decomposition, secret_value, 1, &mut upper_bounds);
        decomposition
    }

    fn decompose_inner(
        &self,
        decomposition: &mut Vec<RingSpec>,
        secret_value: u64,
        multiplier: u64,
        upper_bounds: &mut Vec<u64>,
    ) {
        match self {
            Self::Just(bound) => decomposition.push(RingSpec {
                size: *bound,
                step: multiplier,
                value_index: secret_value,
            }),
            Self::Mul { lhs, rhs } => {
                let lhs_size = upper_bounds.pop().expect("upper_bounds underflow");
                lhs.decompose_inner(
                    decomposition,
                    secret_value % lhs_size,
                    multiplier,
                    upper_bounds,
                );
                rhs.decompose_inner(
                    decomposition,
                    secret_value / lhs_size,
                    multiplier * lhs_size,
                    upper_bounds,
                );
            }
            Self::Add { lhs, rhs } => {
                let lhs_size = upper_bounds.pop().expect("upper_bounds underflow");
                // TODO: is `saturating_sub` constant-time?
                let to_rhs = secret_value.saturating_sub(lhs_size - 1);
                lhs.decompose_inner(
                    decomposition,
                    secret_value - to_rhs,
                    multiplier,
                    upper_bounds,
                );
                rhs.decompose_inner(decomposition, to_rhs, multiplier, upper_bounds);
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

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;

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
        assert_eq!(value.upper_bound(&mut vec![]), 12_345);

        let value = RangeDecomposition::optimal(777_777);
        assert_eq!(
            value.to_string(),
            "0..3 * 0..7 * 0..7 * 0..11 * (0..2 + 0..4 * 0..4 * 0..5 * 0..6)"
        );
        assert_eq!(value.upper_bound(&mut vec![]), 777_777);

        let value = RangeDecomposition::optimal(12_345_678);
        assert_eq!(
            value.to_string(),
            "0..6 * (0..2 + 0..4 * 0..5 * 0..7) * \
             (0..2 + 0..3 * 0..4 * 0..4 * 0..4 * 0..4 * (0..2 + 0..3 * 0..6))"
        );
        assert_eq!(value.upper_bound(&mut vec![]), 12_345_678);
    }

    fn test_range_decomposition(decomposition: &RangeDecomposition, upper_bound: u64) {
        let mut rng = thread_rng();
        for _ in 0..100 {
            let secret_value = rng.gen_range(0..upper_bound);
            let ring_values = decomposition.decompose(secret_value);

            let restored = ring_values
                .iter()
                .fold(0, |acc, spec| acc + spec.value_index * spec.step);
            assert_eq!(
                restored, secret_value,
                "Cannot restore secret value {}; decomposed as {:?}",
                secret_value, ring_values
            );
        }
    }

    #[test]
    fn applying_range() {
        let decomposition = RangeDecomposition::optimal(1_000);
        let ring_values: Vec<_> = decomposition
            .decompose(567)
            .iter()
            .map(|spec| (spec.value_index, spec.step))
            .collect();
        assert_eq!(ring_values, [(2, 1), (3, 5), (2, 25), (4, 125)]);
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
}
