//! Range proofs for ElGamal ciphertexts.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use subtle::{ConditionallySelectable, ConstantTimeGreater};
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
#[derive(Debug, Clone, PartialEq)]
pub struct RangeDecomposition {
    rings: Vec<RingSpec>,
}

impl fmt::Display for RangeDecomposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, ring_spec) in self.rings.iter().enumerate() {
            if ring_spec.step > 1 {
                write!(formatter, "{} * ", ring_spec.step)?;
            }
            write!(formatter, "0..{}", ring_spec.size)?;

            if i + 1 < self.rings.len() {
                formatter.write_str(" + ")?;
            }
        }
        Ok(())
    }
}

/// `RangeDecomposition` together with optimized parameters.
#[derive(Debug, Clone)]
struct OptimalDecomposition {
    decomposition: RangeDecomposition,
    optimal_len: u64,
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
        Self::optimize(upper_bound, &mut optimal_values).decomposition
    }

    fn just(capacity: u64) -> Self {
        let spec = RingSpec {
            size: capacity,
            step: 1,
        };
        Self { rings: vec![spec] }
    }

    fn combine_mul(self, new_ring_size: u64, multiplier: u64) -> Self {
        let mut combined_rings = self.rings;
        for spec in &mut combined_rings {
            spec.step *= multiplier;
        }
        combined_rings.push(RingSpec {
            size: new_ring_size,
            step: 1,
        });

        Self {
            rings: combined_rings,
        }
    }

    /// Returns the exclusive upper bound of the range presentable by this decomposition.
    pub fn upper_bound(&self) -> u64 {
        self.rings
            .iter()
            .map(|spec| (spec.size - 1) * spec.step)
            .sum::<u64>()
            + 1
    }

    fn decompose(&self, value_indexes: &mut Vec<usize>, mut secret_value: u64) {
        for ring_spec in &self.rings {
            let mut value_index = secret_value / ring_spec.step;
            let ring_max_value = ring_spec.size - 1;
            let overflow = value_index.ct_gt(&ring_max_value);
            value_index.conditional_assign(&ring_max_value, overflow);
            value_indexes.push(value_index as usize);
            secret_value -= value_index * ring_spec.step;
        }

        debug_assert_eq!(secret_value, 0, "unused secret value for {:?}", self);
    }

    /// We decompose our range `0..n` as `0..a + k * 0..b`, where `a >= 2`, `b >= 2`,
    /// `k >= 2`. For all values in the range to be presentable, we need `a >= k` (otherwise,
    /// there will be gaps) and
    ///
    /// ```text
    /// n - 1 = a - 1 + k * (b - 1) <=> n = a + k * (b - 1)
    /// ```
    ///
    /// (to accurately represent the upper bound). For valid decompositions, we apply the
    /// same decomposition recursively to `0..b`. If `P(n)` is the optimal proof length for
    /// range `0..n`, we thus obtain
    ///
    /// ```text
    /// P(n) = min_(a, k) { a + 2 + P((n - a) / k + 1) }.
    /// ```
    ///
    /// Here, `a` is the number of commitments (= number of elements in the ring `0..a`), plus
    /// 2 group elements in a partial ElGamal ciphertext corresponding to the ring.
    ///
    /// We additionally trim the solution space using a lower-bound estimate
    ///
    /// ```text
    /// P(n) >= 3 * log2(n),
    /// ```
    ///
    /// which can be proven recursively.
    fn optimize(
        upper_bound: u64,
        optimal_values: &mut HashMap<u64, OptimalDecomposition>,
    ) -> OptimalDecomposition {
        if let Some(opt) = optimal_values.get(&upper_bound) {
            return opt.clone();
        }

        let mut opt = OptimalDecomposition {
            optimal_len: upper_bound + 2,
            decomposition: RangeDecomposition::just(upper_bound),
        };

        for first_ring_size in 2_u64.. {
            if first_ring_size + 2 > opt.optimal_len {
                // Any further estimate will be worse than the current optimum.
                break;
            }

            let remaining_capacity = upper_bound - first_ring_size;
            for multiplier in 2_u64..=first_ring_size {
                if remaining_capacity % multiplier != 0 {
                    continue;
                }
                let inner_upper_bound = remaining_capacity / multiplier + 1;
                if inner_upper_bound < 2 {
                    // Since `inner_upper_bound` decreases w.r.t. `multiplier`, we can
                    // break here.
                    break;
                }

                let best_estimate =
                    first_ring_size + 2 + Self::lower_len_estimate(inner_upper_bound);
                if best_estimate > opt.optimal_len {
                    continue;
                }

                let inner_opt = Self::optimize(inner_upper_bound, optimal_values);
                let candidate_len = first_ring_size + 2 + inner_opt.optimal_len;
                let candidate_rings = 1 + inner_opt.decomposition.rings.len();

                if candidate_len < opt.optimal_len
                    || (candidate_len == opt.optimal_len
                        && candidate_rings < opt.decomposition.rings.len())
                {
                    opt.optimal_len = candidate_len;
                    opt.decomposition = inner_opt
                        .decomposition
                        .combine_mul(first_ring_size, multiplier);
                }
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
}

#[derive(Debug, Clone)]
pub struct PreparedRangeDecomposition<G: Group> {
    inner: RangeDecomposition,
    admissible_values: Vec<Vec<G::Element>>,
}

impl<G: Group> From<RangeDecomposition> for PreparedRangeDecomposition<G> {
    fn from(decomposition: RangeDecomposition) -> Self {
        Self::new(decomposition)
    }
}

impl<G: Group> PreparedRangeDecomposition<G> {
    fn new(inner: RangeDecomposition) -> Self {
        let admissible_values = Vec::with_capacity(inner.rings.len());
        let admissible_values = inner.rings.iter().fold(admissible_values, |mut acc, spec| {
            let ring_values: Vec<_> = (0..spec.size)
                .map(|i| G::vartime_mul_generator(&(i * spec.step).into()))
                .collect();
            acc.push(ring_values);
            acc
        });

        Self {
            inner,
            admissible_values,
        }
    }

    /// Decomposes the provided `secret_value` into value indexes in constituent rings.
    fn decompose(&self, secret_value: u64) -> Zeroizing<Vec<usize>> {
        assert!(
            secret_value < self.inner.upper_bound(),
            "Secret value must be in range 0..{}",
            self.inner.upper_bound()
        );
        // We immediately allocate the necessary capacity for `decomposition`.
        let mut decomposition = Zeroizing::new(Vec::with_capacity(self.admissible_values.len()));
        self.inner.decompose(&mut decomposition, secret_value);
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
    fn optimal_value_small() {
        let value = RangeDecomposition::optimal(5);
        assert_eq!(value.rings.as_ref(), [RingSpec { size: 5, step: 1 }]);

        let value = RangeDecomposition::optimal(16);
        assert_eq!(
            value.rings.as_ref(),
            [RingSpec { size: 4, step: 4 }, RingSpec { size: 4, step: 1 }]
        );

        let value = RangeDecomposition::optimal(60);
        assert_eq!(
            value.rings.as_ref(),
            [
                RingSpec { size: 5, step: 12 },
                RingSpec { size: 4, step: 3 },
                RingSpec { size: 3, step: 1 },
            ]
        );

        let value = RangeDecomposition::optimal(1_000);
        assert_eq!(
            value.to_string(),
            "125 * 0..8 + 25 * 0..5 + 5 * 0..5 + 0..5"
        );
    }

    #[test]
    fn optimal_values_with_additives() {
        let value = RangeDecomposition::optimal(17);
        assert_eq!(
            value.rings.as_ref(),
            [RingSpec { size: 4, step: 4 }, RingSpec { size: 5, step: 1 }]
        );

        let value = RangeDecomposition::optimal(101);
        assert_eq!(
            value.rings.as_ref(),
            [
                RingSpec { size: 5, step: 20 },
                RingSpec { size: 5, step: 4 },
                RingSpec { size: 5, step: 1 }
            ]
        );
    }

    #[test]
    fn large_optimal_values() {
        let value = RangeDecomposition::optimal(12_345);
        assert_eq!(
            value.to_string(),
            "2880 * 0..4 + 720 * 0..5 + 90 * 0..9 + 15 * 0..7 + 3 * 0..5 + 0..3"
        );
        assert_eq!(value.upper_bound(), 12_345);

        let value = RangeDecomposition::optimal(777_777);
        assert_eq!(
            value.to_string(),
            "125440 * 0..6 + 25088 * 0..6 + 3136 * 0..8 + 784 * 0..4 + 196 * 0..4 + \
             49 * 0..5 + 7 * 0..7 + 0..7"
        );
        assert_eq!(value.upper_bound(), 777_777);

        let value = RangeDecomposition::optimal(12_345_678);
        assert_eq!(
            value.to_string(),
            "3072000 * 0..4 + 768000 * 0..4 + 192000 * 0..4 + 48000 * 0..5 + 9600 * 0..6 + \
             1200 * 0..8 + 300 * 0..4 + 75 * 0..5 + 15 * 0..5 + 3 * 0..6 + 0..3"
        );
        assert_eq!(value.upper_bound(), 12_345_678);
    }

    fn test_range_decomposition(decomposition: &RangeDecomposition, upper_bound: u64) {
        let mut rng = thread_rng();

        let values = (0..1_000)
            .map(|_| rng.gen_range(0..upper_bound))
            .chain(0..5)
            .chain((upper_bound - 5)..upper_bound);

        for secret_value in values {
            let mut value_indexes = vec![];
            decomposition.decompose(&mut value_indexes, secret_value);

            let restored = value_indexes
                .iter()
                .zip(&*decomposition.rings)
                .fold(0, |acc, (&idx, spec)| acc + idx as u64 * spec.step);
            assert_eq!(
                restored, secret_value,
                "Cannot restore secret value {}; decomposed as {:?}",
                secret_value, value_indexes
            );
        }
    }

    #[test]
    fn decomposing_for_small_range() {
        let decomposition = RangeDecomposition::optimal(17);
        assert_eq!(decomposition.to_string(), "4 * 0..4 + 0..5");
        let mut value_indexes = vec![];
        decomposition.decompose(&mut value_indexes, 16);
        assert_eq!(value_indexes, [3, 4]);
        // 3 * 4 + 4 = 16
    }

    #[test]
    fn decomposing_for_range() {
        let decomposition = RangeDecomposition::optimal(1_000);
        let mut value_indexes = vec![];
        decomposition.decompose(&mut value_indexes, 567);
        assert_eq!(value_indexes, [4, 2, 3, 2]);
        // 2 + 3 * 5 + 2 * 25 + 4 * 125 = 567

        test_range_decomposition(&decomposition, 1_000);
    }

    #[test]
    fn decomposing_for_larger_range() {
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
        mangled_ciphertext.blinded_element += Ristretto::generator();
        assert!(!proof.verify(
            receiver.public(),
            &decomposition,
            mangled_ciphertext,
            &mut Transcript::new(b"test"),
        ));

        // ...or with another decomposition
        let other_decomposition = RangeDecomposition::just(15).into();
        assert!(!proof.verify(
            receiver.public(),
            &other_decomposition,
            ciphertext,
            &mut Transcript::new(b"test"),
        ));
    }
}
