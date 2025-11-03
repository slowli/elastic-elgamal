//! Range proofs for ElGamal ciphertexts.

use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::{ConditionallySelectable, ConstantTimeGreater};
use zeroize::Zeroizing;

use core::{convert::TryFrom, fmt};

use crate::{
    alloc::{vec, HashMap, ToString, Vec},
    encryption::{CiphertextWithValue, ExtendedCiphertext},
    group::Group,
    proofs::{RingProof, RingProofBuilder, TranscriptForGroup},
    Ciphertext, PublicKey, VerificationError,
};

#[derive(Debug, Clone, Copy, PartialEq)]
struct RingSpec {
    size: u64,
    step: u64,
}

/// Decomposition of an integer range `0..n` into one or more sub-ranges. Decomposing the range
/// allows constructing [`RangeProof`]s with size / computational complexity `O(log n)`.
///
/// # Construction
///
/// To build efficient `RangeProof`s, we need to be able to decompose any value `x` in `0..n`
/// into several components, with each of them being in a smaller predefined range; once we
/// have such a decomposition, we can build a [`RingProof`] around it.
/// To build a decomposition, we use the following generic construction:
///
/// ```text
/// 0..n = 0..t_0 + k_0 * (0..t_1 + k_1 * (0..t_2 + …)),
/// ```
///
/// where `t_i` and `k_i` are integers greater than 1. If `x` is a value in `0..n`,
/// it is decomposed as
///
/// ```text
/// x = x_0 + k_0 * x_1 + k_0 * k_1 * x_2 + …; x_i in 0..t_i.
/// ```
///
/// For a decomposition to be valid (i.e., to represent any value in `0..n` and no other values),
/// the following statements are sufficient:
///
/// - `t_i >= k_i` (no gaps in values)
/// - `n = t_0 + k_0 * (t_1 - 1 + k_1 * …)` (exact upper bound).
///
/// The size of a `RingProof` is the sum of upper range bounds `t_i` (= number of responses) + 1
/// (the common challenge). Additionally, we need a ciphertext per each sub-range `0..t_i`
/// (i.e., for each ring in `RingProof`). In practice, proof size is logarithmic:
///
/// | Upper bound `n`| Optimal decomposition | Proof size |
/// |---------------:|-----------------------|-----------:|
/// | 5              | `0..5`                | 6 scalars  |
/// | 10             | `0..5 * 2 + 0..2`     | 8 scalars, 2 elements |
/// | 20             | `0..5 * 4 + 0..4`     | 10 scalars, 2 elements |
/// | 50             | `(0..5 * 5 + 0..5) * 2 + 0..2` | 13 scalars, 4 elements |
/// | 64             | `(0..4 * 4 + 0..4) * 4 + 0..4` | 13 scalars, 4 elements |
/// | 100            | `(0..5 * 5 + 0..5) * 4 + 0..4` | 15 scalars, 4 elements |
/// | 256            | `((0..4 * 4 + 0..4) * 4 + 0..4) * 4 + 0..4` | 17 scalars, 6 elements |
/// | 1000           | `((0..8 * 5 + 0..5) * 5 + 0..5) * 5 + 0..5` | 24 scalars, 6 elements |
///
/// (We do not count one of sub-range ciphertexts since it can be restored from the other
/// sub-range ciphertexts and the original ciphertext of the value.)
///
/// ## Notes
///
/// - Decomposition of some values may be non-unique, but this is fine for our purposes.
/// - Encoding of a value in a certain base is a partial case, with all `t_i` and `k_i` equal
///   to the base. It only works for `n` being a power of the base.
/// - Other types of decompositions may perform better, but this one has a couple
///   of nice properties. It works for all `n`s, and the optimal decomposition can be found
///   recursively.
/// - If we know how to create / verify range proofs for `0..N`, proofs for all ranges `0..n`,
///   `n < N` can be constructed as a combination of 2 proofs: a proof that encrypted value `x`
///   is in `0..N` and that `n - 1 - x` is in `0..N`. (The latter is proved for a ciphertext
///   obtained by the matching linear transform of the original ciphertext of `x`.)
///   This does not help us if proofs for `0..N` are constructed using [`RingProof`]s,
///   but allows estimating for which `n` a [Bulletproofs]-like construction would become
///   more efficient despite using 2 proofs. If we take `N = 2^(2^P)`
///   and the "vanilla" Bulletproof length `2 * P + 9`, this threshold is around `n = 2000`.
///
/// [Bulletproofs]: https://crypto.stanford.edu/bulletproofs/
///
/// # Examples
///
/// Finding out the optimal decomposition for a certain range:
///
/// ```
/// # use elastic_elgamal::RangeDecomposition;
/// let range = RangeDecomposition::optimal(42);
/// assert_eq!(range.to_string(), "6 * 0..7 + 0..6");
/// assert_eq!(range.proof_size(), 16); // 14 scalars, 2 elements
///
/// let range = RangeDecomposition::optimal(100);
/// assert_eq!(range.to_string(), "20 * 0..5 + 4 * 0..5 + 0..4");
/// assert_eq!(range.proof_size(), 19); // 15 scalars, 4 elements
/// ```
///
/// See [`RangeProof`] docs for an end-to-end example of usage.
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
    /// Finds an optimal decomposition of the range with the given `upper_bound` in terms
    /// of space of the range proof.
    ///
    /// Empirically, this method has sublinear complexity, but may work slowly for large values
    /// of `upper_bound` (say, larger than 1 billion).
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

    /// Returns the total number of items in all rings.
    fn rings_size(&self) -> u64 {
        self.rings.iter().map(|spec| spec.size).sum::<u64>()
    }

    /// Returns the size of [`RangeProof`]s using this decomposition, measured as a total number
    /// of scalars and group elements in the proof. Computational complexity of creating and
    /// verifying proofs is also linear w.r.t. this number.
    pub fn proof_size(&self) -> u64 {
        self.rings_size() + 2 * self.rings.len() as u64 - 1
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

        debug_assert_eq!(secret_value, 0, "unused secret value for {self:?}");
    }

    /// We decompose our range `0..n` as `0..t + k * 0..T`, where `t >= 2`, `T >= 2`,
    /// `k >= 2`. For all values in the range to be presentable, we need `t >= k` (otherwise,
    /// there will be gaps) and
    ///
    /// ```text
    /// n - 1 = t - 1 + k * (T - 1) <=> n = t + k * (T - 1)
    /// ```
    ///
    /// (to accurately represent the upper bound). For valid decompositions, we apply the
    /// same decomposition recursively to `0..T`. If `P(n)` is the optimal proof length for
    /// range `0..n`, we thus obtain
    ///
    /// ```text
    /// P(n) = min_(t, k) { t + 2 + P((n - t) / k + 1) }.
    /// ```
    ///
    /// Here, `t` is the number of commitments (= number of scalars for ring `0..t`), plus
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

    #[cfg(feature = "std")]
    fn lower_len_estimate(upper_bound: u64) -> u64 {
        ((upper_bound as f64).log2() * 3.0).ceil() as u64
    }

    #[cfg(not(feature = "std"))]
    fn lower_len_estimate(upper_bound: u64) -> u64 {
        Self::int_lower_len_estimate(upper_bound)
    }

    // We may not have floating-point arithmetics on no-std targets; thus, we use
    // a less precise estimate.
    #[cfg(any(test, not(feature = "std")))]
    #[inline]
    fn int_lower_len_estimate(upper_bound: u64) -> u64 {
        let log2_upper_bound = if upper_bound == 0 {
            0
        } else {
            63 - u64::from(upper_bound.leading_zeros()) // rounded down
        };
        log2_upper_bound * 3
    }
}

/// [`RangeDecomposition`] together with values precached for creating and/or verifying
/// [`RangeProof`]s in a certain [`Group`].
#[derive(Debug, Clone)]
pub struct PreparedRange<G: Group> {
    inner: RangeDecomposition,
    admissible_values: Vec<Vec<G::Element>>,
}

impl<G: Group> From<RangeDecomposition> for PreparedRange<G> {
    fn from(decomposition: RangeDecomposition) -> Self {
        Self::new(decomposition)
    }
}

impl<G: Group> PreparedRange<G> {
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

    /// Returns a reference to the contained decomposition.
    pub fn decomposition(&self) -> &RangeDecomposition {
        &self.inner
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
///
/// # Construction
///
/// To make the proof more compact – `O(log n)` in terms of size and proving / verification
/// complexity – we use the same trick as for [Pedersen commitments] (used, e.g., for confidential
/// transaction amounts in [Elements]):
///
/// 1. Represent the encrypted value `x` as `x = x_0 + k_0 * x_1 + k_0 * k_1 * x_2 + …`,
///    where `0 <= x_i < t_i` is the decomposition of `x` as per the [`RangeDecomposition`],
///    `0..t_0 + k_0 * (0..t_1 + …)`.
///    As an example, if `n` is a power of 2, one can choose a decomposition as
///    the base-2 presentation of `x`, i.e., `t_i = k_i = 2` for all `i`.
///    For brevity, denote a multiplier of `x_i` in `x` decomposition as `K_i`,
///    `K_i = k_0 * … * k_{i-1}`; `K_0 = 1` by extension.
/// 2. Split the ciphertext: `E = E_0 + E_1 + …`, where `E_i` encrypts `K_i * x_i`.
/// 3. Produce a [`RingProof`] that for all `i` the encrypted scalar for `E_i`
///    is among 0, `K_i`, …, `K_i * (t_i - 1)`. The range proof consists of all `E_i` ciphertexts
///    and this `RingProof`.
///
/// As with range proofs for Pedersen commitments, this construction is not optimal
/// in terms of space or proving / verification complexity for large ranges;
/// it is linear w.r.t. the bit length of the range.
/// (Constructions like [Bulletproofs] are *logarithmic* w.r.t. the bit length.)
/// Still, it can be useful for small ranges.
///
/// [Pedersen commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
/// [Elements]: https://elementsproject.org/features/confidential-transactions/investigation
/// [Bulletproofs]: https://crypto.stanford.edu/bulletproofs/
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{
/// #     group::Ristretto, DiscreteLogTable, Keypair, RangeDecomposition, RangeProof, Ciphertext,
/// # };
/// # use merlin::Transcript;
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate the ciphertext receiver.
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// // Find the optimal range decomposition for our range
/// // and specialize it for the Ristretto group.
/// let range = RangeDecomposition::optimal(100).into();
///
/// let (ciphertext, proof) = RangeProof::new(
///     receiver.public(),
///     &range,
///     55,
///     &mut Transcript::new(b"test_proof"),
///     &mut rng,
/// );
/// let ciphertext = Ciphertext::from(ciphertext);
///
/// // Check that the ciphertext is valid
/// let lookup = DiscreteLogTable::new(0..100);
/// assert_eq!(receiver.secret().decrypt(ciphertext, &lookup), Some(55));
/// // ...and that the proof verifies.
/// proof.verify(
///     receiver.public(),
///     &range,
///     ciphertext,
///     &mut Transcript::new(b"test_proof"),
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct RangeProof<G: Group> {
    partial_ciphertexts: Vec<Ciphertext<G>>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    inner: RingProof<G>,
}

impl<G: Group> RangeProof<G> {
    /// Encrypts `value` for `receiver` and creates a zero-knowledge proof that the encrypted value
    /// is in `range`.
    ///
    /// This is a lower-level operation; see [`PublicKey::encrypt_range()`] for a higher-level
    /// alternative.
    ///
    /// # Panics
    ///
    /// Panics if `value` is outside the range specified by `range`.
    pub fn new<R: RngCore + CryptoRng>(
        receiver: &PublicKey<G>,
        range: &PreparedRange<G>,
        value: u64,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> (CiphertextWithValue<G, u64>, Self) {
        let ciphertext = CiphertextWithValue::new(value, receiver, rng);
        let proof = Self::from_ciphertext(receiver, range, &ciphertext, transcript, rng);
        (ciphertext, proof)
    }

    /// Creates a proof that a value in `ciphertext` is in the `range`.
    ///
    /// The caller is responsible for providing a `ciphertext` encrypted for the `receiver`;
    /// if the ciphertext is encrypted for another public key, the resulting proof will not verify.
    ///
    /// # Panics
    ///
    /// Panics if `value` is outside the range specified by `range`.
    pub fn from_ciphertext<R: RngCore + CryptoRng>(
        receiver: &PublicKey<G>,
        range: &PreparedRange<G>,
        ciphertext: &CiphertextWithValue<G, u64>,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Self {
        let value_indexes = range.decompose(*ciphertext.value());
        debug_assert_eq!(value_indexes.len(), range.admissible_values.len());
        transcript.start_proof(b"encryption_range_proof");
        transcript.append_message(b"range", range.inner.to_string().as_bytes());

        let ring_responses_size = usize::try_from(range.inner.rings_size())
            .expect("Integer overflow when allocating ring responses");
        let mut ring_responses = vec![G::Scalar::default(); ring_responses_size];

        let mut proof_builder = RingProofBuilder::new(
            receiver,
            range.admissible_values.len(),
            &mut ring_responses,
            transcript,
            rng,
        );

        let mut cumulative_ciphertext = ExtendedCiphertext::zero();
        let mut it = value_indexes.iter().zip(&range.admissible_values);

        let partial_ciphertexts = it
            .by_ref()
            .take(value_indexes.len() - 1)
            .map(|(value_index, admissible_values)| {
                let ciphertext = proof_builder.add_value(admissible_values, *value_index);
                let inner = ciphertext.inner;
                cumulative_ciphertext += ciphertext;
                inner
            })
            .collect();

        let last_partial_ciphertext =
            ciphertext.extended_ciphertext().clone() - cumulative_ciphertext;
        let (&value_index, admissible_values) = it.next().unwrap();
        // ^ `unwrap()` is safe by construction
        proof_builder.add_precomputed_value(
            last_partial_ciphertext,
            admissible_values,
            value_index,
        );

        Self {
            partial_ciphertexts,
            inner: RingProof::new(proof_builder.build(), ring_responses),
        }
    }

    /// Verifies this proof against `ciphertext` for `receiver` and the specified `range`.
    ///
    /// This is a lower-level operation; see [`PublicKey::verify_range()`] for a higher-level
    /// alternative.
    ///
    /// For a proof to verify, all parameters must be identical to ones provided when creating
    /// the proof. In particular, `range` must have the same decomposition.
    ///
    /// # Errors
    ///
    /// Returns an error if this proof does not verify.
    pub fn verify(
        &self,
        receiver: &PublicKey<G>,
        range: &PreparedRange<G>,
        ciphertext: Ciphertext<G>,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError> {
        // Check decomposition / proof consistency.
        VerificationError::check_lengths(
            "admissible values",
            self.partial_ciphertexts.len() + 1,
            range.admissible_values.len(),
        )?;

        transcript.start_proof(b"encryption_range_proof");
        transcript.append_message(b"range", range.inner.to_string().as_bytes());

        let ciphertext_sum = self
            .partial_ciphertexts
            .iter()
            .fold(Ciphertext::zero(), |acc, ciphertext| acc + *ciphertext);
        let ciphertexts = self
            .partial_ciphertexts
            .iter()
            .copied()
            .chain(Some(ciphertext - ciphertext_sum));

        let admissible_values = range.admissible_values.iter().map(Vec::as_slice);
        self.inner
            .verify(receiver, admissible_values, ciphertexts, transcript)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use test_casing::test_casing;

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

    #[test_casing(4, [1_000, 9_999, 12_345, 54_321])]
    fn decomposing_for_larger_range(upper_bound: u64) {
        let decomposition = RangeDecomposition::optimal(upper_bound);
        let mut rng = rand::rng();

        let values = (0..1_000)
            .map(|_| rng.random_range(0..upper_bound))
            .chain(0..5)
            .chain((upper_bound - 5)..upper_bound);

        for secret_value in values {
            let mut value_indexes = vec![];
            decomposition.decompose(&mut value_indexes, secret_value);

            let restored = value_indexes
                .iter()
                .zip(&decomposition.rings)
                .fold(0, |acc, (&idx, spec)| acc + idx as u64 * spec.step);
            assert_eq!(
                restored, secret_value,
                "Cannot restore secret value {secret_value}; decomposed as {value_indexes:?}"
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
    }

    #[test_casing(4, [12, 15, 20, 50])]
    fn range_proof_basics(upper_bound: u64) {
        let decomposition = RangeDecomposition::optimal(upper_bound).into();

        let mut rng = rand::rng();
        let receiver = Keypair::<Ristretto>::generate(&mut rng);
        let (ciphertext, proof) = RangeProof::new(
            receiver.public(),
            &decomposition,
            10,
            &mut Transcript::new(b"test"),
            &mut rng,
        );
        let ciphertext = ciphertext.into();

        proof
            .verify(
                receiver.public(),
                &decomposition,
                ciphertext,
                &mut Transcript::new(b"test"),
            )
            .unwrap();

        // Should not verify with another transcript context
        assert!(proof
            .verify(
                receiver.public(),
                &decomposition,
                ciphertext,
                &mut Transcript::new(b"other"),
            )
            .is_err());

        // ...or with another receiver
        let other_receiver = Keypair::<Ristretto>::generate(&mut rng);
        assert!(proof
            .verify(
                other_receiver.public(),
                &decomposition,
                ciphertext,
                &mut Transcript::new(b"test"),
            )
            .is_err());

        // ...or with another ciphertext
        let other_ciphertext = receiver.public().encrypt(10_u64, &mut rng);
        assert!(proof
            .verify(
                receiver.public(),
                &decomposition,
                other_ciphertext,
                &mut Transcript::new(b"test"),
            )
            .is_err());

        let mut mangled_ciphertext = ciphertext;
        mangled_ciphertext.blinded_element += Ristretto::generator();
        assert!(proof
            .verify(
                receiver.public(),
                &decomposition,
                mangled_ciphertext,
                &mut Transcript::new(b"test"),
            )
            .is_err());

        // ...or with another decomposition
        let other_decomposition = RangeDecomposition::just(15).into();
        assert!(proof
            .verify(
                receiver.public(),
                &other_decomposition,
                ciphertext,
                &mut Transcript::new(b"test"),
            )
            .is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn int_lower_len_estimate_is_always_not_more_than_exact() {
        let samples = (0..1_000).chain((1..1_000).map(|i| i * 1_000));
        for sample in samples {
            let floating_point_estimate = RangeDecomposition::lower_len_estimate(sample);
            let int_estimate = RangeDecomposition::int_lower_len_estimate(sample);
            assert!(
                floating_point_estimate >= int_estimate,
                "Unexpected estimates for {sample}: floating-point = {floating_point_estimate}, \
                 int = {int_estimate}"
            );
        }
    }
}
