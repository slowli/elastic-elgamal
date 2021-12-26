//! `Ciphertext` and closely related types.

use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use core::{fmt, marker::PhantomData, ops};

#[cfg(feature = "serde")]
use crate::serde::ElementHelper;
use crate::{
    alloc::{vec, Vec},
    group::Group,
    proofs::{LogEqualityProof, RingProof, VerificationError},
    PublicKey, SecretKey,
};

/// Ciphertext for ElGamal encryption.
///
/// Ciphertexts are partially homomorphic: they can be added together or multiplied by a scalar
/// value.
///
/// # Examples
///
/// Basic usage and arithmetic for ciphertexts:
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// // Generate a keypair for the ciphertext receiver.
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// // Create a couple of ciphertexts.
/// let mut enc = receiver.public().encrypt(2_u64, &mut rng);
/// enc += receiver.public().encrypt(3_u64, &mut rng) * 4;
/// // Check that the ciphertext decrypts to 2 + 3 * 4 = 14.
/// let lookup_table = DiscreteLogTable::new(0..20);
/// let decrypted = receiver.secret().decrypt(enc, &lookup_table);
/// assert_eq!(decrypted, Some(14));
/// ```
///
/// Creating a ciphertext of a boolean value together with a proof:
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair for the ciphertext receiver.
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// // Create and verify a boolean encryption.
/// let (enc, proof) =
///     receiver.public().encrypt_bool(false, &mut rng);
/// receiver.public().verify_bool(enc, &proof)?;
/// # Ok(())
/// # }
/// ```
///
/// Creating a ciphertext of an integer value together with a range proof:
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, Keypair, RangeDecomposition};
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate the ciphertext receiver.
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// // Find the optimal range decomposition for our range
/// // and specialize it for the Ristretto group.
/// let range = RangeDecomposition::optimal(100).into();
///
/// let (ciphertext, proof) = receiver
///     .public()
///     .encrypt_range(&range, 42, &mut rng);
///
/// // Check that the the proof verifies.
/// receiver.public().verify_range(&range, ciphertext, &proof)?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext<G: Group> {
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    pub(crate) random_element: G::Element,
    #[cfg_attr(feature = "serde", serde(with = "ElementHelper::<G>"))]
    pub(crate) blinded_element: G::Element,
}

impl<G: Group> fmt::Debug for Ciphertext<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext")
            .field("random_element", &self.random_element)
            .field("blinded_element", &self.blinded_element)
            .finish()
    }
}

impl<G: Group> Ciphertext<G> {
    /// Represents encryption of zero value without the blinding factor.
    pub fn zero() -> Self {
        Self {
            random_element: G::identity(),
            blinded_element: G::identity(),
        }
    }

    /// Serializes this ciphertext as two group elements (the random element,
    /// then the blinded value).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = vec![0_u8; 2 * G::ELEMENT_SIZE];
        G::serialize_element(&self.random_element, &mut bytes[..G::ELEMENT_SIZE]);
        G::serialize_element(&self.blinded_element, &mut bytes[G::ELEMENT_SIZE..]);
        bytes
    }
}

impl<G: Group> ops::Add for Ciphertext<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            random_element: self.random_element + rhs.random_element,
            blinded_element: self.blinded_element + rhs.blinded_element,
        }
    }
}

impl<G: Group> ops::AddAssign for Ciphertext<G> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<G: Group> ops::Sub for Ciphertext<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            random_element: self.random_element - rhs.random_element,
            blinded_element: self.blinded_element - rhs.blinded_element,
        }
    }
}

impl<G: Group> ops::SubAssign for Ciphertext<G> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for Ciphertext<G> {
    type Output = Self;

    fn mul(self, rhs: &G::Scalar) -> Self {
        Self {
            random_element: self.random_element * rhs,
            blinded_element: self.blinded_element * rhs,
        }
    }
}

impl<G: Group> ops::Mul<u64> for Ciphertext<G> {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        let scalar = G::Scalar::from(rhs);
        self * &scalar
    }
}

/// Lookup table for discrete logarithms.
///
/// For [`Ciphertext`]s to be partially homomorphic, the encrypted values must be
/// group scalars linearly mapped to group elements: `x -> [x]G`, where `G` is the group
/// generator. After decryption it is necessary to map the decrypted group element back to a scalar
/// (i.e., get its discrete logarithm with base `G`). Because of discrete logarithm assumption,
/// this task is computationally infeasible in the general case; however, if the possible range
/// of encrypted values is small, it is possible to "cheat" by precomputing mapping `[x]G -> x`
/// for all allowed `x` ahead of time. This is exactly what `DiscreteLogTable` does.
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, Ciphertext, Keypair};
/// # use rand::thread_rng;
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let ciphertexts = (0_u64..16)
///     .map(|i| receiver.public().encrypt(i, &mut rng));
/// // Assume that we know that the plaintext is in range 0..16,
/// // e.g., via a zero-knowledge proof.
/// let lookup_table = DiscreteLogTable::new(0..16);
/// // Then, we can use the lookup table to decrypt values.
/// // A single table may be shared for multiple decryption operations
/// // (i.e., it may be constructed ahead of time).
/// for (i, enc) in ciphertexts.enumerate() {
///     assert_eq!(
///         receiver.secret().decrypt(enc, &lookup_table),
///         Some(i as u64)
///     );
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DiscreteLogTable<G: Group> {
    inner: HashMap<Vec<u8>, u64>,
    _t: PhantomData<G>,
}

impl<G: Group> DiscreteLogTable<G> {
    /// Creates a lookup table for the specified `values`.
    pub fn new(values: impl IntoIterator<Item = u64>) -> Self {
        let lookup_table = values
            .into_iter()
            .filter(|&value| value != 0)
            .map(|i| {
                let element = G::vartime_mul_generator(&G::Scalar::from(i));
                let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
                G::serialize_element(&element, &mut bytes);
                (bytes, i)
            })
            .collect();

        Self {
            inner: lookup_table,
            _t: PhantomData,
        }
    }

    /// Gets the discrete log of `decrypted_element`, or `None` if it is not present among `values`
    /// stored in this table.
    pub fn get(&self, decrypted_element: &G::Element) -> Option<u64> {
        if G::is_identity(decrypted_element) {
            // The identity element may have a special serialization (e.g., in SEC standard
            // for elliptic curves), so we check it separately.
            Some(0)
        } else {
            let mut bytes = vec![0_u8; G::ELEMENT_SIZE];
            G::serialize_element(decrypted_element, &mut bytes);
            self.inner.get(&bytes).copied()
        }
    }
}

/// [`Ciphertext`] together with the random scalar used to create it.
#[derive(Debug, Clone)]
#[doc(hidden)] // only public for benchmarking
pub struct ExtendedCiphertext<G: Group> {
    pub(crate) inner: Ciphertext<G>,
    pub(crate) random_scalar: SecretKey<G>,
}

impl<G: Group> ExtendedCiphertext<G> {
    /// Creates a ciphertext of `value` for the specified `receiver`.
    pub(crate) fn new<R: CryptoRng + RngCore>(
        value: G::Element,
        receiver: &PublicKey<G>,
        rng: &mut R,
    ) -> Self {
        let random_scalar = SecretKey::<G>::generate(rng);
        let random_element = G::mul_generator(&random_scalar.0);
        let dh_element = receiver.element * &random_scalar.0;
        let blinded_element = value + dh_element;

        Self {
            inner: Ciphertext {
                random_element,
                blinded_element,
            },
            random_scalar,
        }
    }

    pub(crate) fn with_value(self, value: SecretKey<G>) -> CiphertextWithValue<G> {
        CiphertextWithValue { inner: self, value }
    }
}

/// ElGamal [`Ciphertext`] together with fully retained information about the encrypted value and
/// randomness used to create the ciphertext.
///
/// This type can be used to produce certain kinds of proofs, such as
/// [`SumOfSquaresProof`](crate::SumOfSquaresProof).
#[derive(Debug)]
pub struct CiphertextWithValue<G: Group> {
    inner: ExtendedCiphertext<G>,
    value: SecretKey<G>,
}

impl<G: Group> From<CiphertextWithValue<G>> for Ciphertext<G> {
    fn from(ciphertext: CiphertextWithValue<G>) -> Self {
        ciphertext.inner.inner
    }
}

impl<G: Group> CiphertextWithValue<G> {
    /// Encrypts a value for the specified receiver.
    ///
    /// This is a lower-level operation compared to [`PublicKey::encrypt()`] and should be used
    /// if the resulting ciphertext is necessary to produce proofs.
    pub fn new<T, R: CryptoRng + RngCore>(value: T, receiver: &PublicKey<G>, rng: &mut R) -> Self
    where
        G::Scalar: From<T>,
    {
        let value = SecretKey::new(G::Scalar::from(value));
        let element = G::mul_generator(&value.0);
        ExtendedCiphertext::new(element, receiver, rng).with_value(value)
    }

    /// Returns a reference to the contained [`Ciphertext`].
    pub fn inner(&self) -> &Ciphertext<G> {
        &self.inner.inner
    }

    pub(crate) fn random_scalar(&self) -> &SecretKey<G> {
        &self.inner.random_scalar
    }

    pub(crate) fn value(&self) -> &SecretKey<G> {
        &self.value
    }
}

/// Encrypted choice of a value in a range `0..n` for certain integer `n > 1` together with
/// validity zero-knowledge proofs.
///
/// # Construction
///
/// The choice is represented as a vector of `n` *variant ciphertexts* of Boolean values (0 or 1),
/// where the chosen variant encrypts 1 and other variants encrypt 0.
/// This ensures that multiple [`EncryptedChoice`]s can be added (e.g., within a voting protocol).
/// These ciphertexts can be obtained via [`PublicKey::verify_choice()`].
///
/// Zero-knowledge proofs are:
///
/// - A [`RingProof`] attesting that all `n` ciphertexts encrypt 0 or 1.
///   This proof can be obtained via [`Self::range_proof()`].
/// - A [`LogEqualityProof`] attesting that the encrypted values sum up to 1. Combined with
///   the range proof, this means that exactly one of encrypted values is 1, and all others are 0.
///   This proof can be obtained via [`Self::sum_proof()`].
///
/// # Examples
///
/// ```
/// # use elastic_elgamal::{group::Ristretto, DiscreteLogTable, EncryptedChoice, Keypair};
/// # use rand::thread_rng;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = thread_rng();
/// let receiver = Keypair::<Ristretto>::generate(&mut rng);
/// let choice = 2;
/// let enc = receiver.public().encrypt_choice(5, choice, &mut rng);
/// let variants = receiver.public().verify_choice(&enc)?;
///
/// // `variants` is a slice of 5 Boolean value ciphertexts
/// assert_eq!(variants.len(), 5);
/// let lookup_table = DiscreteLogTable::new(0..=1);
/// for (idx, &v) in variants.iter().enumerate() {
///     assert_eq!(
///         receiver.secret().decrypt(v, &lookup_table),
///         Some((idx == choice) as u64)
///     );
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct EncryptedChoice<G: Group> {
    pub(crate) variants: Vec<Ciphertext<G>>,
    pub(crate) range_proof: RingProof<G>,
    pub(crate) sum_proof: LogEqualityProof<G>,
}

#[allow(clippy::len_without_is_empty)] // `is_empty()` would always be false
impl<G: Group> EncryptedChoice<G> {
    /// Returns the number of variants in this choice.
    pub fn len(&self) -> usize {
        self.variants.len()
    }

    /// Returns variant ciphertexts **without** checking their validity.
    pub fn variants_unchecked(&self) -> &[Ciphertext<G>] {
        &self.variants
    }

    /// Returns the range proof for the variant ciphertexts.
    pub fn range_proof(&self) -> &RingProof<G> {
        &self.range_proof
    }

    /// Returns the sum proof for the variant ciphertexts.
    pub fn sum_proof(&self) -> &LogEqualityProof<G> {
        &self.sum_proof
    }
}

/// Error verifying an [`EncryptedChoice`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ChoiceVerificationError {
    /// [`EncryptedChoice`] does not have variants.
    ///
    /// This error means that the `EncryptedChoice` is malformed (e.g., after deserializing it
    /// from an untrusted source).
    Empty,
    /// Error verifying [`EncryptedChoice::sum_proof()`].
    Sum(VerificationError),
    /// Error verifying [`EncryptedChoice::range_proof()`].
    Range(VerificationError),
}

impl fmt::Display for ChoiceVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("encrypted choice does not have variants"),
            Self::Sum(err) => write!(formatter, "cannot verify sum proof: {}", err),
            Self::Range(err) => write!(formatter, "cannot verify range proofs: {}", err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChoiceVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sum(err) | Self::Range(err) => Some(err),
            _ => None,
        }
    }
}
