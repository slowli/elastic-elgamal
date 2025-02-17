//! `Ciphertext` and closely related types.

use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use core::{fmt, marker::PhantomData, ops};

#[cfg(feature = "serde")]
use crate::serde::ElementHelper;
use crate::{
    alloc::{vec, HashMap, Vec},
    group::{Group, ScalarOps},
    PublicKey, SecretKey,
};

/// Ciphertext for ElGamal encryption.
///
/// A ciphertext consists of 2 group elements: the random element `R` and a blinded encrypted
/// value `B`. If the ciphertext encrypts integer value `v`, it holds that
///
/// ```text
/// R = [r]G;
/// B = [v]G + [r]K = [v]G + [k]R;
/// ```
///
/// where:
///
/// - `G` is the conventional group generator
/// - `r` is a random scalar selected by the encrypting party
/// - `K` and `k` are the recipient's public and private keys, respectively.
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
    /// Creates `Ciphertext` instance from `random_element` and `blinded_element`.
    pub fn from_elements(random_element: G::Element, blinded_element: G::Element) -> Self {
        Self {
            random_element,
            blinded_element,
        }
    }

    /// Represents encryption of zero value without the blinding factor.
    pub fn zero() -> Self {
        Self {
            random_element: G::identity(),
            blinded_element: G::identity(),
        }
    }

    /// Creates a non-blinded encryption of the specified scalar `value`, i.e., `(O, [value]G)`
    /// where `O` is identity and `G` is the conventional group generator.
    pub fn non_blinded<T>(value: T) -> Self
    where
        G::Scalar: From<T>,
    {
        let scalar = Zeroizing::new(G::Scalar::from(value));
        Self {
            random_element: G::identity(),
            blinded_element: G::mul_generator(&scalar),
        }
    }

    /// Returns a reference to the random element.
    pub fn random_element(&self) -> &G::Element {
        &self.random_element
    }

    /// Returns a reference to the blinded element.
    pub fn blinded_element(&self) -> &G::Element {
        &self.blinded_element
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

impl<G: Group> ops::Neg for Ciphertext<G> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            random_element: -self.random_element,
            blinded_element: -self.blinded_element,
        }
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
        let random_element = G::mul_generator(random_scalar.expose_scalar());
        let dh_element = receiver.as_element() * random_scalar.expose_scalar();
        let blinded_element = value + dh_element;

        Self {
            inner: Ciphertext {
                random_element,
                blinded_element,
            },
            random_scalar,
        }
    }

    pub(crate) fn zero() -> Self {
        Self {
            inner: Ciphertext::zero(),
            random_scalar: SecretKey::new(G::Scalar::from(0_u64)),
        }
    }

    pub(crate) fn with_value<V>(self, value: V) -> CiphertextWithValue<G, V>
    where
        V: Zeroize,
        G::Scalar: From<V>,
    {
        CiphertextWithValue {
            inner: self,
            value: Zeroizing::new(value),
        }
    }
}

impl<G: Group> ops::Add for ExtendedCiphertext<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
            random_scalar: self.random_scalar + rhs.random_scalar,
        }
    }
}

impl<G: Group> ops::AddAssign for ExtendedCiphertext<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.inner += rhs.inner;
        self.random_scalar += rhs.random_scalar;
    }
}

impl<G: Group> ops::Sub for ExtendedCiphertext<G> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
            random_scalar: self.random_scalar - rhs.random_scalar,
        }
    }
}

/// ElGamal [`Ciphertext`] together with fully retained information about the encrypted value and
/// randomness used to create the ciphertext.
///
/// This type can be used to produce certain kinds of proofs, such as
/// [`SumOfSquaresProof`](crate::SumOfSquaresProof).
#[derive(Debug)]
pub struct CiphertextWithValue<G: Group, V: Zeroize = <G as ScalarOps>::Scalar> {
    inner: ExtendedCiphertext<G>,
    value: Zeroizing<V>,
}

impl<G: Group, V: Zeroize> From<CiphertextWithValue<G, V>> for Ciphertext<G> {
    fn from(ciphertext: CiphertextWithValue<G, V>) -> Self {
        ciphertext.inner.inner
    }
}

impl<G: Group, V> CiphertextWithValue<G, V>
where
    V: Copy + Zeroize,
    G::Scalar: From<V>,
{
    /// Encrypts a value for the specified receiver.
    ///
    /// This is a lower-level operation compared to [`PublicKey::encrypt()`] and should be used
    /// if the resulting ciphertext is necessary to produce proofs.
    pub fn new<R: CryptoRng + RngCore>(value: V, receiver: &PublicKey<G>, rng: &mut R) -> Self {
        let scalar = Zeroizing::new(G::Scalar::from(value));
        let element = G::mul_generator(&scalar);
        ExtendedCiphertext::new(element, receiver, rng).with_value(value)
    }

    /// Converts the enclosed value into a scalar.
    pub fn generalize(self) -> CiphertextWithValue<G> {
        CiphertextWithValue {
            inner: self.inner,
            value: Zeroizing::new(G::Scalar::from(*self.value)),
        }
    }
}

impl<G: Group, V> CiphertextWithValue<G, V>
where
    V: Zeroize,
    G::Scalar: From<V>,
{
    /// Returns a reference to the contained [`Ciphertext`].
    pub fn inner(&self) -> &Ciphertext<G> {
        &self.inner.inner
    }

    pub(crate) fn extended_ciphertext(&self) -> &ExtendedCiphertext<G> {
        &self.inner
    }

    pub(crate) fn randomness(&self) -> &SecretKey<G> {
        &self.inner.random_scalar
    }

    pub(crate) fn value(&self) -> &V {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::{curve25519::scalar::Scalar as Curve25519Scalar, group::Ristretto, Keypair};

    #[test]
    fn ciphertext_addition() {
        let mut rng = thread_rng();
        let numbers: Vec<_> = (0..10).map(|_| u64::from(rng.gen::<u32>())).collect();
        let sum = numbers.iter().copied().sum::<u64>();

        let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        let ciphertexts = numbers.into_iter().map(|x| pk.encrypt(x, &mut rng));
        let sum_ciphertext = ciphertexts.reduce(ops::Add::add).unwrap();
        let decrypted = sk.decrypt_to_element(sum_ciphertext);

        assert_eq!(decrypted, Ristretto::vartime_mul_generator(&sum.into()));
    }

    #[test]
    fn ciphertext_mul_by_u64() {
        let mut rng = thread_rng();
        let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        for _ in 0..100 {
            let x = rng.gen::<u64>();
            let multiplier = rng.gen::<u64>();
            let ciphertext = pk.encrypt(x, &mut rng);
            let decrypted = sk.decrypt_to_element(ciphertext * multiplier);

            let expected_decryption =
                Curve25519Scalar::from(x) * Curve25519Scalar::from(multiplier);
            assert_eq!(
                decrypted,
                Ristretto::vartime_mul_generator(&expected_decryption)
            );
        }
    }

    #[test]
    fn ciphertext_negation() {
        let mut rng = thread_rng();
        let (pk, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        for _ in 0..100 {
            let x = rng.gen::<u64>();
            let ciphertext = pk.encrypt(x, &mut rng);
            let neg_ciphertext = -ciphertext;
            let decrypted = sk.decrypt_to_element(neg_ciphertext);

            assert_eq!(
                decrypted,
                Ristretto::vartime_mul_generator(&-Curve25519Scalar::from(x))
            );
        }
    }

    #[test]
    fn non_blinded_ciphertext() {
        let mut rng = thread_rng();
        let (_, sk) = Keypair::<Ristretto>::generate(&mut rng).into_tuple();
        for _ in 0..100 {
            let x = rng.gen::<u64>();
            let ciphertext = Ciphertext::non_blinded(x);
            let decrypted = sk.decrypt_to_element(ciphertext);

            assert_eq!(
                decrypted,
                Ristretto::vartime_mul_generator(&Curve25519Scalar::from(x))
            );
        }
    }
}
