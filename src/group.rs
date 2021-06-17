//! Traits and implementations for prime-order groups in which
//! the [decisional Diffie–Hellman][DDH] (DDH), [computational Diffie–Hellman][CDH] (CDH)
//! and [discrete log][DLP] (DL) problems are believed to be hard.
//!
//! (Decisional Diffie–Hellman assumption is considered stronger than both CDH and DL,
//! so if DDH is believed to hold for a certain group, it should be good to go.)
//!
//! Such groups can be applied for ElGamal encryption and other cryptographic protocols from this crate.
//!
//! [DDH]: https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption
//! [CDH]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_problem
//! [DLP]: https://en.wikipedia.org/wiki/Discrete_logarithm

use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use std::{fmt, io, ops};

mod curve25519;
mod generic;
mod ristretto;
pub use self::{curve25519::Curve25519Subgroup, generic::Generic, ristretto::Ristretto};

/// Helper trait for [`Group`] that describes operations on group scalars.
pub trait ScalarOps {
    /// Scalar type. As per [`Group`] contract, scalars must form a prime field.
    /// Arithmetic operations on scalars requested here must be constant-time.
    type Scalar: Copy
        + Default
        + From<u64>
        + ops::Neg<Output = Self::Scalar>
        + ops::Add<Output = Self::Scalar>
        + ops::Sub<Output = Self::Scalar>
        + ops::Mul<Output = Self::Scalar>
        + ConditionallySelectable
        + ConstantTimeEq
        + Zeroize
        + fmt::Debug;

    /// Byte size of a serialized [`Self::Scalar`].
    const SCALAR_SIZE: usize;

    /// Generates a random scalar based on the provided CSPRNG. This operation
    /// must be constant-time.
    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar;

    /// Generates a scalar from a `source` of random bytes. This operation must be constant-time.
    /// The `source` is guaranteed to return any necessary number of bytes.
    ///
    /// # Default implementation
    ///
    /// 1. Create a [ChaCha RNG] using 32 bytes read from `source` as the seed.
    /// 2. Call [`Self::generate_scalar()`] with the created RNG.
    ///
    /// [ChaCha RNG]: https://docs.rs/rand_chacha/
    fn scalar_from_random_bytes<R: io::Read>(mut source: R) -> Self::Scalar {
        let mut rng_seed = <ChaChaRng as SeedableRng>::Seed::default();
        source
            .read_exact(&mut rng_seed)
            .expect("cannot read random bytes from source");
        let mut rng = ChaChaRng::from_seed(rng_seed);
        Self::generate_scalar(&mut rng)
    }

    /// Inverts the `scalar`, which is guaranteed to be non-zero. This operation does not
    /// need to be constant-time.
    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar;

    /// Inverts scalars in a batch. This operation does not need to be constant-time.
    ///
    /// # Default implementation
    ///
    /// Inverts every scalar successively.
    fn invert_scalars(scalars: &mut [Self::Scalar]) {
        for scalar in scalars {
            *scalar = Self::invert_scalar(*scalar);
        }
    }

    /// Serializes the scalar into a byte buffer.
    fn serialize_scalar(scalar: &Self::Scalar, output: &mut Vec<u8>);

    /// Deserializes the scalar from the byte buffer. This method returns `None` if the buffer
    /// does not correspond to a representation of a valid scalar.
    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar>;
}

/// Helper trait for [`Group`] that describes operations on group elements (i.e., EC points
/// for elliptic curve groups).
pub trait ElementOps: ScalarOps {
    /// Element of the group. Arithmetic operations requested here (addition among
    /// elements and multiplication by a `Scalar`) must be constant-time.
    type Element: Copy
        + ops::Add<Output = Self::Element>
        + ops::Sub<Output = Self::Element>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Element>
        + ConditionallySelectable
        + ConstantTimeEq
        + fmt::Debug;

    /// Byte size of a serialized [`Self::Element`].
    const ELEMENT_SIZE: usize;

    /// Returns the identity of the group (aka point at infinity for EC groups).
    fn identity() -> Self::Element;

    /// Checks if the specified element is the identity.
    fn is_identity(element: &Self::Element) -> bool;

    /// Returns the agreed-upon generator of the group.
    fn generator() -> Self::Element;

    /// Serializes `element` into a byte buffer.
    fn serialize_element(element: &Self::Element, output: &mut Vec<u8>);

    /// Deserializes an element from the byte buffer, which is guaranteed to have length
    /// [`Self::ELEMENT_SIZE`].
    fn deserialize_element(input: &[u8]) -> Option<Self::Element>;
}

/// Prime-order group in which the discrete log problem and decisional / computational
/// Diffie–Hellman problems are believed to be hard.
///
/// Groups conforming to this trait can be used for ElGamal encryption and other
/// cryptographic protocols defined in this crate.
///
/// This crate provides the following implementations of this trait:
///
/// - [`Curve25519Subgroup`], representation of a prime-order subgroup of Curve25519
///   with the conventionally chosen generator.
/// - [`Ristretto`], a transform of Curve25519 which eliminates its co-factor 8 with the help
///   of the [eponymous technique][ristretto].
/// - [`Generic`] implementation defined in terms of traits from the [`elliptic-curve`] crate.
///   (For example, this means secp256k1 support via the [`k256`] crate.)
///
/// [ristretto]: https://ristretto.group/
/// [`elliptic-curve`]: https://docs.rs/elliptic-curve/
/// [`k256`]: https://docs.rs/k256/
pub trait Group: Copy + ScalarOps + ElementOps + 'static {
    /// Multiplies the provided scalar by [`ElementOps::generator()`]. This operation must be
    /// constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented using [`Mul`](ops::Mul) (which is constant-time as per the [`ElementOps`]
    /// contract).
    fn mul_generator(k: &Self::Scalar) -> Self::Element {
        Self::generator() * k
    }

    /// Multiplies the provided scalar by [`ElementOps::generator()`].
    /// Unlike [`Self::mul_generator()`], this operation does not need to be constant-time;
    /// thus, it may employ additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::mul_generator()`].
    #[inline]
    fn vartime_mul_generator(k: &Self::Scalar) -> Self::Element {
        Self::mul_generator(k)
    }

    /// Multiplies provided `scalars` by `elements`. This operation must be constant-time
    /// w.r.t. the given length of elements.
    ///
    /// # Default implementation
    ///
    /// Implemented by straightforward computations, which are constant-time as per
    /// the [`ElementOps`] contract.
    fn multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        let mut output = Self::identity();
        for (scalar, element) in scalars.into_iter().zip(elements) {
            output = output + element * scalar;
        }
        output
    }

    /// Calculates `k * k_element + r * G`, where `G` is the group generator. This operation
    /// does not need to be constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented by straightforward arithmetic.
    fn vartime_double_mul_generator(
        k: &Self::Scalar,
        k_element: Self::Element,
        r: &Self::Scalar,
    ) -> Self::Element {
        k_element * k + Self::generator() * r
    }

    /// Multiplies provided `scalars` by `elements`. Unlike [`Self::multi_mul()`],
    /// this operation does not need to be constant-time; thus, it may employ
    /// additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::multi_mul()`].
    #[inline]
    fn vartime_multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
    {
        Self::multi_mul(scalars, elements)
    }
}
