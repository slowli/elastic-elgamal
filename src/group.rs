//! Traits for prime-order groups in which discrete log problem is believed to be hard,
//! and some implementations of such groups.
//!
//! Such groups can be applied for ElGamal [`Encryption`](crate::Encryption)
//! and other cryptographic protocols from this crate.

use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use subtle::{ConditionallySelectable, ConstantTimeEq};

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
pub trait PointOps: ScalarOps {
    /// Member of the group. Arithmetic operations requested here (addition among
    /// points and multiplication by a `Scalar`) must be constant-time.
    type Point: Copy
        + ops::Add<Output = Self::Point>
        + ops::Sub<Output = Self::Point>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Point>
        + ConditionallySelectable
        + ConstantTimeEq
        + fmt::Debug;

    /// Byte size of a serialized [`Self::Point`].
    const POINT_SIZE: usize;

    /// Returns the identity of the group (aka point in infinity for EC groups).
    fn identity() -> Self::Point;

    /// Checks if the specified point is the identity.
    fn is_identity(point: &Self::Point) -> bool;

    /// Returns the agreed-upon generator of the group aka basepoint.
    fn base_point() -> Self::Point;

    /// Serializes `point` into a byte buffer.
    fn serialize_point(point: &Self::Point, output: &mut Vec<u8>);

    /// Deserializes a point from the byte buffer, which is guaranteed to have length
    /// [`Self::POINT_SIZE`].
    fn deserialize_point(input: &[u8]) -> Option<Self::Point>;
}

/// Prime-order group in which discrete log problem is believed to be hard.
///
/// Groups conforming to this trait can be used for ElGamal [`Encryption`] and other
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
/// [`Encryption`]: crate::Encryption
/// [ristretto]: https://ristretto.group/
/// [`elliptic-curve`]: https://docs.rs/elliptic-curve/
/// [`k256`]: https://docs.rs/k256/
pub trait Group: Copy + ScalarOps + PointOps + 'static {
    /// Multiplies the provided scalar by [`PointOps::base_point()`]. This operation must be
    /// constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented using [`Mul`](ops::Mul) (which is constant-time as per the [`PointOps`]
    /// contract).
    fn mul_base_point(k: &Self::Scalar) -> Self::Point {
        Self::base_point() * k
    }

    /// Multiplies the provided scalar by [`PointOps::base_point()`].
    /// Unlike [`Self::mul_base_point()`], this operation does not need to be constant-time;
    /// thus, it may employ additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::mul_base_point()`].
    #[inline]
    fn vartime_mul_base_point(k: &Self::Scalar) -> Self::Point {
        Self::mul_base_point(k)
    }

    /// Multiplies provided `scalars` by `points`. This operation must be constant-time
    /// w.r.t. the given length of elements.
    ///
    /// # Default implementation
    ///
    /// Implemented by straightforward computations, which are constant-time as per
    /// the [`PointOps`] contract.
    fn multi_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        let mut output = Self::identity();
        for (scalar, point) in scalars.into_iter().zip(points) {
            output = output + point * scalar;
        }
        output
    }

    /// Calculates `k * k_point + r * G`, where `G` is the group generator. This operation
    /// does not need to be constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented by straightforward arithmetic.
    fn vartime_double_mul_base_point(
        k: &Self::Scalar,
        k_point: Self::Point,
        r: &Self::Scalar,
    ) -> Self::Point {
        k_point * k + Self::base_point() * r
    }

    /// Multiplies provided `scalars` by `points`. Unlike [`Self::multi_mul()`],
    /// this operation does not need to be constant-time; thus, it may employ
    /// additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::multi_mul()`].
    #[inline]
    fn vartime_multi_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        Self::multi_mul(scalars, points)
    }
}
