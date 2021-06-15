// FIXME: make module public

use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use std::{fmt, io, ops};

mod edwards;
mod generic;
mod ristretto;
pub use self::{edwards::Edwards, generic::Generic, ristretto::Ristretto};

/// Helper trait for `Group` that describes operations on group scalars.
pub trait ScalarOps {
    /// Scalar type. Arithmetic operations must be constant-time.
    type Scalar: Copy
        + Default
        + From<u64>
        + PartialEq
        + ops::Neg<Output = Self::Scalar>
        + ops::Add<Output = Self::Scalar>
        + ops::Sub<Output = Self::Scalar>
        + ops::Mul<Output = Self::Scalar>
        + ConditionallySelectable
        + fmt::Debug;

    /// Byte size of a serialized [`Self::Scalar`].
    const SCALAR_SIZE: usize;

    /// Generates a random scalar based on the provided CSPRNG. This operation
    /// must be constant-time.
    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar;

    /// Generates a scalar from the `source` of random bytes. This operation must be constant-time.
    /// The `source` is guaranteed to return any necessary number of bytes.
    ///
    /// # Default implementation
    ///
    /// 1. Create a [ChaCha RNG] with the 32 bytes from the `source` as the seed.
    /// 2. Call [`Self::generate_scalar()`] with the created RNG.
    ///
    /// [ChaCha CSPRNG]: https://docs.rs/rand_chacha/
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

/// Helper trait for `Group` that describes operations on group elements (i.e., EC points).
pub trait PointOps: ScalarOps {
    /// Member of the group. Should define necessary arithmetic operations (addition among
    /// points and multiplication by a `Scalar`), which must be constant-time.
    type Point: Copy
        + ops::Add<Output = Self::Point>
        + ops::Sub<Output = Self::Point>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Point>
        + ConditionallySelectable
        + ConstantTimeEq
        + fmt::Debug;

    /// Byte size of a serialized [`Self::Point`].
    const POINT_SIZE: usize;

    /// Returns an identity point (aka point in infinity).
    fn identity() -> Self::Point;

    /// Checks if the specified point is an identity point.
    fn is_identity(point: &Self::Point) -> bool;

    /// Returns the agreed-upon generator of the group aka basepoint.
    fn base_point() -> Self::Point;

    /// Serializes a point into a byte buffer.
    fn serialize_point(point: &Self::Point, output: &mut Vec<u8>);

    /// Deserializes a point from the byte buffer, which is guaranteed to have length
    /// [`Self::POINT_SIZE`].
    fn deserialize_point(input: &[u8]) -> Option<Self::Point>;
}

/// Prime-order group that can be used in ElGamal encryption and related applications.
///
/// This crate provides two implementations of this trait:
///
/// - [`Edwards`], representation of a prime-order subgroup of Ed25519 with the conventionally
///   chosen generator.
/// - [`Ristretto`], a transform of Ed25519 which eliminates its co-factor 8 with the help
///   of the [eponymous technique][ristretto].
///
/// [ristretto]: https://ristretto.group/
/// [`Edwards`]: enum.Edwards.html
/// [`Ristretto`]: enum.Ristretto.html
pub trait Group: Copy + ScalarOps + PointOps + 'static {
    /// Multiplies the provided scalar by [`PointOps::base_point()`]. This operation must be
    /// constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented using [`Mul`](ops::Mul) (which is constant-time as per the [`PointOps`]
    /// contract).
    fn scalar_mul_basepoint(k: &Self::Scalar) -> Self::Point {
        Self::base_point() * k
    }

    /// Multiplies the provided scalar by [`PointOps::base_point()`].
    /// Unlike [`Self::scalar_mul_basepoint()`], this operation does not need to be constant-time;
    /// thus, it may employ additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::scalar_mul_basepoint()`].
    #[inline]
    fn vartime_scalar_mul_basepoint(k: &Self::Scalar) -> Self::Point {
        Self::scalar_mul_basepoint(k)
    }

    /// Multiplies provided `scalars` by `points`. This operation must be constant-time
    /// w.r.t. the given length of elements.
    ///
    /// # Default implementation
    ///
    /// Implemented by straightforward computations, which are constant-time as per
    /// the [`PointOps`] contract.
    fn multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
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
    /// Implemented by straightforward computations.
    fn vartime_double_scalar_mul_basepoint(
        k: &Self::Scalar,
        k_point: Self::Point,
        r: &Self::Scalar,
    ) -> Self::Point {
        k_point * k + Self::base_point() * r
    }

    /// Multiplies provided `scalars` by `points`. Unlike [`Self::multiscalar_mul()`],
    /// this operation does not need to be constant-time; thus, it may employ
    /// additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by calling [`Self::multiscalar_mul()`].
    #[inline]
    fn vartime_multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        Self::multiscalar_mul(scalars, points)
    }
}
