use curve25519_dalek::traits::{Identity, IsIdentity};
use rand_core::{CryptoRng, RngCore};
use subtle::{ConditionallySelectable, ConstantTimeEq};

use std::{fmt, ops};

mod edwards;
mod ristretto;
pub use self::{edwards::Edwards, ristretto::Ristretto};

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const HASH_SIZE: usize = 64;

/// Helper trait for `Group` that describes operations on group scalars.
pub trait ScalarOps {
    /// Scalar type. Arithmetic operations should be constant-time.
    type Scalar: Copy
        + Default
        + From<u64>
        + PartialEq
        + ops::Neg<Output = Self::Scalar>
        + ops::Add<Output = Self::Scalar>
        + ops::Sub<Output = Self::Scalar>
        + ops::Mul<Output = Self::Scalar>
        + ConditionallySelectable
        + ::std::fmt::Debug;

    /// Generates a random scalar based on the provided CSPRNG.
    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar;

    fn scalar_from_random_bytes(bytes: [u8; 2 * SECRET_KEY_SIZE]) -> Self::Scalar;

    /// Inverts the scalar. If the scalar is zero, the method should panic.
    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar;

    /// Inverts scalars in a batch. The default implementation inverts every scalar successively.
    fn invert_scalars(scalars: &mut [Self::Scalar]) {
        for scalar in scalars {
            *scalar = Self::invert_scalar(*scalar);
        }
    }

    /// Serializes the scalar into a byte buffer.
    fn serialize_scalar(scalar: &Self::Scalar) -> [u8; SECRET_KEY_SIZE];

    /// Deserializes the scalar from the byte buffer. This method returns `None` if the buffer
    /// does not correspond to a representation of a valid scalar.
    fn deserialize_scalar(bytes: [u8; SECRET_KEY_SIZE]) -> Option<Self::Scalar>;
}

/// Helper trait for `Group` that describes operations on group elements (i.e., EC points).
pub trait PointOps: ScalarOps {
    /// Member of the group. Should define necessary arithmetic operations (addition among
    /// points and multiplication by a `Scalar`), which need to be constant-time.
    type Point: Copy
        + Identity
        + IsIdentity
        + ops::Add<Output = Self::Point>
        + ops::Sub<Output = Self::Point>
        + for<'a> ops::Mul<&'a Self::Scalar, Output = Self::Point>
        + ConditionallySelectable
        + ConstantTimeEq;

    /// Compressed presentation of a `Point`.
    type CompressedPoint: Copy + Eq + ::std::fmt::Debug;

    /// Agreed-upon generator of the group aka basepoint.
    const BASE_POINT: Self::Point;

    /// Converts a point to the compressed presentation.
    fn compress(point: &Self::Point) -> Self::CompressedPoint;

    /// Serializes a point into a byte buffer.
    fn serialize_point(point: &Self::CompressedPoint) -> [u8; PUBLIC_KEY_SIZE];

    /// Deserializes a point from the byte buffer.
    fn deserialize_point(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self::CompressedPoint;

    /// Decompresses the given compressed point into a full one. This operation may fail
    /// if compression does not correspond to a point in this group.
    fn decompress(compressed: &Self::CompressedPoint) -> Option<Self::Point>;
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
    /// Multiplies the provided scalar by `BASE_POINT`. This operation needs
    /// to be constant-time.
    fn scalar_mul_basepoint(k: &Self::Scalar) -> Self::Point {
        Self::BASE_POINT * k
    }

    fn multiscalar_mul<'a, I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        let mut output = Self::Point::identity();
        for (scalar, point) in scalars.into_iter().zip(points) {
            output = output + point * scalar;
        }
        output
    }

    /// Calculates `k * k_point + r * G`, where `G` is the group generator. This operation
    /// does not need to be constant-time.
    fn vartime_double_scalar_mul_basepoint(
        k: Self::Scalar,
        k_point: Self::Point,
        r: Self::Scalar,
    ) -> Self::Point {
        k_point * &k + Self::BASE_POINT * &r
    }

    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator<Item = Self::Scalar>,
        J: IntoIterator<Item = Self::Point>,
    {
        let mut output = Self::Point::identity();
        for (scalar, point) in scalars.into_iter().zip(points) {
            output = output + point * &scalar;
        }
        output
    }
}

#[derive(Debug)]
pub struct SecretKey<G: Group>(pub(crate) G::Scalar);

impl<G: Group> Clone for SecretKey<G> {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

impl<G: Group> SecretKey<G> {
    pub(crate) fn new(scalar: G::Scalar) -> Self {
        SecretKey(scalar)
    }

    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        SecretKey(G::generate_scalar(rng))
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_SIZE]) -> Option<Self> {
        G::deserialize_scalar(bytes).map(SecretKey)
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        G::serialize_scalar(&self.0)
    }
}

impl<G: Group> ops::Add for SecretKey<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        SecretKey(self.0 + rhs.0)
    }
}

impl<G: Group> ops::AddAssign for SecretKey<G> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl<G: Group> ops::Mul<G::Scalar> for SecretKey<G> {
    type Output = Self;

    fn mul(self, k: G::Scalar) -> Self {
        SecretKey(self.0 * k)
    }
}

impl<'a, G: Group> ops::Mul<G::Scalar> for &'a SecretKey<G> {
    type Output = SecretKey<G>;

    fn mul(self, k: G::Scalar) -> SecretKey<G> {
        SecretKey(self.0 * k)
    }
}

/// Public key in the signature scheme.
///
/// # Implementation details
///
/// We store both the compressed group point (which is what public key *is*
/// in most digital signature implementations) and its decompression into a group element.
/// This increases the memory footprint, but speeds up arithmetic on the keys.
pub struct PublicKey<G: Group> {
    pub(crate) compressed: G::CompressedPoint,
    pub(crate) full: G::Point,
}

impl<G: Group> Clone for PublicKey<G> {
    fn clone(&self) -> Self {
        PublicKey {
            compressed: self.compressed,
            full: self.full,
        }
    }
}

impl<G> fmt::Debug for PublicKey<G>
where
    G: Group,
    <G as PointOps>::CompressedPoint: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_tuple("PublicKey")
            .field(&self.compressed)
            .finish()
    }
}

impl<G> PartialEq for PublicKey<G>
where
    G: Group,
    <G as PointOps>::CompressedPoint: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.compressed == other.compressed
    }
}

impl<G: Group> Copy for PublicKey<G> {}

impl<G: Group> PublicKey<G> {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Option<Self> {
        let compressed = G::deserialize_point(bytes);
        G::decompress(&compressed)
            .filter(|point| !point.is_identity())
            .map(|full| PublicKey { compressed, full })
    }

    pub(crate) fn new(full: G::Point, compressed: G::CompressedPoint) -> Self {
        debug_assert!(G::compress(&full) == compressed);
        PublicKey { compressed, full }
    }

    pub(crate) fn from_point(full: G::Point) -> Self {
        PublicKey {
            full,
            compressed: G::compress(&full),
        }
    }

    pub fn from_secret(secret: &SecretKey<G>) -> Self {
        let point = G::BASE_POINT * &secret.0;
        PublicKey {
            compressed: G::compress(&point),
            full: point,
        }
    }

    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        G::serialize_point(&self.compressed)
    }
}

impl<G: Group> ops::Add<Self> for PublicKey<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let point = self.full + rhs.full;
        PublicKey {
            compressed: G::compress(&point),
            full: point,
        }
    }
}

impl<G: Group> ops::Mul<G::Scalar> for PublicKey<G> {
    type Output = Self;

    fn mul(self, k: G::Scalar) -> Self {
        let point = self.full * &k;
        PublicKey {
            compressed: G::compress(&point),
            full: point,
        }
    }
}

pub struct Keypair<G: Group> {
    secret: SecretKey<G>,
    public: PublicKey<G>,
}

impl<G: Group> Clone for Keypair<G> {
    fn clone(&self) -> Self {
        Keypair {
            secret: self.secret.clone(),
            public: self.public,
        }
    }
}

impl<G: Group> Keypair<G> {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = SecretKey::generate(rng);
        Keypair {
            public: PublicKey::from_secret(&secret),
            secret,
        }
    }

    pub fn from_secret(secret: SecretKey<G>) -> Self {
        Keypair {
            public: PublicKey::from_secret(&secret),
            secret,
        }
    }

    pub fn from_bytes(bytes: [u8; SECRET_KEY_SIZE]) -> Option<Self> {
        SecretKey::from_bytes(bytes).map(Self::from_secret)
    }

    pub fn public(&self) -> PublicKey<G> {
        self.public
    }

    pub fn secret(&self) -> &SecretKey<G> {
        &self.secret
    }

    pub fn into_tuple(self) -> (PublicKey<G>, SecretKey<G>) {
        (self.public, self.secret)
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.secret.to_bytes()
    }
}

impl<G: Group> ops::Mul<G::Scalar> for Keypair<G> {
    type Output = Self;

    fn mul(self, k: G::Scalar) -> Self {
        Keypair {
            secret: self.secret * k,
            public: self.public * k,
        }
    }
}
