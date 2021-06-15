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
    /// [`Self::BYTE_SIZE`].
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
    /// Multiplies the provided scalar by [`Self::base_point()`]. This operation must be
    /// constant-time.
    ///
    /// # Default implementation
    ///
    /// Implemented by multiplying [`Self::base_point()`] by `k` (which is constant-time as
    /// per the [`PointOps`] contract).
    fn scalar_mul_basepoint(k: &Self::Scalar) -> Self::Point {
        Self::base_point() * k
    }

    /// Multiplies the provided scalar by [`Self::base_point()`].
    /// Unlike [`Self::scalar_mul_basepoint()`], this operation does not need to be constant-time;
    /// thus, it may employ additional optimizations.
    ///
    /// # Default implementation
    ///
    /// Implemented by multiplying [`Self::base_point()`] by `k`.
    fn vartime_scalar_mul_basepoint(k: &Self::Scalar) -> Self::Point {
        Self::base_point() * k
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

/// Secret key for ElGamal encryption and related protocols. This is a thin wrapper around
/// the [`Group`] scalar.
// TODO: zeroize?
pub struct SecretKey<G: Group>(pub(crate) G::Scalar);

impl<G: Group> fmt::Debug for SecretKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_struct("SecretKey")
            .field("public", &PublicKey::from(self))
            .finish()
    }
}

impl<G: Group> Clone for SecretKey<G> {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

impl<G: Group> SecretKey<G> {
    pub(crate) fn new(scalar: G::Scalar) -> Self {
        SecretKey(scalar)
    }

    /// Generates a random secret key.
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        SecretKey(G::generate_scalar(rng))
    }

    /// Deserializes a secret key from bytes. If bytes do not represent a valid scalar,
    /// returns `None`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G::SCALAR_SIZE {
            return None;
        }
        G::deserialize_scalar(bytes).map(SecretKey)
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

impl<G: Group> ops::Mul<G::Scalar> for &SecretKey<G> {
    type Output = SecretKey<G>;

    fn mul(self, k: G::Scalar) -> SecretKey<G> {
        SecretKey(self.0 * k)
    }
}

/// Public key for ElGamal encryption and related protocols.
///
/// # Implementation details
///
/// We store both the original bytes (which are used in zero-knowledge proofs)
/// and its decompression into a group element.
/// This increases the memory footprint, but speeds up arithmetic on the keys.
pub struct PublicKey<G: Group> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) full: G::Point,
}

impl<G: Group> Clone for PublicKey<G> {
    fn clone(&self) -> Self {
        PublicKey {
            bytes: self.bytes.clone(),
            full: self.full,
        }
    }
}

impl<G: Group> fmt::Debug for PublicKey<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter
            .debug_tuple("PublicKey")
            .field(&hex::encode(&self.bytes))
            .finish()
    }
}

impl<G> PartialEq for PublicKey<G>
where
    G: Group,
{
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<G: Group> PublicKey<G> {
    /// Deserializes a public key from bytes. If the bytes do not represent a valid [`Group`]
    /// element, returns `None`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G::POINT_SIZE {
            return None;
        }

        G::deserialize_point(bytes)
            .filter(|point| !G::is_identity(point))
            .map(|full| PublicKey {
                bytes: bytes.to_vec(),
                full,
            })
    }

    pub(crate) fn from_point(full: G::Point) -> Self {
        let mut point_bytes = Vec::with_capacity(G::POINT_SIZE);
        G::serialize_point(&full, &mut point_bytes);
        PublicKey {
            full,
            bytes: point_bytes,
        }
    }

    /// Returns bytes representing the group element corresponding to this key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<G: Group> From<&SecretKey<G>> for PublicKey<G> {
    fn from(secret_key: &SecretKey<G>) -> Self {
        let point = G::scalar_mul_basepoint(&secret_key.0);
        Self::from_point(point)
    }
}

impl<G: Group> ops::Add<Self> for PublicKey<G> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let point = self.full + rhs.full;
        Self::from_point(point)
    }
}

impl<G: Group> ops::Mul<G::Scalar> for PublicKey<G> {
    type Output = Self;

    fn mul(self, k: G::Scalar) -> Self {
        let point = self.full * &k;
        Self::from_point(point)
    }
}

/// Keypair for ElGamal encryption and related protocols, consisting of a [`SecretKey`]
/// and the matching [`PublicKey`].
pub struct Keypair<G: Group> {
    secret: SecretKey<G>,
    public: PublicKey<G>,
}

impl<G: Group> fmt::Debug for Keypair<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keypair")
            .field("public", &self.public)
            .finish()
    }
}

impl<G: Group> Clone for Keypair<G> {
    fn clone(&self) -> Self {
        Keypair {
            secret: self.secret.clone(),
            public: self.public.clone(),
        }
    }
}

impl<G: Group> Keypair<G> {
    /// Generates a random keypair.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = SecretKey::generate(rng);
        Keypair {
            public: PublicKey::from(&secret),
            secret,
        }
    }

    /// Returns the public part of this keypair.
    pub fn public(&self) -> &PublicKey<G> {
        &self.public
    }

    /// Returns the secret part of this keypair.
    pub fn secret(&self) -> &SecretKey<G> {
        &self.secret
    }

    /// Returns public and secret keys comprising this keypair.
    pub fn into_tuple(self) -> (PublicKey<G>, SecretKey<G>) {
        (self.public, self.secret)
    }
}

impl<G: Group> From<SecretKey<G>> for Keypair<G> {
    fn from(secret: SecretKey<G>) -> Self {
        Self {
            public: PublicKey::from(&secret),
            secret,
        }
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
