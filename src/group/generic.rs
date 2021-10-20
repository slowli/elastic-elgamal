use elliptic_curve::{
    consts::U1,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    sec1::{
        EncodedPoint, FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize,
    },
    weierstrass::Curve as WeierstrassCurve,
    Field, FieldSize, Group as _, ProjectiveArithmetic, ProjectivePoint, Scalar,
};
use ff::PrimeField;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use std::{marker::PhantomData, ops};

use super::{ElementOps, Group, ScalarOps};

/// Generic [`Group`] implementation for elliptic curves defined in terms of the traits
/// from the [`elliptic-curve`] crate.
///
/// # Assumptions
///
/// - Arithmetic operations required to be constant-time as per [`ScalarOps`] and [`ElementOps`]
///   contracts are indeed constant-time.
///
/// [`elliptic-curve`]: https://docs.rs/elliptic-curve/
#[derive(Debug)]
pub struct Generic<C>(PhantomData<C>);

impl<C> Clone for Generic<C> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C> Copy for Generic<C> {}

impl<C> ScalarOps for Generic<C>
where
    C: ProjectiveArithmetic,
    Scalar<C>: Zeroize,
{
    type Scalar = Scalar<C>;

    const SCALAR_SIZE: usize = <FieldSize<C> as Unsigned>::USIZE;

    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
        Scalar::<C>::random(rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap()
    }

    fn serialize_scalar(scalar: &Self::Scalar, buffer: &mut [u8]) {
        buffer.copy_from_slice(scalar.to_repr().as_ref());
    }

    fn deserialize_scalar(buffer: &[u8]) -> Option<Self::Scalar> {
        // For most curves, cloning will be resolved as a copy.
        Scalar::<C>::from_repr(GenericArray::from_slice(buffer).clone())
    }
}

impl<C> ElementOps for Generic<C>
where
    C: ProjectiveArithmetic + WeierstrassCurve,
    Scalar<C>: Zeroize,
    UntaggedPointSize<C>: ops::Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    ProjectivePoint<C>: ToEncodedPoint<C> + FromEncodedPoint<C>,
{
    type Element = ProjectivePoint<C>;

    const ELEMENT_SIZE: usize = <FieldSize<C> as Unsigned>::USIZE + 1;

    #[inline]
    fn identity() -> Self::Element {
        C::ProjectivePoint::identity()
    }

    #[inline]
    fn is_identity(element: &Self::Element) -> bool {
        element.is_identity().into()
    }

    #[inline]
    fn generator() -> Self::Element {
        C::ProjectivePoint::generator()
    }

    fn serialize_element(element: &Self::Element, buffer: &mut [u8]) {
        let encoded_point = element.to_encoded_point(true);
        buffer.copy_from_slice(encoded_point.as_bytes());
    }

    fn deserialize_element(input: &[u8]) -> Option<Self::Element> {
        let encoded_point = EncodedPoint::<C>::from_bytes(input).ok()?;
        ProjectivePoint::<C>::from_encoded_point(&encoded_point)
    }
}

impl<C> Group for Generic<C>
where
    C: ProjectiveArithmetic + WeierstrassCurve + 'static,
    Scalar<C>: Zeroize,
    UntaggedPointSize<C>: ops::Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    ProjectivePoint<C>: ToEncodedPoint<C> + FromEncodedPoint<C>,
{
    // Default implementations are fine.
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;

    type K256 = Generic<k256::Secp256k1>;

    #[test]
    fn scalar_roundtrip() {
        let mut rng = thread_rng();
        let mut buffer = vec![0_u8; K256::SCALAR_SIZE];
        for _ in 0..100 {
            let scalar = K256::generate_scalar(&mut rng);
            K256::serialize_scalar(&scalar, &mut buffer);
            assert_eq!(K256::deserialize_scalar(&buffer).unwrap(), scalar);
        }
    }

    #[test]
    fn point_roundtrip() {
        let mut rng = thread_rng();
        let mut buffer = vec![0_u8; K256::ELEMENT_SIZE];
        for _ in 0..100 {
            let point = K256::mul_generator(&K256::generate_scalar(&mut rng));
            K256::serialize_element(&point, &mut buffer);
            assert_eq!(K256::deserialize_element(&buffer).unwrap(), point);
        }
    }
}
