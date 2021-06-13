use elliptic_curve::{
    consts::U1,
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    sec1::{
        EncodedPoint, FromEncodedPoint, ToEncodedPoint, UncompressedPointSize, UntaggedPointSize,
    },
    weierstrass::Curve as WeierstrassCurve,
    Field, FieldSize, Group, ProjectiveArithmetic, ProjectivePoint, Scalar,
};
use ff::PrimeField;
use rand_core::{CryptoRng, RngCore};

use std::{marker::PhantomData, ops};

use super::{PointOps, ScalarOps};

#[derive(Debug)]
pub struct Generic<C>(PhantomData<C>);

impl<C> Clone for Generic<C> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<C> Copy for Generic<C> {}

impl<C: ProjectiveArithmetic> ScalarOps for Generic<C> {
    type Scalar = Scalar<C>;

    const SCALAR_SIZE: usize = <FieldSize<C> as Unsigned>::USIZE;

    fn generate_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Self::Scalar {
        Scalar::<C>::random(rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap()
    }

    fn serialize_scalar(scalar: &Self::Scalar, output: &mut Vec<u8>) {
        output.extend_from_slice(scalar.to_repr().as_ref());
    }

    fn deserialize_scalar(bytes: &[u8]) -> Option<Self::Scalar> {
        // FIXME: avoid cloning here
        Scalar::<C>::from_repr(GenericArray::from_slice(bytes).clone())
    }
}

impl<C> PointOps for Generic<C>
where
    C: ProjectiveArithmetic + WeierstrassCurve,
    UntaggedPointSize<C>: ops::Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    ProjectivePoint<C>: ToEncodedPoint<C> + FromEncodedPoint<C>,
{
    type Point = ProjectivePoint<C>;

    const POINT_SIZE: usize = <UntaggedPointSize<C> as Unsigned>::USIZE + 1;

    fn identity() -> Self::Point {
        C::ProjectivePoint::identity()
    }

    fn is_identity(point: &Self::Point) -> bool {
        point.is_identity().into()
    }

    fn base_point() -> Self::Point {
        C::ProjectivePoint::generator()
    }

    fn serialize_point(point: &Self::Point, output: &mut Vec<u8>) {
        let encoded_point = point.to_encoded_point(true);
        output.extend_from_slice(encoded_point.as_bytes())
    }

    fn deserialize_point(input: &[u8]) -> Option<Self::Point> {
        let encoded_point = EncodedPoint::<C>::from_bytes(input).ok()?;
        ProjectivePoint::<C>::from_encoded_point(&encoded_point)
    }
}

impl<C> super::Group for Generic<C>
where
    C: ProjectiveArithmetic + WeierstrassCurve + 'static,
    UntaggedPointSize<C>: ops::Add<U1> + ArrayLength<u8>,
    UncompressedPointSize<C>: ArrayLength<u8>,
    ProjectivePoint<C>: ToEncodedPoint<C> + FromEncodedPoint<C>,
{
}
