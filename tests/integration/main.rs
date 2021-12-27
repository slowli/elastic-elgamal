//! Generic tests independent of the `Group` implementation.

use subtle::ConstantTimeEq;

use std::fmt;

mod basic;
mod sharing;

// TODO: test quadratic voting

pub fn assert_ct_eq<T: ConstantTimeEq + fmt::Debug>(x: &T, y: &T) {
    assert!(
        bool::from(x.ct_eq(y)),
        "Values are not equal: {:?}, {:?}",
        x,
        y
    );
}
