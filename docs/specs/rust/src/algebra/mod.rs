use num_bigint::BigInt;
use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

pub mod blas;
pub mod gf2_128;
pub mod interpolation;
pub mod p256;
pub mod random;

pub use blas::*;
pub use gf2_128::{BinarySubfield, Gf2_128, sample_gf2_128};
pub use interpolation::{lagrange_basis, lagrange_matrix};
pub use p256::{P256, P256Subfield, sample_p256};
pub use random::*;

pub fn ceil_lg2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (usize::BITS - (n - 1).leading_zeros()) as usize
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FieldError {
    InvalidLength,
    ValueOutOfRange,
    InvalidSubfield,
}

impl std::fmt::Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldError::InvalidLength => write!(f, "Invalid byte length for field element"),
            FieldError::ValueOutOfRange => write!(f, "Field element value out of range"),
            FieldError::InvalidSubfield => write!(f, "Invalid subfield element byte encoding"),
        }
    }
}

impl std::error::Error for FieldError {}

pub trait Subfield<F: Field>:
    Default + Clone + PartialEq + Eq + std::fmt::Debug + Send + Sync + 'static
{
    fn reed_solomon_eval_point(&self, x: usize) -> F;
    fn subfield_serialized_size(&self) -> usize;
    fn to_subfield_bytes(&self, val: F) -> Vec<u8>;
    fn from_subfield_bytes(&self, bytes: &[u8]) -> Result<F, FieldError>;
    fn contains_subfield(&self, val: F) -> bool;
    fn sample<R: Rng>(&self, rng: &mut R) -> F;
}

pub trait Field:
    Sized
    + Clone
    + Copy
    + PartialEq
    + Eq
    + std::fmt::Debug
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Neg<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + Send
    + Sync
    + 'static
{
    type Subfield: Subfield<Self>;

    fn zero() -> Self;
    fn one() -> Self;
    fn mone() -> Self {
        Self::zero() - Self::one()
    }
    fn is_zero(&self) -> bool;
    fn is_one(&self) -> bool;
    fn inv(&self) -> Self;
    fn pow(&self, exp: &BigInt) -> Self {
        use num_traits::{One, Zero};
        let mut res = Self::one();
        let mut base = *self;
        let mut e = exp.clone();
        let zero = BigInt::zero();
        let one_bi = BigInt::one();
        while e > zero {
            if (&e & &one_bi) == one_bi {
                res *= base;
            }
            base *= base;
            e >>= 1;
        }
        res
    }
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError>;
    fn serialized_size() -> usize;

    fn sumcheck_eval_points() -> Vec<Self>;
    fn sample<R: Rng>(rng: &mut R) -> Self;
}
