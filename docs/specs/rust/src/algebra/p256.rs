use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use num_bigint::BigInt;
use num_traits::One;

use super::{Field, FieldError, Rng, Subfield};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct P256Subfield;

impl Subfield<P256> for P256Subfield {
    fn reed_solomon_eval_point(&self, x: usize) -> P256 {
        P256::new(BigInt::from(x))
    }

    fn subfield_serialized_size(&self) -> usize {
        32
    }

    fn to_subfield_bytes(&self, val: P256) -> Vec<u8> {
        val.to_bytes()
    }

    fn from_subfield_bytes(&self, bytes: &[u8]) -> Result<P256, FieldError> {
        P256::from_bytes(bytes)
    }

    fn contains_subfield(&self, _val: P256) -> bool {
        true
    }

    fn sample<R: Rng>(&self, rng: &mut R) -> P256 {
        sample_p256(rng)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256 {
    pub v: [u8; 32],
}

impl P256 {
    pub fn prime() -> BigInt {
        BigInt::parse_bytes(
            b"115792089210356248762697446949407573530086143415290314195533631308867097853951",
            10,
        )
        .unwrap()
    }

    pub fn new(val: BigInt) -> Self {
        let p = Self::prime();
        let val_mod = ((val % &p) + &p) % p;
        let (_, bytes) = val_mod.to_bytes_le();
        let mut v = [0u8; 32];
        v[..bytes.len()].copy_from_slice(&bytes);
        Self { v }
    }

    pub fn to_bigint(&self) -> BigInt {
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &self.v)
    }
}

impl Add for P256 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self::new(self.to_bigint() + other.to_bigint())
    }
}

impl Sub for P256 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self::new(self.to_bigint() - other.to_bigint())
    }
}

impl Mul for P256 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        Self::new(self.to_bigint() * other.to_bigint())
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for P256 {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}

impl Neg for P256 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self::zero() - self
    }
}

impl AddAssign for P256 {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl SubAssign for P256 {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl MulAssign for P256 {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Field for P256 {
    type Subfield = P256Subfield;

    fn zero() -> Self {
        Self { v: [0u8; 32] }
    }

    fn one() -> Self {
        Self::new(BigInt::one())
    }

    fn is_zero(&self) -> bool {
        self.v == [0u8; 32]
    }

    fn is_one(&self) -> bool {
        *self == Self::one()
    }

    fn inv(&self) -> Self {
        assert!(!self.is_zero(), "cannot invert zero");
        let p = Self::prime();
        self.pow(&(p - BigInt::from(2)))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.v.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError> {
        if bytes.len() != 32 {
            return Err(FieldError::InvalidLength);
        }
        let val = BigInt::from_bytes_le(num_bigint::Sign::Plus, bytes);
        if val >= Self::prime() {
            return Err(FieldError::ValueOutOfRange);
        }
        let mut v = [0u8; 32];
        v.copy_from_slice(bytes);
        Ok(Self { v })
    }

    fn serialized_size() -> usize {
        32
    }

    fn sumcheck_eval_points() -> Vec<Self> {
        vec![Self::zero(), Self::one(), Self::new(BigInt::from(2))]
    }

    fn sample<R: Rng>(rng: &mut R) -> Self {
        sample_p256(rng)
    }
}

pub fn sample_p256<R: Rng>(rng: &mut R) -> P256 {
    let p = P256::prime();
    loop {
        let b = rng.bytes(32);
        let val = BigInt::from_bytes_le(num_bigint::Sign::Plus, &b);
        if val < p {
            return P256::new(val);
        }
    }
}
