// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use super::{Field, FieldError, Rng, Subfield};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gf2_128 {
    pub v: u128,
}

fn clmul_reduce(a: u128, b: u128) -> u128 {
    let mut res = 0u128;
    let mut temp = b;
    for i in 0..128 {
        if ((a >> i) & 1) == 1 {
            res ^= temp;
        }
        let overflow = (temp >> 127) & 1;
        temp <<= 1;
        if overflow == 1 {
            temp ^= 0x87;
        }
    }
    res
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Gf2_128 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self {
            v: self.v ^ other.v,
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for Gf2_128 {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Self {
            v: self.v ^ other.v,
        }
    }
}

impl Mul for Gf2_128 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        Self {
            v: clmul_reduce(self.v, other.v),
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Gf2_128 {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}

impl Neg for Gf2_128 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        self
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl AddAssign for Gf2_128 {
    fn add_assign(&mut self, other: Self) {
        self.v ^= other.v;
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl SubAssign for Gf2_128 {
    fn sub_assign(&mut self, other: Self) {
        self.v ^= other.v;
    }
}

impl MulAssign for Gf2_128 {
    fn mul_assign(&mut self, other: Self) {
        self.v = clmul_reduce(self.v, other.v);
    }
}

impl Field for Gf2_128 {
    type Subfield = BinarySubfield;

    fn zero() -> Self {
        Self { v: 0 }
    }

    fn one() -> Self {
        Self { v: 1 }
    }

    fn is_zero(&self) -> bool {
        self.v == 0
    }

    fn is_one(&self) -> bool {
        self.v == 1
    }

    fn inv(&self) -> Self {
        assert!(!self.is_zero(), "cannot invert zero");
        self.pow_u128(u128::MAX - 1)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.v.to_le_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, FieldError> {
        if bytes.len() != 16 {
            return Err(FieldError::InvalidLength);
        }
        let mut v_bytes = [0u8; 16];
        v_bytes.copy_from_slice(bytes);
        Ok(Self {
            v: u128::from_le_bytes(v_bytes),
        })
    }

    fn serialized_size() -> usize {
        16
    }

    fn sumcheck_eval_points() -> Vec<Self> {
        vec![
            Self::zero(),
            Self::one(),
            Self {
                v: SUBFIELD_BASIS[1],
            },
        ]
    }

    fn sample<R: Rng>(rng: &mut R) -> Self {
        sample_gf2_128(rng)
    }
}

impl Gf2_128 {
    pub fn pow_u128(&self, exp: u128) -> Self {
        let mut res = Self::one();
        let mut base = *self;
        let mut e = exp;
        while e > 0 {
            if (e & 1) == 1 {
                res *= base;
            }
            base *= base;
            e >>= 1;
        }
        res
    }
}

pub fn sample_gf2_128<R: Rng>(rng: &mut R) -> Gf2_128 {
    let b = rng.bytes(16);
    Gf2_128::from_bytes(&b).expect("valid 16 bytes")
}

const SUBFIELD_BASIS: [u128; 16] = [
    0x1,
    0x5c5971877501d4b8f1871e01b64fda4c,
    0x8bb99658eaf2cae0a6e310fb6e176ea8,
    0xb61e08da12f9665c3f8de8a2f9ff7eed,
    0xa76c2e634c6483ae9ba3282087a3f827,
    0x54944ff4a5269cedf7af4e93629f689e,
    0x5439ecfd75a950d8d0765f1873309b88,
    0x49ecdfbe06777b02e566f9fc3d9b58a2,
    0x97a401b733e66a9319af205497f8e2d0,
    0x789fd7793ce7523860e4dbdce9777814,
    0xaa440b2d4b546256c0f157187adbc05b,
    0x79f2cadb70b6115d222f207d0d8ad9f9,
    0xae72af7894ce037df6d1f84fb66c52b8,
    0xd6f226d783d454db4af94ef056d28a30,
    0x057d918d494925fc0f37a0a4d91b4220,
    0x18d4bbb6833c5ae8b683012350e55753,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinarySubfield {
    pub basis: Vec<Gf2_128>,
    pub dimension: usize,
}

impl Default for BinarySubfield {
    fn default() -> Self {
        Self::new()
    }
}

impl BinarySubfield {
    pub fn new() -> Self {
        let basis = SUBFIELD_BASIS.map(|v| Gf2_128 { v }).to_vec();
        Self {
            basis,
            dimension: 16,
        }
    }

    pub fn solve_subfield(&self, e: Gf2_128) -> Option<u64> {
        let mut rows = [0u32; 128];
        for j in 0..self.dimension {
            let bv = self.basis[j].v;
            for r in 0..128 {
                if ((bv >> r) & 1) == 1 {
                    rows[r] |= 1 << j;
                }
            }
        }
        let ev = e.v;
        for r in 0..128 {
            if ((ev >> r) & 1) == 1 {
                rows[r] |= 1 << self.dimension;
            }
        }

        rref_solve(&mut rows, self.dimension)
    }
}

fn rref_solve(rows: &mut [u32; 128], cols: usize) -> Option<u64> {
    let mut pivot_cols = vec![None; cols];
    let mut r_idx = 0;
    for c in 0..cols {
        let pivot_row = (r_idx..128).find(|&r| ((rows[r] >> c) & 1) == 1);
        if let Some(p_row) = pivot_row {
            rows.swap(r_idx, p_row);
            for r in 0..128 {
                if r != r_idx && ((rows[r] >> c) & 1) == 1 {
                    rows[r] ^= rows[r_idx];
                }
            }
            pivot_cols[c] = Some(r_idx);
            r_idx += 1;
        }
    }

    for &row_val in &rows[r_idx..128] {
        if ((row_val >> cols) & 1) == 1 {
            return None;
        }
    }

    let mut sol = 0u64;
    for c in 0..cols {
        if let Some(ridx) = pivot_cols[c] {
            if ((rows[ridx] >> cols) & 1) == 1 {
                sol |= 1 << c;
            }
        }
    }
    Some(sol)
}

impl Subfield<Gf2_128> for BinarySubfield {
    fn reed_solomon_eval_point(&self, x: usize) -> Gf2_128 {
        let mut res = Gf2_128::zero();
        for i in 0..16 {
            if ((x >> i) & 1) == 1 {
                res += self.basis[i];
            }
        }
        res
    }

    fn subfield_serialized_size(&self) -> usize {
        2
    }

    fn to_subfield_bytes(&self, val: Gf2_128) -> Vec<u8> {
        let sol = self.solve_subfield(val).expect("element not in subfield");
        vec![(sol & 0xff) as u8, ((sol >> 8) & 0xff) as u8]
    }

    fn from_subfield_bytes(&self, bytes: &[u8]) -> Result<Gf2_128, FieldError> {
        if bytes.len() != 2 {
            return Err(FieldError::InvalidLength);
        }
        let val = (bytes[0] as u16) | ((bytes[1] as u16) << 8);
        let mut res = Gf2_128::zero();
        for i in 0..16 {
            if ((val >> i) & 1) == 1 {
                res += self.basis[i];
            }
        }
        Ok(res)
    }

    fn contains_subfield(&self, val: Gf2_128) -> bool {
        self.solve_subfield(val).is_some()
    }

    fn sample<R: Rng>(&self, rng: &mut R) -> Gf2_128 {
        let b = rng.bytes(2);
        self.from_subfield_bytes(&b).expect("valid subfield bytes")
    }
}
