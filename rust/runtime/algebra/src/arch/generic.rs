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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Gf2_128(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gf2_128Accum(pub Gf2_128);

impl Gf2_128 {
    #[inline(always)]
    pub const fn from_u128(v: u128) -> Self {
        Self(v)
    }

    #[inline(always)]
    pub const fn to_u128(&self) -> u128 {
        self.0
    }

    #[inline(always)]
    pub fn xor_in_place(&mut self, other: &Self) {
        self.0 ^= other.0;
    }

    #[inline(always)]
    pub fn xor(&self, other: &Self) -> Self {
        Self(self.0 ^ other.0)
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

#[inline(always)]
fn clmul64(x: u64, y: u64) -> (u64, u64) {
    let lo = clmul64_lo(x, y);
    let hi = clmul64_hi(x, y);
    (lo, hi)
}

#[inline(always)]
fn clmul64_hi(x: u64, y: u64) -> u64 {
    clmul64_lo(x.reverse_bits(), y.reverse_bits()).reverse_bits() >> 1
}

#[inline(always)]
fn clmul64_lo(x: u64, y: u64) -> u64 {
    let m0 = 0x1111111111111111u64;
    let m1 = 0x2222222222222222u64;
    let m2 = 0x4444444444444444u64;
    let m3 = 0x8888888888888888u64;

    let x0 = x & m0;
    let x1 = x & m1;
    let x2 = x & m2;
    let x3 = x & m3;
    let y0 = y & m0;
    let y1 = y & m1;
    let y2 = y & m2;
    let y3 = y & m3;

    let z0 = x0.wrapping_mul(y0) ^ x1.wrapping_mul(y3) ^ x2.wrapping_mul(y2) ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1) ^ x1.wrapping_mul(y0) ^ x2.wrapping_mul(y3) ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2) ^ x1.wrapping_mul(y1) ^ x2.wrapping_mul(y0) ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3) ^ x1.wrapping_mul(y2) ^ x2.wrapping_mul(y1) ^ x3.wrapping_mul(y0);

    (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)
}

#[inline(always)]
fn gf2_128_reduce(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    let (a0, a1) = a;
    let (b0, b1) = b;
    let r0 = a0 ^ b1 ^ (b1 << 1) ^ (b1 << 2) ^ (b1 << 7);
    let r1 = a1 ^ b0 ^ (b1 >> 63) ^ (b1 >> 62) ^ (b1 >> 57);
    (r0, r1)
}

#[inline(always)]
pub fn gf2_128_mul(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    let x_v0 = x.0 as u64;
    let x_v1 = (x.0 >> 64) as u64;
    let y_v0 = y.0 as u64;
    let y_v1 = (y.0 >> 64) as u64;

    let t0 = clmul64(x_v0, y_v0);
    let t2 = clmul64(x_v1, y_v1);
    let t1 = clmul64(x_v0 ^ x_v1, y_v0 ^ y_v1);

    let t1_xor = (t1.0 ^ t0.0 ^ t2.0, t1.1 ^ t0.1 ^ t2.1);
    let t1_red = gf2_128_reduce(t1_xor, t2);
    let t0_red = gf2_128_reduce(t0, t1_red);

    Gf2_128(t0_red.0 as u128 | ((t0_red.1 as u128) << 64))
}

#[inline(always)]
pub fn gf2_128_mac(acc: &mut Gf2_128Accum, x: &Gf2_128, y: &Gf2_128) {
    let res = gf2_128_mul(*x, *y);
    acc.0 .0 ^= res.0;
}

#[inline(always)]
pub fn gf2_128_add_accum(a: &mut Gf2_128Accum, b: &Gf2_128Accum) {
    a.0 .0 ^= b.0 .0;
}

#[inline(always)]
pub fn gf2_128_accum_reduce(acc: &Gf2_128Accum) -> Gf2_128 {
    acc.0
}

#[inline(always)]
pub fn cmovne<const N: usize>(
    a: &mut [crate::limb::Limb; N],
    x: crate::limb::Limb,
    y: crate::limb::Limb,
    b: &[crate::limb::Limb; N],
) {
    let mask = (x != y) as u64;
    let mask = (0u64.wrapping_sub(mask)) as crate::limb::Limb;
    for i in 0..N {
        a[i] = (a[i] & !mask) | (b[i] & mask);
    }
}

#[inline(always)]
pub fn cmovnz<const N: usize>(
    a: &mut [crate::limb::Limb; N],
    nz: crate::limb::Limb,
    b: &[crate::limb::Limb; N],
) {
    cmovne(a, nz, 0, b);
}
pub use cmovnz as cmovzn;

#[inline(always)]
pub fn zero_but_you_dont_know_it() -> crate::limb::Limb {
    0 as crate::limb::Limb
}



