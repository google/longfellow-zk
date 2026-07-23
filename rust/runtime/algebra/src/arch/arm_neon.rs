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

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Gf2_128(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gf2_128Accum(pub [Gf2_128; 3]);

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

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn unzip_p8(a: poly8x16_t, b: poly8x16_t) -> (poly8x16_t, poly8x16_t) {
    let res = vuzpq_p8(a, b);
    (res.0, res.1)
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn unzip_p8(a: poly8x16_t, b: poly8x16_t) -> (poly8x16_t, poly8x16_t) {
    (vuzp1q_p8(a, b), vuzp2q_p8(a, b))
}

#[inline(always)]
unsafe fn xor_p8(a: poly8x16_t, b: poly8x16_t) -> poly8x16_t {
    vreinterpretq_p8_u8(veorq_u8(vreinterpretq_u8_p8(a), vreinterpretq_u8_p8(b)))
}

#[inline(always)]
unsafe fn ext_p8<const N: i32>(a: poly8x16_t, b: poly8x16_t) -> poly8x16_t {
    vreinterpretq_p8_u8(vextq_u8::<N>(
        vreinterpretq_u8_p8(a),
        vreinterpretq_u8_p8(b),
    ))
}

#[inline(always)]
unsafe fn dup_p8(val: u8) -> poly8x8_t {
    vreinterpret_p8_u8(vdup_n_u8(val))
}

#[inline(always)]
unsafe fn dupq_p8(val: u8) -> poly8x16_t {
    vreinterpretq_p8_u8(vdupq_n_u8(val))
}

#[inline(always)]
unsafe fn mull_p8(a: poly8x8_t, b: poly8x8_t) -> poly8x16_t {
    vreinterpretq_p8_p16(vmull_p8(a, b))
}

#[inline(always)]
unsafe fn pmac64x8(cin: poly8x16_t, x: poly8x8_t, y: u8) -> (poly8x16_t, poly8x16_t) {
    let zero = dupq_p8(0);
    let prod = mull_p8(x, dup_p8(y));
    let (mut uzp0, uzp1) = unzip_p8(prod, zero);
    uzp0 = xor_p8(uzp0, cin);
    (uzp0, uzp1)
}

#[inline(always)]
unsafe fn pmul64x8(x: poly8x8_t, y: u8) -> poly8x16_t {
    let zero = dupq_p8(0);
    let prod = mull_p8(x, dup_p8(y));
    let (uzp0, uzp1) = unzip_p8(prod, zero);
    xor_p8(uzp0, ext_p8::<15>(uzp1, uzp1))
}

#[inline(always)]
unsafe fn u64_to_poly8x8(v: u64) -> poly8x8_t {
    core::mem::transmute::<[u8; 8], poly8x8_t>(v.to_le_bytes())
}

#[inline(always)]
unsafe fn poly8x16_to_u128(v: poly8x16_t) -> u128 {
    let bytes: [u8; 16] = core::mem::transmute(v);
    u128::from_le_bytes(bytes)
}

#[inline(always)]
unsafe fn pmul64x64(x: poly8x8_t, y: poly8x8_t) -> poly8x16_t {
    let y_bytes: [u8; 8] = core::mem::transmute(y);
    let mut r = dupq_p8(0);

    let mut prod = pmac64x8(r, x, y_bytes[0]);
    r = prod.0;

    prod = pmac64x8(prod.1, x, y_bytes[1]);
    r = xor_p8(r, ext_p8::<15>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[2]);
    r = xor_p8(r, ext_p8::<14>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[3]);
    r = xor_p8(r, ext_p8::<13>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[4]);
    r = xor_p8(r, ext_p8::<12>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[5]);
    r = xor_p8(r, ext_p8::<11>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[6]);
    r = xor_p8(r, ext_p8::<10>(prod.0, prod.0));

    prod = pmac64x8(prod.1, x, y_bytes[7]);
    r = xor_p8(r, ext_p8::<9>(prod.0, prod.0));
    r = xor_p8(r, ext_p8::<8>(prod.1, prod.1));

    r
}

#[inline(always)]
unsafe fn reduce_128(mut z0: u128, mut z12: u128, z3: u128) -> Gf2_128 {
    let z3_hi: poly8x8_t = u64_to_poly8x8((z3 >> 64) as u64);
    let p3: u128 = poly8x16_to_u128(pmul64x8(z3_hi, 0x87));
    z12 ^= (z3 << 64) ^ p3;

    let z12_hi: poly8x8_t = u64_to_poly8x8((z12 >> 64) as u64);
    let p12: u128 = poly8x16_to_u128(pmul64x8(z12_hi, 0x87));
    z0 ^= (z12 << 64) ^ p12;

    Gf2_128(z0)
}

#[inline(always)]
pub fn gf2_128_mul(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    unsafe {
        let x0: poly8x8_t = u64_to_poly8x8(x.0 as u64);
        let x1: poly8x8_t = u64_to_poly8x8((x.0 >> 64) as u64);
        let y0: poly8x8_t = u64_to_poly8x8(y.0 as u64);
        let y1: poly8x8_t = u64_to_poly8x8((y.0 >> 64) as u64);

        let z0: u128 = poly8x16_to_u128(pmul64x64(x0, y0));
        let z1: u128 = poly8x16_to_u128(pmul64x64(x0, y1));
        let z2: u128 = poly8x16_to_u128(pmul64x64(x1, y0));
        let z3: u128 = poly8x16_to_u128(pmul64x64(x1, y1));

        reduce_128(z0, z1 ^ z2, z3)
    }
}

#[inline(always)]
pub fn gf2_128_mac(acc: &mut Gf2_128Accum, x: &Gf2_128, y: &Gf2_128) {
    unsafe {
        let x0: poly8x8_t = u64_to_poly8x8(x.0 as u64);
        let x1: poly8x8_t = u64_to_poly8x8((x.0 >> 64) as u64);
        let y0: poly8x8_t = u64_to_poly8x8(y.0 as u64);
        let y1: poly8x8_t = u64_to_poly8x8((y.0 >> 64) as u64);

        let z0: u128 = poly8x16_to_u128(pmul64x64(x0, y0));
        let z1: u128 = poly8x16_to_u128(pmul64x64(x0, y1));
        let z2: u128 = poly8x16_to_u128(pmul64x64(x1, y0));
        let z3: u128 = poly8x16_to_u128(pmul64x64(x1, y1));

        acc.0[0].0 ^= z0;
        acc.0[1].0 ^= z1 ^ z2;
        acc.0[2].0 ^= z3;
    }
}

#[inline(always)]
pub fn gf2_128_add_accum(a: &mut Gf2_128Accum, b: &Gf2_128Accum) {
    a.0[0].0 ^= b.0[0].0;
    a.0[1].0 ^= b.0[1].0;
    a.0[2].0 ^= b.0[2].0;
}

#[inline(always)]
pub fn gf2_128_accum_reduce(acc: &Gf2_128Accum) -> Gf2_128 {
    unsafe { reduce_128(acc.0[0].0, acc.0[1].0, acc.0[2].0) }
}

#[inline(always)]
pub fn cmovne<const N: usize>(
    a: &mut [crate::limb::Limb; N],
    x: crate::limb::Limb,
    y: crate::limb::Limb,
    b: &[crate::limb::Limb; N],
) {
    for i in 0..N {
        let mut ai = a[i];
        let bi = b[i];
        unsafe {
            core::arch::asm!(
                "cmp {x}, {y}",
                "csel {a}, {a}, {b}, eq",
                x = in(reg) x,
                y = in(reg) y,
                a = inout(reg) ai,
                b = in(reg) bi,
                options(pure, nomem, nostack)
            );
        }
        a[i] = ai;
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

