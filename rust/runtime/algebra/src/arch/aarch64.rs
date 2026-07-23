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

#[cfg(not(target_feature = "aes"))]
compile_error!("AArch64 builds require ARMv8-A Cryptographic extension (+aes / PMULL). Enable it via target-feature=+aes,+sha2.");

use std::arch::aarch64::*;

#[inline(always)]
pub fn cmovne<const N: usize>(
    a: &mut [crate::limb::Limb; N],
    x: crate::limb::Limb,
    y: crate::limb::Limb,
    b: &[crate::limb::Limb; N],
) {
    #[cfg(target_arch = "aarch64")]
    if N == 1 {
        unsafe {
            core::arch::asm!(
                "cmp {x}, {y}",
                "csel {a0}, {a0}, {b0}, eq",
                x = in(reg) x,
                y = in(reg) y,
                a0 = inout(reg) a[0],
                b0 = in(reg) b[0],
                options(pure, nomem, nostack)
            );
        }
        return;
    } else if N == 2 {
        unsafe {
            core::arch::asm!(
                "cmp {x}, {y}",
                "csel {a0}, {a0}, {b0}, eq",
                "csel {a1}, {a1}, {b1}, eq",
                x = in(reg) x,
                y = in(reg) y,
                a0 = inout(reg) a[0],
                a1 = inout(reg) a[1],
                b0 = in(reg) b[0],
                b1 = in(reg) b[1],
                options(pure, nomem, nostack)
            );
        }
        return;
    } else if N == 3 {
        unsafe {
            core::arch::asm!(
                "cmp {x}, {y}",
                "csel {a0}, {a0}, {b0}, eq",
                "csel {a1}, {a1}, {b1}, eq",
                "csel {a2}, {a2}, {b2}, eq",
                x = in(reg) x,
                y = in(reg) y,
                a0 = inout(reg) a[0],
                a1 = inout(reg) a[1],
                a2 = inout(reg) a[2],
                b0 = in(reg) b[0],
                b1 = in(reg) b[1],
                b2 = in(reg) b[2],
                options(pure, nomem, nostack)
            );
        }
        return;
    } else if N == 4 {
        unsafe {
            core::arch::asm!(
                "cmp {x}, {y}",
                "csel {a0}, {a0}, {b0}, eq",
                "csel {a1}, {a1}, {b1}, eq",
                "csel {a2}, {a2}, {b2}, eq",
                "csel {a3}, {a3}, {b3}, eq",
                x = in(reg) x,
                y = in(reg) y,
                a0 = inout(reg) a[0],
                a1 = inout(reg) a[1],
                a2 = inout(reg) a[2],
                a3 = inout(reg) a[3],
                b0 = in(reg) b[0],
                b1 = in(reg) b[1],
                b2 = in(reg) b[2],
                b3 = in(reg) b[3],
                options(pure, nomem, nostack)
            );
        }
        return;
    }
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
    std::hint::black_box(0 as crate::limb::Limb)
}

// ============================================================================
// GF(2^128) ARM64 NEON Functions & Types
// ============================================================================

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Gf2_128(pub poly64x2_t);

#[derive(Clone, Copy, Debug)]
pub struct Gf2_128Accum(pub [Gf2_128; 3]);

impl Gf2_128 {
    #[inline(always)]
    pub const fn from_u64s(low: u64, high: u64) -> Self {
        unsafe { Self(std::mem::transmute([low, high])) }
    }

    #[inline(always)]
    pub const fn from_u128(v: u128) -> Self {
        unsafe { Self(std::mem::transmute(v)) }
    }

    #[inline(always)]
    pub fn to_u128(&self) -> u128 {
        unsafe {
            let u = vreinterpretq_u64_p64(self.0);
            let low = vgetq_lane_u64(u, 0) as u128;
            let high = vgetq_lane_u64(u, 1) as u128;
            low | (high << 64)
        }
    }

    #[inline(always)]
    pub fn xor_in_place(&mut self, other: &Self) {
        unsafe { self.0 = xor_poly(self.0, other.0); }
    }

    #[inline(always)]
    pub fn xor(&self, other: &Self) -> Self {
        unsafe { Self(xor_poly(self.0, other.0)) }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.to_u128() == 0
    }
}

impl Default for Gf2_128 {
    #[inline(always)]
    fn default() -> Self {
        Self::from_u128(0)
    }
}

impl Default for Gf2_128Accum {
    #[inline(always)]
    fn default() -> Self {
        Self([Gf2_128::default(); 3])
    }
}

impl PartialEq for Gf2_128 {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.to_u128() == other.to_u128()
    }
}
impl Eq for Gf2_128 {}

impl std::hash::Hash for Gf2_128 {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_u128().hash(state);
    }
}

impl std::fmt::Debug for Gf2_128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gf2_128({:#034x})", self.to_u128())
    }
}

#[inline(always)]
unsafe fn vmull_low(x: poly64x2_t, y: poly64x2_t) -> poly64x2_t {
    let x0 = vgetq_lane_p64(x, 0);
    let y0 = vgetq_lane_p64(y, 0);
    let res = vmull_p64(x0, y0);
    vreinterpretq_p64_p128(res)
}

#[inline(always)]
unsafe fn vmull_high(x: poly64x2_t, y: poly64x2_t) -> poly64x2_t {
    let res = vmull_high_p64(x, y);
    vreinterpretq_p64_p128(res)
}

#[inline(always)]
unsafe fn xor_poly(a: poly64x2_t, b: poly64x2_t) -> poly64x2_t {
    let a_u: uint64x2_t = vreinterpretq_u64_p64(a);
    let b_u: uint64x2_t = vreinterpretq_u64_p64(b);
    vreinterpretq_p64_u64(veorq_u64(a_u, b_u))
}

#[inline(always)]
unsafe fn ext_poly_1(a: poly64x2_t, b: poly64x2_t) -> poly64x2_t {
    let a_u: uint64x2_t = vreinterpretq_u64_p64(a);
    let b_u: uint64x2_t = vreinterpretq_u64_p64(b);
    vreinterpretq_p64_u64(vextq_u64(a_u, b_u, 1))
}

#[inline(always)]
unsafe fn reduce_128(t0: poly64x2_t, t1: poly64x2_t) -> poly64x2_t {
    let zero = vcombine_p64(vcreate_p64(0), vcreate_p64(0));
    let poly = vcombine_p64(vcreate_p64(0), vcreate_p64(0x87));
    let red_high = vmull_high(t1, poly);
    let red_ext = ext_poly_1(zero, t1);
    xor_poly(xor_poly(t0, red_ext), red_high)
}

#[inline(always)]
pub fn gf2_128_mul(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    unsafe {
        let t0 = vmull_low(x.0, y.0);
        let swx = ext_poly_1(x.0, x.0);
        let t1a = vmull_low(swx, y.0);
        let t1b = vmull_high(swx, y.0);
        let t1_raw = xor_poly(t1a, t1b);
        let t2 = vmull_high(x.0, y.0);
        let t1 = reduce_128(t1_raw, t2);
        let res = reduce_128(t0, t1);
        Gf2_128(res)
    }
}

#[inline(always)]
pub fn gf2_128_mac(acc: &mut Gf2_128Accum, x: &Gf2_128, y: &Gf2_128) {
    unsafe {
        let t0 = vmull_low(x.0, y.0);
        let swx = ext_poly_1(x.0, x.0);
        let t1a = vmull_low(swx, y.0);
        let t1b = vmull_high(swx, y.0);
        let t1 = xor_poly(t1a, t1b);
        let t2 = vmull_high(x.0, y.0);

        acc.0[0].0 = xor_poly(acc.0[0].0, t0);
        acc.0[1].0 = xor_poly(acc.0[1].0, t1);
        acc.0[2].0 = xor_poly(acc.0[2].0, t2);
    }
}

#[inline(always)]
pub fn gf2_128_add_accum(a: &mut Gf2_128Accum, b: &Gf2_128Accum) {
    unsafe {
        a.0[0].0 = xor_poly(a.0[0].0, b.0[0].0);
        a.0[1].0 = xor_poly(a.0[1].0, b.0[1].0);
        a.0[2].0 = xor_poly(a.0[2].0, b.0[2].0);
    }
}

#[inline(always)]
pub fn gf2_128_accum_reduce(acc: &Gf2_128Accum) -> Gf2_128 {
    unsafe {
        let t0 = acc.0[0].0;
        let mut t1 = acc.0[1].0;
        let t2 = acc.0[2].0;
        t1 = reduce_128(t1, t2);
        let res = reduce_128(t0, t1);
        Gf2_128(res)
    }
}
