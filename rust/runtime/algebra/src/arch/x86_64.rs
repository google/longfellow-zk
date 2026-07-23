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

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{__m128i, _mm_xor_si128, _mm_set_epi64x, _mm_slli_si128, _mm_clmulepi64_si128};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Gf2_128(pub __m128i);

#[derive(Clone, Copy, Debug)]
pub struct Gf2_128Accum(pub [Gf2_128; 3]);

impl Gf2_128 {
    #[inline(always)]
    #[must_use]
    pub const fn from_u128(v: u128) -> Self {
        unsafe { Self(std::mem::transmute::<u128, __m128i>(v)) }
    }

    #[inline(always)]
    #[must_use]
    pub const fn to_u128(&self) -> u128 {
        unsafe { std::mem::transmute::<__m128i, u128>(self.0) }
    }

    #[inline(always)]
    pub fn xor_in_place(&mut self, other: &Self) {
        unsafe {
            self.0 = _mm_xor_si128(self.0, other.0);
        }
    }

    #[inline(always)]
    #[must_use]
    pub fn xor(&self, other: &Self) -> Self {
        unsafe { Self(_mm_xor_si128(self.0, other.0)) }
    }

    #[inline(always)]
    #[must_use]
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
unsafe fn reduce_128(mut z0: __m128i, mut z12: __m128i, mut z3: __m128i) -> Gf2_128 {
    let poly = _mm_set_epi64x(0, 0x87);

    let mut tmp = _mm_slli_si128(z3, 8);
    z12 = _mm_xor_si128(z12, tmp);
    z3 = _mm_clmulepi64_si128(z3, poly, 0x01);
    z12 = _mm_xor_si128(z12, z3);

    tmp = _mm_slli_si128(z12, 8);
    z0 = _mm_xor_si128(z0, tmp);
    z12 = _mm_clmulepi64_si128(z12, poly, 0x01);
    z0 = _mm_xor_si128(z0, z12);

    Gf2_128(z0)
}

#[inline(always)]
#[must_use]
pub fn gf2_128_mul(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    unsafe {
        let z0 = _mm_clmulepi64_si128(x.0, y.0, 0x00);
        let z1 = _mm_clmulepi64_si128(x.0, y.0, 0x01);
        let z2 = _mm_clmulepi64_si128(x.0, y.0, 0x10);
        let z3 = _mm_clmulepi64_si128(x.0, y.0, 0x11);
        reduce_128(z0, _mm_xor_si128(z1, z2), z3)
    }
}

#[inline(always)]
pub fn gf2_128_mac(acc: &mut Gf2_128Accum, x: &Gf2_128, y: &Gf2_128) {
    unsafe {
        let z0 = _mm_clmulepi64_si128(x.0, y.0, 0x00);
        let z1 = _mm_clmulepi64_si128(x.0, y.0, 0x01);
        let z2 = _mm_clmulepi64_si128(x.0, y.0, 0x10);
        let z3 = _mm_clmulepi64_si128(x.0, y.0, 0x11);

        acc.0[0].0 = _mm_xor_si128(acc.0[0].0, z0);
        acc.0[1].0 = _mm_xor_si128(acc.0[1].0, _mm_xor_si128(z1, z2));
        acc.0[2].0 = _mm_xor_si128(acc.0[2].0, z3);
    }
}

#[inline(always)]
pub fn gf2_128_add_accum(a: &mut Gf2_128Accum, b: &Gf2_128Accum) {
    unsafe {
        a.0[0].0 = _mm_xor_si128(a.0[0].0, b.0[0].0);
        a.0[1].0 = _mm_xor_si128(a.0[1].0, b.0[1].0);
        a.0[2].0 = _mm_xor_si128(a.0[2].0, b.0[2].0);
    }
}

#[inline(always)]
#[must_use]
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
    #[cfg(target_arch = "x86")]
    {
        for i in 0..N {
            let mut ai = a[i];
            let bi = b[i];
            unsafe {
                core::arch::asm!(
                    "cmp {x}, {y}",
                    "cmovne {a}, {b}",
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
    #[cfg(target_arch = "x86_64")]
    {
        if N == 1 {
            unsafe {
                core::arch::asm!(
                    "cmp {x}, {y}",
                    "cmovne {a0}, {b0}",
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
                    "cmovne {a0}, {b0}",
                    "cmovne {a1}, {b1}",
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
                    "cmovne {a0}, {b0}",
                    "cmovne {a1}, {b1}",
                    "cmovne {a2}, {b2}",
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
                    "cmovne {a0}, {b0}",
                    "cmovne {a1}, {b1}",
                    "cmovne {a2}, {b2}",
                    "cmovne {a3}, {b3}",
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
                    "cmovne {a}, {b}",
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
#[must_use]
pub fn zero_but_you_dont_know_it() -> crate::limb::Limb {
    core::hint::black_box(0 as crate::limb::Limb)
}
