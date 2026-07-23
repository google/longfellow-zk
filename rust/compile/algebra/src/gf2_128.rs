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

use num_bigint::BigUint;

use crate::field::{AlgebraicField, CompileField};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gf2_128(u128);

fn xor(a: Gf2_128, b: Gf2_128) -> Gf2_128 {
    Gf2_128(a.0 ^ b.0)
}

#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "pclmulqdq",
        target_feature = "sse2"
    ),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "aes"
    )
)))]
const POLY: u128 = 0x87;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "pclmulqdq",
    target_feature = "sse2"
))]
fn clmul64(x: u64, y: u64) -> (u64, u64) {
    unsafe {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::{__m128i, _mm_clmulepi64_si128};
        let x_val = std::mem::transmute::<u128, __m128i>(u128::from(x));
        let y_val = std::mem::transmute::<u128, __m128i>(u128::from(y));
        let res = _mm_clmulepi64_si128(x_val, y_val, 0x00);
        let res_u128 = std::mem::transmute::<__m128i, u128>(res);
        (res_u128 as u64, (res_u128 >> 64) as u64)
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_feature = "aes"
))]
fn clmul64_aarch64(x: u64, y: u64) -> (u64, u64) {
    unsafe {
        use std::arch::aarch64::*;
        let res: u128 = std::mem::transmute(vmull_p64(x, y));
        (res as u64, (res >> 64) as u64)
    }
}

#[cfg(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "pclmulqdq",
        target_feature = "sse2"
    ),
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "aes"
    )
))]
fn reduce(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    let (a0, a1) = a;
    let (b0, b1) = b;
    let r0 = a0 ^ b1 ^ (b1 << 1) ^ (b1 << 2) ^ (b1 << 7);
    let r1 = a1 ^ b0 ^ (b1 >> 63) ^ (b1 >> 62) ^ (b1 >> 57);
    (r0, r1)
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "pclmulqdq",
    target_feature = "sse2"
))]
fn mul_pclmul(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    let x_v0 = x.0 as u64;
    let x_v1 = (x.0 >> 64) as u64;
    let y_v0 = y.0 as u64;
    let y_v1 = (y.0 >> 64) as u64;

    let t0 = clmul64(x_v0, y_v0);
    let t2 = clmul64(x_v1, y_v1);
    let t1 = clmul64(x_v0 ^ x_v1, y_v0 ^ y_v1);

    let t1_xor = (t1.0 ^ t0.0 ^ t2.0, t1.1 ^ t0.1 ^ t2.1);
    let t1_red = reduce(t1_xor, t2);
    let t0_red = reduce(t0, t1_red);

    Gf2_128(u128::from(t0_red.0) | (u128::from(t0_red.1) << 64))
}

#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_feature = "aes"
))]
fn mul_aarch64(x: Gf2_128, y: Gf2_128) -> Gf2_128 {
    let x_v0 = x.0 as u64;
    let x_v1 = (x.0 >> 64) as u64;
    let y_v0 = y.0 as u64;
    let y_v1 = (y.0 >> 64) as u64;

    let t0 = clmul64_aarch64(x_v0, y_v0);
    let t2 = clmul64_aarch64(x_v1, y_v1);
    let t1 = clmul64_aarch64(x_v0 ^ x_v1, y_v0 ^ y_v1);

    let t1_xor = (t1.0 ^ t0.0 ^ t2.0, t1.1 ^ t0.1 ^ t2.1);
    let t1_red = reduce(t1_xor, t2);
    let t0_red = reduce(t0, t1_red);

    Gf2_128(t0_red.0 as u128 | ((t0_red.1 as u128) << 64))
}

fn mul(a: Gf2_128, b: Gf2_128) -> Gf2_128 {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "pclmulqdq",
        target_feature = "sse2"
    ))]
    {
        mul_pclmul(a, b)
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_feature = "aes"
    ))]
    {
        mul_aarch64(a, b)
    }
    #[cfg(not(any(
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "pclmulqdq",
            target_feature = "sse2"
        ),
        all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_feature = "aes"
        )
    )))]
    {
        let mut res = 0u128;
        let mut temp_a = a.0;
        let mut cur_b = b.0;
        for _ in 0..128 {
            if (cur_b & 1) != 0 {
                res ^= temp_a;
            }
            let msb = (temp_a >> 127) & 1;
            temp_a <<= 1;
            if msb != 0 {
                temp_a ^= POLY;
            }
            cur_b >>= 1;
        }
        Gf2_128(res)
    }
}

fn invert(e: Gf2_128) -> Gf2_128 {
    assert!(e.0 != 0, "cannot invert zero");
    let mut res = Gf2_128(1);
    let mut temp = e;
    for i in 0..128 {
        if i > 0 {
            res = mul(res, temp);
        }
        temp = mul(temp, temp);
    }
    res
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gf2_128Field {
    cantor_basis: [Gf2_128; 128],
}

impl Default for Gf2_128Field {
    fn default() -> Self {
        Self::new()
    }
}

impl Gf2_128Field {
    pub fn new() -> Self {
        Self {
            cantor_basis: core_algebra::CANTOR_BASIS_U128.map(Gf2_128),
        }
    }
}

impl core_algebra::BareField for Gf2_128Field {
    type E = Gf2_128;
}

impl core_algebra::Comparable for Gf2_128Field {
    fn compare(&self, a: &Self::E, b: &Self::E) -> std::cmp::Ordering {
        a.0.cmp(&b.0)
    }
}

impl core_algebra::AlgebraicField for Gf2_128Field {
    fn zero(&self) -> Self::E {
        Gf2_128(0)
    }
    fn one(&self) -> Self::E {
        Gf2_128(1)
    }
    fn add(&self, a: &mut Self::E, b: &Self::E) {
        *a = xor(*a, *b);
    }
    fn sub(&self, a: &mut Self::E, b: &Self::E) {
        *a = xor(*a, *b);
    }
    fn mul(&self, a: &mut Self::E, b: &Self::E) {
        *a = mul(*a, *b);
    }
    fn invert(&self, a: &Self::E) -> Self::E {
        invert(*a)
    }
}

impl CompileField for Gf2_128Field {
    fn characteristic(&self) -> BigUint {
        BigUint::from(2u64)
    }

    fn pseudo_basis(&self, i: usize) -> Self::E {
        assert!(i < 128, "i < dimension");
        Gf2_128(1u128 << i)
    }

    fn pseudo_dimension(&self) -> usize {
        128
    }

    fn pseudo_basis_unsafe(&self, i: usize) -> Self::E {
        self.pseudo_basis(i)
    }

    fn pseudo_dimension_of_multiplicative_group(&self) -> usize {
        128
    }
}

impl core_algebra::SerializableField for Gf2_128Field {
    fn name(&self) -> String {
        "GF2_128".to_string()
    }

    fn id(&self) -> usize {
        4
    }

    fn is_binary(&self) -> bool {
        true
    }

    fn serialized_size_bytes(&self) -> usize {
        16
    }

    #[inline]
    fn to_bytes_into(&self, e: &Self::E, dst: &mut [u8]) {
        assert_eq!(
            dst.len(),
            16,
            "destination slice length mismatch: {} != 16",
            dst.len()
        );
        dst.copy_from_slice(&e.0.to_le_bytes());
    }

    fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
        if bytes.len() != 16 {
            return Err("Invalid size".to_string());
        }
        let v = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
        Ok(Gf2_128(v))
    }

    fn serialized_mone(&self) -> Vec<u8> {
        let mone = self.mone();
        self.to_bytes(&mone)
    }
}

impl core_algebra::HasLookupPoints for Gf2_128Field {
    fn lookup_point(&self, _n: usize, i: usize) -> Self::E {
        let mut pt = Gf2_128(0);
        for j in 0..(usize::BITS as usize) {
            if (i & (1usize << j)) != 0 {
                pt = self.addf(&pt, &self.cantor_basis[j]);
            }
        }
        pt
    }
}

impl core_algebra::SupportsU64Conversions for Gf2_128Field {
    fn u64_to_element(&self, n: u64) -> Self::E {
        Gf2_128(u128::from(n))
    }
}

impl core_algebra::SupportsU128Conversions for Gf2_128Field {
    fn u128_to_element(&self, n: u128) -> Self::E {
        Gf2_128(n)
    }
}

impl crate::field::CompileBinaryField for Gf2_128Field {
    fn generator(&self) -> Self::E {
        Gf2_128(2)
    }
}
