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

//! Reference implementation of GF(2^128) using a u128 backing store
//! and naive bitwise multiplication / reduction.

use crate::field::{
    AlgebraicField, BareField, HasLookupPoints, SerializableField, SupportsU128Conversions,
};

/// The irreducible polynomial P(x) = x^128 + x^7 + x^2 + x + 1.
/// Represented as the low 128 coefficients: x^7 + x^2 + x + 1 = 0x87.
const POLY: u128 = 0x87;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gf2_128(pub u128);

impl std::fmt::Debug for Gf2_128 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gf2_128({:#034x})", self.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Gf2_128Field {
    cantor_basis: [Gf2_128; 128],
}

impl Gf2_128Field {
    pub fn new() -> Self {
        Self {
            cantor_basis: super::proto::CANTOR_BASIS.map(Gf2_128),
        }
    }

    #[must_use]
    pub fn cantor_basis(&self) -> &[Gf2_128; 128] {
        &self.cantor_basis
    }
}

impl Default for Gf2_128Field {
    fn default() -> Self {
        Self::new()
    }
}

impl BareField for Gf2_128Field {
    type E = Gf2_128;
}

impl AlgebraicField for Gf2_128Field {
    fn zero(&self) -> Self::E {
        Gf2_128(0)
    }

    fn one(&self) -> Self::E {
        Gf2_128(1)
    }

    fn add(&self, a: &mut Self::E, b: &Self::E) {
        *a = Gf2_128(a.0 ^ b.0);
    }

    fn sub(&self, a: &mut Self::E, b: &Self::E) {
        *a = Gf2_128(a.0 ^ b.0);
    }

    fn mul(&self, a: &mut Self::E, b: &Self::E) {
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
        *a = Gf2_128(res);
    }

    fn invert(&self, a: &Self::E) -> Self::E {
        assert!(!self.is_zero(a), "cannot invert zero");
        let mut res = self.one();
        let mut temp = *a;
        for i in 0..128 {
            if i > 0 {
                res = self.mulf(&res, &temp);
            }
            temp = self.mulf(&temp, &temp);
        }
        res
    }
}

impl SerializableField for Gf2_128Field {
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
        let val = u128::from_le_bytes(bytes.try_into().unwrap());
        Ok(Gf2_128(val))
    }

    fn serialized_mone(&self) -> Vec<u8> {
        let mone = self.mone();
        self.to_bytes(&mone)
    }
}

impl HasLookupPoints for Gf2_128Field {
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

impl SupportsU128Conversions for Gf2_128Field {
    fn u128_to_element(&self, n: u128) -> Self::E {
        Gf2_128(n)
    }
}
