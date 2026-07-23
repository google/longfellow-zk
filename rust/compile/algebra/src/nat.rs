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

use core_algebra::Nat;
use num_bigint::BigUint;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompileNat<const W: usize>(pub BigUint);

impl<const W: usize> CompileNat<W> {
    #[must_use]
    pub fn bit_width(&self) -> usize {
        W * 64
    }

    #[must_use]
    pub fn from_biguint(val: &num_bigint::BigUint) -> Self {
        Self(val.clone())
    }

    #[must_use]
    pub fn to_biguint(&self) -> num_bigint::BigUint {
        self.0.clone()
    }
}

impl<const W: usize> std::fmt::Debug for CompileNat<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CompileNat({})", self.0)
    }
}

impl<const W: usize> Nat<W> for CompileNat<W> {
    fn to_limbs(&self) -> [u64; W] {
        let mut limbs = [0u64; W];
        let digits = self.0.to_u64_digits();
        let limit = std::cmp::min(W, digits.len());
        limbs[..limit].copy_from_slice(&digits[..limit]);
        limbs
    }

    fn from_limbs(limbs: &[u64; W]) -> Self {
        let mut digits = Vec::with_capacity(W * 2);
        for &limb in limbs {
            digits.push(limb as u32);
            digits.push((limb >> 32) as u32);
        }
        Self(BigUint::new(digits))
    }

    fn from_u64(val: u64) -> Self {
        Self(BigUint::from(val))
    }

    fn to_bytes_le(&self) -> Vec<u8> {
        let mut bytes = self.0.to_bytes_le();
        bytes.resize(W * 8, 0u8);
        bytes
    }

    fn from_bytes_le(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            W * 8,
            "CompileNat::from_bytes_le: invalid bytes length"
        );
        Self(BigUint::from_bytes_le(bytes))
    }

    fn bit(&self, i: usize) -> bool {
        ((&self.0 >> i) & BigUint::from(1u32)) == BigUint::from(1u32)
    }

    fn to_bits(&self, n: usize) -> Vec<bool> {
        (0..n).map(|i| self.bit(i)).collect()
    }
}

impl<const W: usize> From<BigUint> for CompileNat<W> {
    fn from(val: BigUint) -> Self {
        Self(val)
    }
}

impl<const W: usize> From<u64> for CompileNat<W> {
    fn from(val: u64) -> Self {
        Self(BigUint::from(val))
    }
}
