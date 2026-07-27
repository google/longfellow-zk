// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core_algebra::Nat;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RuntimeNat<const W: usize>([u64; W]);

impl<const W: usize> RuntimeNat<W> {
    #[inline(always)]
    pub(crate) fn from_limbs(limbs: [u64; W]) -> Self {
        Self(limbs)
    }

    #[inline(always)]
    pub(crate) fn limbs(&self) -> &[u64; W] {
        &self.0
    }
}

impl<const W: usize> std::fmt::Debug for RuntimeNat<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RuntimeNat({:?})", self.0)
    }
}

impl<const W: usize> PartialOrd for RuntimeNat<W> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<const W: usize> Ord for RuntimeNat<W> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..W).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl<const W: usize> Nat<W> for RuntimeNat<W> {
    fn to_limbs(&self) -> [u64; W] {
        self.0
    }

    fn from_limbs(limbs: &[u64; W]) -> Self {
        Self(*limbs)
    }

    fn from_u64(val: u64) -> Self {
        let mut limbs = [0u64; W];
        if W > 0 {
            limbs[0] = val;
        }
        Self(limbs)
    }

    fn to_bytes_le(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(W * 8);
        for &limb in &self.0 {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    fn from_bytes_le(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            W * 8,
            "RuntimeNat::from_bytes_le: invalid bytes length"
        );
        let mut limbs = [0u64; W];
        for i in 0..W {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(buf);
        }
        Self(limbs)
    }

    fn bit(&self, i: usize) -> bool {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        if limb_idx < W {
            (self.0[limb_idx] & (1u64 << bit_idx)) != 0
        } else {
            false
        }
    }

    fn to_bits(&self, n: usize) -> Vec<bool> {
        (0..n).map(|i| self.bit(i)).collect()
    }
}
