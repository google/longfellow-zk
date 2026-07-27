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

pub type Limb = u32;

pub const LIMB_BITS: usize = 32;
pub const LIMBS_PER_U64: usize = 2;

#[inline(always)]
pub const fn u64_to_limbs(val: u64) -> [Limb; LIMBS_PER_U64] {
    [val as u32, (val >> 32) as u32]
}

#[inline(always)]
pub const fn limbs_to_u64(limbs: &[Limb]) -> u64 {
    (limbs[0] as u64) | ((limbs[1] as u64) << 32)
}

#[inline(always)]
pub fn words64_to_limbs<const W: usize, const L: usize>(words: &[u64; W]) -> [Limb; L] {
    let mut limbs = [0 as Limb; L];
    for i in 0..W {
        if 2 * i < L {
            limbs[2 * i] = words[i] as u32;
        }
        if 2 * i + 1 < L {
            limbs[2 * i + 1] = (words[i] >> 32) as u32;
        }
    }
    limbs
}

#[inline(always)]
pub fn limbs_to_words64<const W: usize, const L: usize>(limbs: &[Limb; L]) -> [u64; W] {
    let mut words = [0u64; W];
    for i in 0..W {
        let low = if 2 * i < L { limbs[2 * i] as u64 } else { 0 };
        let high = if 2 * i + 1 < L {
            limbs[2 * i + 1] as u64
        } else {
            0
        };
        words[i] = low | (high << 32);
    }
    words
}

#[inline(always)]
pub fn mulhl_one(a: Limb, b: Limb) -> (Limb, Limb) {
    let p = (a as u64) * (b as u64);
    (p as u32, (p >> 32) as u32)
}
