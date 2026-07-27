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

pub type Limb = u64;

pub const LIMB_BITS: usize = 64;
pub const LIMBS_PER_U64: usize = 1;

#[inline(always)]
#[must_use]
pub const fn u64_to_limbs(val: u64) -> [Limb; LIMBS_PER_U64] {
    [val]
}

#[inline(always)]
#[must_use]
pub const fn limbs_to_u64(limbs: &[Limb]) -> u64 {
    limbs[0]
}

#[inline(always)]
#[must_use]
pub fn words64_to_limbs<const W: usize, const L: usize>(words: &[u64; W]) -> [Limb; L] {
    let mut limbs = [0 as Limb; L];
    for (i, &word) in words.iter().enumerate() {
        if i < L {
            limbs[i] = word;
        }
    }
    limbs
}

#[inline(always)]
#[must_use]
pub fn limbs_to_words64<const W: usize, const L: usize>(limbs: &[Limb; L]) -> [u64; W] {
    let mut words = [0u64; W];
    for (i, &limb) in limbs.iter().enumerate() {
        if i < W {
            words[i] = limb;
        }
    }
    words
}

#[inline(always)]
#[must_use]
pub fn mulhl_one(a: Limb, b: Limb) -> (Limb, Limb) {
    let p = u128::from(a) * u128::from(b);
    (p as u64, (p >> 64) as u64)
}
