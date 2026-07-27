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

use std::ops::BitXor;

use crate::circuit::TermDelta;

/// A single entry slot in our two-way set-associative LRU cache.
#[derive(Clone, Copy, Default)]
struct Slot {
    d: TermDelta,
    index: u32,
    valid: bool,
}

/// A cache bucket containing two LRU slots (2-way set associative).
/// Slot 0 is the most recently used (MRU) slot, and slot 1 is the least recently used (LRU) slot.
#[derive(Clone, Copy, Default)]
struct CacheEntry {
    slots: [Slot; 2],
}

/// Approximate delta table builder for fast, memory-efficient circuit deserialization.
///
/// Instead of maintaining an exact hash table (such as `HashMap`) which incurs high memory overhead
/// and rehashing costs when deduplicating millions of circuit term deltas, we implement
/// Longfellow's exact 2-way set-associative LRU cache strategy over a fixed prime-sized table
/// (typically 8209). This trades occasional deduplication misses for $O(1)$ allocation-free lookups
/// and minimal memory footprint.
pub struct ApproximateDeltaTableBuilder {
    pub deltas: Vec<TermDelta>,
    cache: Vec<CacheEntry>,
}

impl ApproximateDeltaTableBuilder {
    /// Creates a new table builder with the specified cache bucket count.
    ///
    /// For best hash distribution, `cache_size` should be a prime number (e.g. 8209).
    #[must_use]
    pub fn new(cache_size: usize) -> Self {
        Self {
            deltas: Vec::new(),
            cache: vec![CacheEntry::default(); cache_size],
        }
    }

    /// Hashes and deduplicates a term delta `(dg, dh0, dh1, vi)`, returning its index in
    /// `self.deltas`.
    ///
    /// Uses Longfellow's exact FNV-1a derived 64-bit hash function and 2-way LRU eviction policy.
    pub fn dedup(&mut self, dg: u32, dh0: u32, dh1: u32, vi: u32) -> u32 {
        let d = TermDelta {
            g: dg,
            h: [dh0, dh1],
            k_index: vi,
        };

        // Longfellow's exact hash_combine / FNV-1a variant:
        //   static uint64_t hash_combine(uint64_t seed, uint64_t v) {
        //     return (seed * 0x100000001b3ull) ^ v;
        //   }
        #[inline(always)]
        fn hash_combine(seed: u64, v: u32) -> u64 {
            seed.wrapping_mul(0x0100_0000_01b3).bitxor(u64::from(v))
        }

        let mut h = 0xcbf2_9ce4_8422_2325_u64;
        h = hash_combine(h, dg);
        h = hash_combine(h, dh0);
        h = hash_combine(h, dh1);
        h = hash_combine(h, vi);

        let idx = (h as usize) % self.cache.len();
        let ent = &mut self.cache[idx];

        // Check slot 0 (MRU):
        if ent.slots[0].valid && ent.slots[0].d == d {
            return ent.slots[0].index;
        }

        // Check slot 1 (LRU):
        if ent.slots[1].valid && ent.slots[1].d == d {
            // Maintain the LRU property that slot[0] is the most recently used:
            ent.slots.swap(0, 1);
            return ent.slots[0].index;
        }

        // Cache miss: push new delta and perform LRU eviction (slot 0 -> slot 1, new -> slot 0).
        let index = self.deltas.len() as u32;
        self.deltas.push(d);

        ent.slots[1] = ent.slots[0];
        ent.slots[0] = Slot {
            d,
            index,
            valid: true,
        };

        index
    }
}

/// Exact delta table builder using a standard `HashMap` for perfect, collision-free deduplication.
/// Typically used at compiler/compile time where optimal compression outweighs runtime allocations.
pub struct ExactDeltaTableBuilder {
    pub deltas: Vec<TermDelta>,
    map: std::collections::HashMap<TermDelta, u32>,
}

impl Default for ExactDeltaTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExactDeltaTableBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            deltas: Vec::new(),
            map: std::collections::HashMap::new(),
        }
    }

    pub fn dedup(&mut self, dg: u32, dh0: u32, dh1: u32, vi: u32) -> u32 {
        let d = TermDelta {
            g: dg,
            h: [dh0, dh1],
            k_index: vi,
        };
        *self.map.entry(d).or_insert_with(|| {
            let index = self.deltas.len() as u32;
            self.deltas.push(d);
            index
        })
    }
}
