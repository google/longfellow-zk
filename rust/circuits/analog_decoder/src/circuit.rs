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

use circuits_boolean::{Bitw, Boolean};
use circuits_lookup::{Lookup, Table};
use compile_logic::{Eltw, Logic};
use core_algebra::ElementOf;

use crate::proto;

pub struct AnalogDecoder<'a, L: Logic> {
    logic: &'a L,
    lookup: Lookup<'a, L>,
}

impl<'a, L: Logic> AnalogDecoder<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            lookup: Lookup::new(logic),
        }
    }

    fn delta(&self, b: bool) -> Eltw<L> {
        if b {
            self.logic.one()
        } else {
            self.logic.zero()
        }
    }

    #[must_use]
    pub fn unary_point(&self, n: usize, i: usize) -> ElementOf<L::F> {
        proto::unary_point(self.logic.field(), n, i)
    }

    #[must_use]
    pub fn unary(&self, n: usize) -> UnaryDecoder<'a, L> {
        assert!(n >= 2, "unary decoder requires n >= 2, got n = {n}");
        let mut pluckers = Vec::with_capacity(n + 1);
        for k in 0..=n {
            let plucker = self.lookup.table(n + 1, |i| Some(self.delta(i == k)));
            pluckers.push(plucker);
        }

        UnaryDecoder {
            logic: self.logic,
            pluckers,
            boolean: Boolean::new(self.logic),
        }
    }

    #[must_use]
    pub fn binary_point(&self, width: usize, i: usize) -> ElementOf<L::F> {
        proto::binary_point(self.logic.field(), width, i)
    }

    #[must_use]
    pub fn bit(&self, width: usize, k: usize) -> BitDecoder<'a, L> {
        let boolean = Boolean::new(self.logic);
        let n = 1 << width;
        let plucker = self.lookup.table(n + 1, |i| {
            if i < n {
                let bit_val = (i.checked_shr(k as u32).unwrap_or(0) & 1) == 1;
                let bit_wire = boolean.konst(bit_val);
                Some(boolean.as_eltw(&bit_wire))
            } else {
                None
            }
        });
        BitDecoder { plucker, boolean }
    }

    #[must_use]
    pub fn binary(&self, width: usize) -> BinaryDecoder<'a, L> {
        let n = 1 << width;
        let range_plucker = self.lookup.table(n + 1, |i| Some(self.delta(i == n)));
        let mut bits = Vec::with_capacity(width);
        for k in 0..width {
            bits.push(self.bit(width, k));
        }
        BinaryDecoder {
            logic: self.logic,
            range_plucker,
            bits,
        }
    }
}

pub struct BitDecoder<'a, L: Logic> {
    plucker: Table<'a, L>,
    boolean: Boolean<'a, L>,
}

impl<L: Logic> BitDecoder<'_, L> {
    /// Decodes a bit from an encoded field element.
    ///
    /// # Soundness Note
    /// `of_eltw` emits the quadratic boolean assertion `v * (1 - v) = 0` on the evaluated table
    /// output, enforcing that the evaluated result for this bit position is strictly a boolean
    /// bit (0 or 1).
    pub fn decode(&self, encoded: &Eltw<L>) -> Bitw<L> {
        let val = self.plucker.eval(encoded);
        let precious_val = self.boolean.logic().precious(&val);
        self.boolean.of_eltw(precious_val)
    }

    pub fn decode_with_assertion(&self, encoded: &Eltw<L>, assertion: L::Assertions) -> Bitw<L> {
        let val = self.plucker.eval(encoded);
        let precious_val = self.boolean.logic().precious(&val);
        self.boolean.of_eltw_with_assertion(precious_val, assertion)
    }
}

pub struct BinaryDecoder<'a, L: Logic> {
    logic: &'a L,
    range_plucker: Table<'a, L>,
    bits: Vec<BitDecoder<'a, L>>,
}

impl<L: Logic> BinaryDecoder<'_, L> {
    pub fn decode(&self, encoded: &Eltw<L>) -> Vec<Bitw<L>> {
        let range_ok = self.range_plucker.eval(encoded);
        let assert_in_range = self.logic.assert0("assert_in_range", &range_ok);
        self.bits
            .iter()
            .map(|bit_dec| {
                let val = bit_dec.plucker.eval(encoded);
                let precious_val = self.logic.precious(&val);
                bit_dec
                    .boolean
                    .of_eltw_with_assertion(precious_val, assert_in_range.clone())
            })
            .collect()
    }
}

pub struct UnaryDecoder<'a, L: Logic> {
    logic: &'a L,
    pluckers: Vec<Table<'a, L>>,
    boolean: Boolean<'a, L>,
}

impl<L: Logic> UnaryDecoder<'_, L> {
    pub fn decode(&self, encoded: &Eltw<L>) -> (L::Assertions, Vec<Bitw<L>>) {
        let n = self.pluckers.len() - 1;

        // 1. Evaluate range check basis polynomial:
        let range_ok = self.pluckers[n].eval(encoded);
        let assert_in_range = self.logic.assert0("assert_in_range", &range_ok);

        // 2. Evaluate each basis polynomial:
        let decoded: Vec<_> = self.pluckers[0..n]
            .iter()
            .map(|plucker| {
                let val = plucker.eval(encoded);
                let precious_val = self.logic.precious(&val);
                // Since X is guaranteed to be in the range, basis polynomials evaluate to bits (0
                // or 1). We use of_eltw_with_assertion to attach the range check assertion.
                self.boolean
                    .of_eltw_with_assertion(precious_val, assert_in_range.clone())
            })
            .collect();

        (assert_in_range, decoded)
    }
}
