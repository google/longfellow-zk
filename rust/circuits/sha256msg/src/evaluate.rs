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

use circuits_bitvec::BitvecLogic;
use circuits_sha256::evaluate::evaluate_derived as sha256_evaluate_derived;
use compile_logic::Logic;

use super::{
    circuit::Given as WireGiven,
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<L: Logic, const S: usize>(
    given: &ConcreteGiven,
    bv: &BitvecLogic<L>,
) -> WireGiven<L, S> {
    let padded_preimage = given.padded_preimage.iter().map(|&b| bv.of_u8(b)).collect();
    let nblocks = bv.of_u64::<S>(given.nblocks as u64);
    let length_bytes = bv.of_u64_val(given.length_bytes);

    let boolean = circuits_boolean::Boolean::new(bv.logic());
    let expected_hash = bv.from_fn::<256, _>(|idx| {
        let word_idx = 7 - (idx / 32);
        let bit_idx = idx % 32;
        let w = given.expected_hash[word_idx];
        let bit_val = (w.checked_shr(bit_idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    });

    WireGiven {
        padded_preimage,
        nblocks,
        length_bytes,
        expected_hash,
    }
}

pub fn evaluate_derived<L: Logic>(
    derived: &ConcreteDerived,
    bv: &BitvecLogic<L>,
) -> Vec<circuits_sha256::Derived<L>> {
    derived
        .sha_derived
        .iter()
        .map(|w| sha256_evaluate_derived(w, bv))
        .collect()
}
