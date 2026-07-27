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
use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO, const MAX_BLOCKS: usize>(
    bv: &BitvecLogic<L>,
    pos: &mut usize,
) -> Given<L, MAX_BLOCKS> {
    let bitvec_io = circuits_bitvec::BitvecIO::new(bv);

    let nblocks = bitvec_io.next(pos);
    let length_bytes = bitvec_io.next(pos);

    let mut padded_preimage = Vec::with_capacity(MAX_BLOCKS * 64);
    for _ in 0..(MAX_BLOCKS * 64) {
        padded_preimage.push(bitvec_io.next(pos));
    }

    let expected_hash = bitvec_io.next(pos);

    Given {
        padded_preimage,
        nblocks,
        length_bytes,
        expected_hash,
    }
}

pub fn allocate_derived<L: LogicIO, const MAX_BLOCKS: usize>(
    bv: &BitvecLogic<L>,
    pos: &mut usize,
) -> Derived<L> {
    let mut all_args = Vec::with_capacity(MAX_BLOCKS);
    for _ in 0..MAX_BLOCKS {
        all_args.push(circuits_sha256::allocate_derived(bv, pos));
    }
    all_args
}
