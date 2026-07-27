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

use circuits_bitvec::{BitvecIO, BitvecLogic};
use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(logic: &L, bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let message = bitvec_io.next::<256>(pos);
    let mac_av = logic.next(pos);
    let mac_ap0 = logic.next(pos);
    let mac_ap1 = logic.next(pos);
    let tag0 = logic.next(pos);
    let tag1 = logic.next(pos);
    Given {
        message,
        mac_av,
        mac_ap: [mac_ap0, mac_ap1],
        tag: [tag0, tag1],
    }
}

pub fn allocate_derived(_pos: &mut usize) -> Derived {}
