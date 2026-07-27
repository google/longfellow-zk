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

use super::circuit::Given;

pub fn allocate_given<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let v = bitvec_io.next::<8>(pos);
    Given { v }
}
