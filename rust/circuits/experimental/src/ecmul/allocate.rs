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

use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(logic: &L, n: usize, pos: &mut usize) -> Given<L> {
    let boolean_io = circuits_boolean::BooleanIO::new(logic);
    let mut exp_bits = Vec::with_capacity(n);
    for _ in 0..n {
        exp_bits.push(boolean_io.next(pos));
    }
    let a = circuits_ec::pt2_wires(logic, pos);
    let b = circuits_ec::pt2_wires(logic, pos);
    Given { exp_bits, a, b }
}

pub fn allocate_derived<L: LogicIO>(logic: &L, n: usize, pos: &mut usize) -> Derived<L> {
    let mut round = Vec::with_capacity(n);
    for _ in 0..n {
        round.push(circuits_ec::pt3_wires(logic, pos));
    }
    let zinv = logic.next(pos);
    Derived { round, zinv }
}
