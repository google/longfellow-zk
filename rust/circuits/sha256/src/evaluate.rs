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
use compile_logic::Logic;

use super::{
    circuit::{Derived, Given},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> Given<L> {
    let input_block = std::array::from_fn(|i| bv.of_u32(given.input_block[i]));
    let h0 = std::array::from_fn(|i| bv.of_u32(given.h0[i]));
    Given { input_block, h0 }
}

pub fn evaluate_derived<L: Logic>(derived: &ConcreteDerived, bv: &BitvecLogic<L>) -> Derived<L> {
    let outw = std::array::from_fn(|i| bv.of_u32(derived.outw[i]));
    let oute = std::array::from_fn(|i| bv.of_u32(derived.oute[i]));
    let outa = std::array::from_fn(|i| bv.of_u32(derived.outa[i]));
    let h1 = std::array::from_fn(|i| bv.of_u32(derived.h1[i]));
    Derived {
        outw,
        oute,
        outa,
        h1,
    }
}
