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
    circuit::{Derived as WireDerived, Given as WireGiven, State},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> WireGiven<L> {
    let initial_state: State<L> =
        std::array::from_fn(|x| std::array::from_fn(|y| bv.of_u64_val(given.initial_state[x][y])));
    WireGiven { initial_state }
}

pub fn evaluate_derived<L: Logic>(
    derived: &ConcreteDerived,
    bv: &BitvecLogic<L>,
) -> WireDerived<L> {
    let mut intermediate_states = Vec::with_capacity(derived.intermediate_states.len());
    for rust_state in &derived.intermediate_states {
        let state: State<L> =
            std::array::from_fn(|x| std::array::from_fn(|y| bv.of_u64_val(rust_state[x][y])));
        intermediate_states.push(state);
    }
    WireDerived {
        intermediate_states,
    }
}
