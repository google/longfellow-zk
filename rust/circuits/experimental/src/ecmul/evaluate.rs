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

use circuits_ec::{evaluate_pt2, evaluate_pt3};
use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::Logic;

use super::{
    circuit::{Derived as WireDerived, Given as WireGiven},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    given: &ConcreteGiven<W, F>,
    logic: &L,
    n: usize,
) -> WireGiven<L> {
    let boolean = circuits_boolean::Boolean::new(logic);
    let mut exp_bits = Vec::with_capacity(n);
    for i in 0..n {
        let bit_val = ((&given.exp >> i) & num_bigint::BigUint::from(1u32))
            == num_bigint::BigUint::from(1u32);
        exp_bits.push(boolean.konst(bit_val));
    }
    WireGiven {
        exp_bits,
        a: evaluate_pt2(&given.a, logic),
        b: evaluate_pt2(&given.b, logic),
    }
}

pub fn evaluate_derived<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    derived: &ConcreteDerived<W, F>,
    logic: &L,
) -> WireDerived<L> {
    let round = derived
        .round
        .iter()
        .map(|p| evaluate_pt3(p, logic))
        .collect();
    WireDerived {
        round,
        zinv: logic.konst(&derived.zinv),
    }
}
