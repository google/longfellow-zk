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

use circuits_bitvec::{BitvecLogic, V128};
use compile_logic::Logic;

use super::{circuit::Given as WireGiven, concrete::ConcreteGiven};

pub fn evaluate_given<L: Logic>(
    logic: &L,
    bv: &BitvecLogic<L>,
    given: &ConcreteGiven,
) -> WireGiven<L> {
    let boolean = circuits_boolean::Boolean::new(logic);
    let message = bv.from_fn::<256, _>(|idx| {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        let byte = given.message[byte_idx];
        let bit_val = (byte.checked_shr(bit_idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    });

    let of_u128 = |val: u128| -> V128<L> {
        bv.from_fn::<128, _>(|idx| {
            let bit_val = (val.checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
            boolean.konst(bit_val)
        })
    };

    let mac_av = of_u128(given.mac_av);
    let mac_ap = [of_u128(given.mac_ap[0]), of_u128(given.mac_ap[1])];
    let tag = [of_u128(given.tag[0]), of_u128(given.tag[1])];

    WireGiven {
        message,
        mac_av,
        mac_ap,
        tag,
    }
}
