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
    circuit::{
        AttrSlice, Derived as WireDerived, DisclosedAttribute as WireDisclosedAttribute,
        FieldLocator as WireFieldLocator, Given as WireGiven,
    },
    concrete::{ConcreteDerived, ConcreteGiven},
    constants::K_ATTR_INDEX_BITS,
};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> WireGiven<L> {
    let get_padded = |vec: &[u8], i: usize| -> u8 {
        if i < vec.len() {
            vec[i]
        } else {
            0
        }
    };

    let attribute_preimage = AttrSlice {
        data: std::array::from_fn(|i| bv.of_u8(get_padded(&given.preimage, i))),
        len: bv.of_u64::<K_ATTR_INDEX_BITS>(given.preimage.len() as u64),
    };

    let field_locator = WireFieldLocator {
        slot_position: std::array::from_fn(|i| {
            bv.of_u64::<K_ATTR_INDEX_BITS>(given.field_locator.slot_position[i] as u64)
        }),
        length: std::array::from_fn(|i| {
            bv.of_u64::<K_ATTR_INDEX_BITS>(given.field_locator.length[i] as u64)
        }),
        permutation: std::array::from_fn(|i| {
            let slot = (given.field_locator.permutation >> (2 * i)) & 3;
            bv.of_u64::<2>(slot as u64)
        }),
    };

    let disclosed_attribute = WireDisclosedAttribute {
        expected_name: AttrSlice {
            data: std::array::from_fn(|i| bv.of_u8(get_padded(&given.name, i))),
            len: bv.of_u64::<K_ATTR_INDEX_BITS>(given.name.len() as u64),
        },
        expected_cbor_value: AttrSlice {
            data: std::array::from_fn(|i| bv.of_u8(get_padded(&given.cbor_value, i))),
            len: bv.of_u64::<K_ATTR_INDEX_BITS>(given.cbor_value.len() as u64),
        },
    };

    let boolean = circuits_boolean::Boolean::new(bv.logic());
    let expected_digest = bv.from_fn::<256, _>(|idx| {
        let word_idx = 7 - (idx / 32);
        let bit_idx = idx % 32;
        let w = given.expected_digest[word_idx];
        let bit_val = (w.checked_shr(bit_idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    });

    WireGiven {
        attribute_preimage,
        field_locator,
        disclosed_attribute,
        expected_digest,
    }
}

pub fn evaluate_derived<L: Logic>(
    derived: &ConcreteDerived,
    bv: &BitvecLogic<L>,
) -> WireDerived<L> {
    circuits_sha256msg::evaluate::evaluate_derived(&derived.sha_derived, bv)
}
