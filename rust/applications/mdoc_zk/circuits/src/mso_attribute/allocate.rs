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

use crate::mso_attribute::{
    circuit::{AttrSlice, Derived, DisclosedAttribute, FieldLocator, Given},
    constants::K_ATTR_INDEX_BITS,
};

pub fn allocate_given<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = circuits_bitvec::BitvecIO::new(bv);
    let attribute_preimage = AttrSlice {
        data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
        len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
    };

    let field_locator = FieldLocator {
        slot_position: std::array::from_fn(|_| bitvec_io.next::<K_ATTR_INDEX_BITS>(pos)),
        length: std::array::from_fn(|_| bitvec_io.next::<K_ATTR_INDEX_BITS>(pos)),
        permutation: std::array::from_fn(|_| bitvec_io.next::<2>(pos)),
    };

    let disclosed_attribute = DisclosedAttribute {
        expected_name: AttrSlice {
            data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
            len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
        },
        expected_cbor_value: AttrSlice {
            data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
            len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
        },
    };

    let expected_digest = bitvec_io.next::<256>(pos);

    Given {
        attribute_preimage,
        field_locator,
        disclosed_attribute,
        expected_digest,
    }
}

pub fn allocate_derived<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Derived<L> {
    circuits_sha256msg::allocate_derived::<_, 2>(bv, pos)
}
