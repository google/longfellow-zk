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
use circuits_boolean::BooleanIO;
use compile_logic::LogicIO;

use crate::{
    hash::{
        circuit::{AttrDerived, AttrGiven, AttrPreimageBytes, Derived, Given, MsoPreimageBytes},
        constants::{K_HASH_INDEX_BITS, K_TIMESTAMP_LEN},
    },
    mso_attribute::constants::K_ATTR_INDEX_BITS,
};

pub fn allocate_given<L: LogicIO>(
    logic: &L,
    bv: &BitvecLogic<L>,
    num_attrs: usize,
    pos: &mut usize,
) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let boolean_io = BooleanIO::new(logic);

    let disclosed_attributes = (0..num_attrs)
        .map(|_| crate::mso_attribute::circuit::DisclosedAttribute {
            expected_name: crate::mso_attribute::circuit::AttrSlice {
                data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
                len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
            },
            expected_cbor_value: crate::mso_attribute::circuit::AttrSlice {
                data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
                len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
            },
        })
        .collect();

    let now: [circuits_bitvec::V8<L>; K_TIMESTAMP_LEN] =
        std::array::from_fn(|_| bitvec_io.next::<8>(pos));

    let mac_e = [logic.next(pos), logic.next(pos)];
    let mac_device_pkx = [logic.next(pos), logic.next(pos)];
    let mac_device_pky = [logic.next(pos), logic.next(pos)];
    let mac_av = logic.next(pos);

    let suppress_doc_type_check = boolean_io.next(pos);

    let expected_doc_type = crate::mso_attribute::circuit::AttrSlice {
        data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
        len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
    };

    let issuer_sig_e = bitvec_io.next::<256>(pos);
    let preimage = MsoPreimageBytes {
        value: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
        len: bitvec_io.next::<K_HASH_INDEX_BITS>(pos),
    };
    let nblocks = bitvec_io.next::<8>(pos);
    let device_pk = (bitvec_io.next::<256>(pos), bitvec_io.next::<256>(pos));
    let doc_type_offset_in_preimage = bitvec_io.next::<16>(pos);
    let valid_from_offset_in_preimage = bitvec_io.next::<16>(pos);
    let valid_until_offset_in_preimage = bitvec_io.next::<16>(pos);
    let dev_key_info_offset_in_preimage = bitvec_io.next::<16>(pos);
    let value_digests_offset_in_preimage = bitvec_io.next::<16>(pos);

    let attribute_given = (0..num_attrs)
        .map(|_| AttrGiven {
            preimage: AttrPreimageBytes {
                data: std::array::from_fn(|_| bitvec_io.next::<8>(pos)),
                len: bitvec_io.next::<K_ATTR_INDEX_BITS>(pos),
            },
            mso_digest_offset_in_preimage: bitvec_io.next::<16>(pos),
            field_locator: crate::mso_attribute::FieldLocator {
                slot_position: std::array::from_fn(|_| bitvec_io.next::<K_ATTR_INDEX_BITS>(pos)),
                length: std::array::from_fn(|_| bitvec_io.next::<K_ATTR_INDEX_BITS>(pos)),
                permutation: std::array::from_fn(|_| bitvec_io.next::<2>(pos)),
            },
        })
        .collect();

    let mac_ap = std::array::from_fn(|_| [logic.next(pos), logic.next(pos)]);

    Given {
        disclosed_attributes,
        now,
        suppress_doc_type_check,
        expected_doc_type,

        preimage,
        nblocks,
        issuer_sig_e,
        device_pk,
        doc_type_offset_in_preimage,
        valid_from_offset_in_preimage,
        valid_until_offset_in_preimage,
        dev_key_info_offset_in_preimage,
        value_digests_offset_in_preimage,
        attribute_given,
        mac_e,
        mac_device_pkx,
        mac_device_pky,
        mac_av,
        mac_ap,
    }
}

pub fn allocate_derived<L: LogicIO, const MAX_MSO_BLOCKS: usize>(
    bv: &BitvecLogic<L>,
    num_attrs: usize,
    pos: &mut usize,
) -> Derived<L> {
    let attribute_derived = (0..num_attrs)
        .map(|_| AttrDerived {
            sha_derived: circuits_sha256msg::allocate_derived::<_, 2>(bv, pos),
        })
        .collect();

    let sha_derived = circuits_sha256msg::allocate_derived::<_, MAX_MSO_BLOCKS>(bv, pos);

    Derived {
        attribute_derived,
        sha_derived,
    }
}
