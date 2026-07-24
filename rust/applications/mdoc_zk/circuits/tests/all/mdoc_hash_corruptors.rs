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

#![allow(dead_code)]

use compile_algebra::CompileNat;
use core_algebra::Nat;
use mdoc_zk_circuits::hash::concrete::ConcreteGiven;

pub struct MdocHashCorruptor {
    pub name: String,
    pub expected_path: String,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven)>,
}

pub fn all_mdoc_hash_corruptors() -> Vec<MdocHashCorruptor> {
    vec![
        MdocHashCorruptor {
            name: "corrupt_issuer_sig_e".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_message_hash/hash_eq/hash_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.hash_input.issuer_sig_e = CompileNat::<4>::from_u64(0xdeadbeef);
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_preimage_byte".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_message_hash/assert_intermediate_hashes/assert_intermediate_hashes.0/sha256/schedule/schedule.1/assert_wrapping_sum_gf2"
                    .into(),
            corrupt: Box::new(|g| {
                g.preimage.value[10] ^= 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_doc_type_offset".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_doc_type/cbor_header/cbor_header.0/header_byte"
                    .into(),
            corrupt: Box::new(|g| {
                g.doc_type_offset_in_preimage += 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_valid_from_offset".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_validity/valid_from/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.valid_from_offset_in_preimage += 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_valid_until_offset".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_validity/valid_until/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.valid_until_offset_in_preimage += 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_dev_key_info_offset".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_device_key/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.dev_key_info_offset_in_preimage += 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_value_digests_offset".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_value_digests/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.value_digests_offset_in_preimage += 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_mac_av".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_mac_tags/assert_mac/msg0_eq".into(),
            corrupt: Box::new(|g| {
                g.mac_input.mac_av ^= 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_mac_e".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_mac_tags/assert_mac/msg0_eq".into(),
            corrupt: Box::new(|g| {
                g.mac_e[0] ^= 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_mac_device_pkx".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_mac_tags/assert_mac/msg0_eq".into(),
            corrupt: Box::new(|g| {
                g.mac_device_pkx[0] ^= 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_mac_device_pky".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_mac_tags/assert_mac/msg0_eq".into(),
            corrupt: Box::new(|g| {
                g.mac_device_pky[0] ^= 1;
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_attribute_permutation_duplicate".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_attributes/assert_attributes.0/attribute_item/assert_attribute/assert_permutation/assert_permutation.0/perm_neq"
                    .into(),
            corrupt: Box::new(|g| {
                if let Some(attr) = g.attribute_given.get_mut(0) {
                    attr.field_locator.permutation = 1 | (1 << 2) | (2 << 4) | (3 << 6);
                }
            }),
        },
        MdocHashCorruptor {
            name: "corrupt_attribute_permutation_swap".into(),
            expected_path:
                "assert_valid_presentation_and_macs/assert_valid_presentation/assert_attributes/assert_attributes.0/attribute_item/assert_attribute/assert_item_slot_key_only/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                if let Some(attr) = g.attribute_given.get_mut(0) {
                    attr.field_locator.permutation = 1 | (2 << 4) | (3 << 6);
                }
            }),
        },
    ]
}
