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

#[derive(Clone)]
pub struct MsoAttributeMockGiven {
    pub raw_buf: Vec<u8>,
    pub slot_position: [u64; 4],
    pub length: [u64; 4],
    pub permutation: [u64; 4],
    pub disclosed_name: Vec<u8>,
    pub disclosed_name_len: u64,
    pub disclosed_value: Vec<u8>,
    pub disclosed_value_len: u64,
    pub preimage_len: u64,
}

pub struct MsoAttributeCorruptor {
    pub name: String,
    pub expected_path: String,
    pub corrupt: Box<dyn Fn(&mut MsoAttributeMockGiven)>,
}

pub fn all_mso_attribute_corruptors() -> Vec<MsoAttributeCorruptor> {
    // Systematic bitflips across all active bytes of disclosed_name (12 bytes x 8 bits)
    let name_bitflips = (0..12).flat_map(|byte_idx| {
        (0..8).map(move |bit_idx| MsoAttributeCorruptor {
            name: format!("disclosed_name[{byte_idx}].bit[{bit_idx}]"),
            expected_path: format!(
                "assert_attribute/assert_item_slot_key_value/assert_prefix_equal/assert_prefix_equal.{}/prefix_imp/prefix_imp.{bit_idx}/bit.{bit_idx}",
                18 + byte_idx
            ),
            corrupt: Box::new(move |g| {
                if byte_idx < g.disclosed_name.len() {
                    g.disclosed_name[byte_idx] ^= 1 << bit_idx;
                }
            }),
        })
    });

    // Systematic bitflips across all active bytes of disclosed_value (1 byte x 8 bits)
    let value_bitflips = (0..1).flat_map(|byte_idx| {
        (0..8).map(move |bit_idx| MsoAttributeCorruptor {
            name: format!("disclosed_value[{byte_idx}].bit[{bit_idx}]"),
            expected_path: format!(
                "assert_attribute/assert_item_slot_key_value/assert_prefix_equal/assert_prefix_equal.{}/prefix_imp/prefix_imp.{bit_idx}/bit.{bit_idx}",
                13 + byte_idx
            ),
            corrupt: Box::new(move |g| {
                if byte_idx < g.disclosed_value.len() {
                    g.disclosed_value[byte_idx] ^= 1 << bit_idx;
                }
            }),
        })
    });

    let explicit = vec![
        // len = 0 witness attacks
        MsoAttributeCorruptor {
            name: "disclosed_name_len_zero".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/cbor_len_eq/cbor_len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_name_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "disclosed_value_len_zero".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/cbor_len_eq/cbor_len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_value_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "preimage_len_zero".into(),
            expected_path:
                "assert_attribute/assert_message_hash/assert_length/len_eq/len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.preimage_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "field_locator_slot_2_length_zero".into(),
            expected_path:
                "assert_attribute/assert_segments/contiguous_segments/contiguous_segments.2/assert_checked_add/assert_wrapping_add/rest_assert/rest_assert.0/bit_carry"
                    .into(),
            corrupt: Box::new(|g| {
                g.length[2] = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "field_locator_slot_3_length_zero".into(),
            expected_path:
                "assert_attribute/assert_segments/assert_checked_add/assert_wrapping_add/rest_assert/rest_assert.0/bit_carry"
                    .into(),
            corrupt: Box::new(|g| {
                g.length[3] = 0;
            }),
        },
        // CBOR header / structure tampering
        MsoAttributeCorruptor {
            name: "cbor_tag_24_tamper".into(),
            expected_path:
                "assert_attribute/assert_preimage_header/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.raw_buf[0] = 0x00;
            }),
        },
        MsoAttributeCorruptor {
            name: "cbor_map_tag_tamper".into(),
            expected_path:
                "assert_attribute/assert_preimage_header/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.raw_buf[4] = 0xA5;
            }),
        },
        MsoAttributeCorruptor {
            name: "cbor_payload_len_tamper".into(),
            expected_path:
                "assert_attribute/assert_preimage_header/assert_checked_add/assert_wrapping_add/rest_assert/rest_assert.3/bit_carry"
                    .into(),
            corrupt: Box::new(|g| {
                g.raw_buf[3] = 0x50;
            }),
        },
        MsoAttributeCorruptor {
            name: "first_segment_offset_attack".into(),
            expected_path:
                "assert_attribute/assert_segments/first_segment_start/first_segment_start.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.slot_position[0] = 6;
            }),
        },
        MsoAttributeCorruptor {
            name: "non_contiguous_segment_gap_attack".into(),
            expected_path:
                "assert_attribute/assert_segments/contiguous_segments/contiguous_segments.1/assert_checked_add/assert_wrapping_add/bit0"
                    .into(),
            corrupt: Box::new(|g| {
                g.slot_position[2] = 57;
            }),
        },
        MsoAttributeCorruptor {
            name: "payload_total_length_underflow_attack".into(),
            expected_path:
                "assert_attribute/assert_segments/assert_checked_add/assert_wrapping_add/bit0"
                    .into(),
            corrupt: Box::new(|g| {
                g.length[3] = 13;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_digest_id_key".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_only/assert_bytes_at/assert_bytes_at.1/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.raw_buf[6] = 99; // Corrupt 'd' in "digestID"
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_content_byte".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_only/assert_bytes_at/assert_bytes_at.5/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.raw_buf[10] = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_len".into(),
            expected_path:
                "assert_attribute/assert_message_hash/assert_length/len_eq/len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.preimage_len = 99;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_name_data".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/assert_prefix_equal/assert_prefix_equal.22/prefix_imp/prefix_imp.0/bit.0"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_name[4] = b'x';
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_name_len".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/cbor_len_eq/cbor_len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_name_len = 13;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_value_data".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/assert_prefix_equal/assert_prefix_equal.13/prefix_imp/prefix_imp.0/bit.0"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_value[0] = 0xf4; // False instead of True
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_value_len".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_value/cbor_len_eq/cbor_len_eq.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.disclosed_value_len = 2;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_slot_position".into(),
            expected_path:
                "assert_attribute/assert_segments/contiguous_segments/contiguous_segments.0/assert_checked_add/assert_wrapping_add/bit0"
                    .into(),
            corrupt: Box::new(|g| {
                g.slot_position[1] = 14;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_slot_length".into(),
            expected_path:
                "assert_attribute/assert_segments/contiguous_segments/contiguous_segments.1/assert_checked_add/assert_wrapping_add/bit0"
                    .into(),
            corrupt: Box::new(|g| {
                g.length[1] = 42;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_permutation_duplicate".into(),
            expected_path:
                "assert_attribute/assert_permutation/assert_permutation.0/perm_neq".into(),
            corrupt: Box::new(|g| {
                g.permutation[0] = 1;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_permutation_swap".into(),
            expected_path:
                "assert_attribute/assert_item_slot_key_only/assert_bytes_at/assert_bytes_at.0/bytes_at/bytes_at.0/chunk_eq"
                    .into(),
            corrupt: Box::new(|g| {
                g.permutation[0] = 1;
                g.permutation[1] = 0;
            }),
        },
    ];

    name_bitflips
        .chain(value_bitflips)
        .chain(explicit)
        .collect()
}
