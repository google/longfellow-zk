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
    pub name: &'static str,
    pub expected_path: &'static str,
    pub corrupt: Box<dyn Fn(&mut MsoAttributeMockGiven)>,
}

pub fn all_mso_attribute_corruptors() -> Vec<MsoAttributeCorruptor> {
    // Systematic bitflips across all active bytes of disclosed_name (12 bytes x 8 bits)
    let name_bitflips = (0..12).flat_map(|byte_idx| {
        (0..8).map(move |bit_idx| MsoAttributeCorruptor {
            name: "disclosed_name_byte_bitflip",
            expected_path: "prefix_equal",
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
            name: "disclosed_value_byte_bitflip",
            expected_path: "prefix_equal",
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
            name: "disclosed_name_len_zero",
            expected_path: "cbor_len_eq",
            corrupt: Box::new(|g| {
                g.disclosed_name_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "disclosed_value_len_zero",
            expected_path: "cbor_len_eq",
            corrupt: Box::new(|g| {
                g.disclosed_value_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "preimage_len_zero",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.preimage_len = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "field_locator_slot_2_length_zero",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.length[2] = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "field_locator_slot_3_length_zero",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.length[3] = 0;
            }),
        },
        // CBOR header / structure tampering
        MsoAttributeCorruptor {
            name: "cbor_tag_24_tamper",
            expected_path: "bytes_at",
            corrupt: Box::new(|g| {
                g.raw_buf[0] = 0x00;
            }),
        },
        MsoAttributeCorruptor {
            name: "cbor_map_tag_tamper",
            expected_path: "bytes_at",
            corrupt: Box::new(|g| {
                g.raw_buf[4] = 0xA5;
            }),
        },
        MsoAttributeCorruptor {
            name: "cbor_payload_len_tamper",
            expected_path: "assert_preimage_header",
            corrupt: Box::new(|g| {
                g.raw_buf[3] = 0x50;
            }),
        },
        MsoAttributeCorruptor {
            name: "first_segment_offset_attack",
            expected_path: "first_segment_start",
            corrupt: Box::new(|g| {
                g.slot_position[0] = 6;
            }),
        },
        MsoAttributeCorruptor {
            name: "non_contiguous_segment_gap_attack",
            expected_path: "contiguous_segments",
            corrupt: Box::new(|g| {
                g.slot_position[2] = 57;
            }),
        },
        MsoAttributeCorruptor {
            name: "payload_total_length_underflow_attack",
            expected_path: "assert_segments",
            corrupt: Box::new(|g| {
                g.length[3] = 13;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_digest_id_key",
            expected_path: "assert_bytes_at",
            corrupt: Box::new(|g| {
                g.raw_buf[6] = 99; // Corrupt 'd' in "digestID"
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_content_byte",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.raw_buf[10] = 0;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_preimage_len",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.preimage_len = 99;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_name_data",
            expected_path: "prefix_equal",
            corrupt: Box::new(|g| {
                g.disclosed_name[4] = b'x';
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_name_len",
            expected_path: "cbor_len_eq",
            corrupt: Box::new(|g| {
                g.disclosed_name_len = 13;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_value_data",
            expected_path: "prefix_equal",
            corrupt: Box::new(|g| {
                g.disclosed_value[0] = 0xf4; // False instead of True
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_disclosed_value_len",
            expected_path: "cbor_len_eq",
            corrupt: Box::new(|g| {
                g.disclosed_value_len = 2;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_slot_position",
            expected_path: "contiguous_segments",
            corrupt: Box::new(|g| {
                g.slot_position[1] = 14;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_slot_length",
            expected_path: "assert_attribute",
            corrupt: Box::new(|g| {
                g.length[1] = 42;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_permutation_duplicate",
            expected_path: "perm_neq",
            corrupt: Box::new(|g| {
                g.permutation[0] = 1;
            }),
        },
        MsoAttributeCorruptor {
            name: "bad_permutation_swap",
            expected_path: "assert_attribute",
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
