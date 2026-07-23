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

use circuits_sha256msg::concrete::{ConcreteDerived, ConcreteGiven};

#[allow(dead_code)]
pub struct Sha256MsgCorruptor {
    pub name: &'static str,
    pub expected_path: &'static str,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven, &mut ConcreteDerived)>,
}

pub fn all_sha256msg_corruptors() -> Vec<Sha256MsgCorruptor> {
    let bitflips = (0..8)
        .flat_map(|word_idx| {
            (0..32).map(move |bit_idx| Sha256MsgCorruptor {
                name: "expected_hash_bitflip",
                expected_path: "hash_eq",
                corrupt: Box::new(move |g, _d| {
                    g.expected_hash[word_idx] ^= 1 << bit_idx;
                }),
            })
        })
        .chain((0..64).flat_map(|byte_idx| {
            (0..8).map(move |bit_idx| Sha256MsgCorruptor {
                name: "padded_preimage_bitflip",
                expected_path: "assert_intermediate_hashes",
                corrupt: Box::new(move |g, _d| {
                    g.padded_preimage[byte_idx] ^= 1 << bit_idx;
                }),
            })
        }))
        .chain((0..64).map(|bit_idx| Sha256MsgCorruptor {
            name: "length_bytes_bitflip",
            expected_path: "assert_message_hash",
            corrupt: Box::new(move |g, _d| {
                g.length_bytes ^= 1 << bit_idx;
            }),
        }));

    let explicit = vec![
        Sha256MsgCorruptor {
            name: "nblocks_zero",
            expected_path: "nblocks_nz",
            corrupt: Box::new(|g, _d| {
                g.nblocks = 0;
            }),
        },
        Sha256MsgCorruptor {
            name: "nblocks_too_large",
            expected_path: "nblocks_max",
            corrupt: Box::new(|g, _d| {
                g.nblocks = 3; // For MAX_BLOCKS = 2
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_off_by_one_56",
            expected_path: "assert_nblocks",
            corrupt: Box::new(|g, _d| {
                g.nblocks = 1;
                g.length_bytes = 56; // 56 + 9 = 65 > 64 (1 block capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_off_by_one_120",
            expected_path: "assert_nblocks",
            corrupt: Box::new(|g, _d| {
                g.nblocks = 2;
                g.length_bytes = 120; // 120 + 9 = 129 > 128 (2 blocks capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_u64_max_minus_8",
            expected_path: "assert_nblocks",
            corrupt: Box::new(|g, _d| {
                g.length_bytes = u64::MAX - 8;
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_u64_max",
            expected_path: "assert_nblocks",
            corrupt: Box::new(|g, _d| {
                g.length_bytes = u64::MAX;
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_lower_off_by_one_55",
            expected_path: "limit_lower",
            corrupt: Box::new(|g, _d| {
                g.nblocks = 2;
                g.length_bytes = 55; // 55 + 72 = 127 < 128 (2 blocks capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_padding_separator",
            expected_path: "separator",
            corrupt: Box::new(|g, _d| {
                let idx = g.length_bytes as usize;
                if idx < g.padded_preimage.len() {
                    g.padded_preimage[idx] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_padding_zero_byte",
            expected_path: "pad_zero",
            corrupt: Box::new(|g, _d| {
                let idx = (g.length_bytes + 1) as usize;
                if idx < g.padded_preimage.len().saturating_sub(8) {
                    g.padded_preimage[idx] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_beyond_active_block",
            expected_path: "beyond_active",
            corrupt: Box::new(|g, _d| {
                if g.padded_preimage.len() > 64 {
                    g.padded_preimage[64] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_encoded_length_field",
            expected_path: "len_eq",
            corrupt: Box::new(|g, _d| {
                let active_end = (g.nblocks as usize) * 64;
                if active_end > 0 && active_end <= g.padded_preimage.len() {
                    g.padded_preimage[active_end - 1] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_derived_intermediate_h1",
            expected_path: "hash_eq",
            corrupt: Box::new(|_g, d| {
                if !d.sha_derived.is_empty() {
                    d.sha_derived[0].h1[0] ^= 1;
                }
            }),
        },
    ];

    bitflips.chain(explicit).collect()
}
