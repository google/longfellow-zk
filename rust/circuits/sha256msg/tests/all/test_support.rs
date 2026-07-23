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
    pub name: String,
    pub expected_path: String,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven, &mut ConcreteDerived)>,
}

impl Sha256MsgCorruptor {
    pub fn expected_compiled_path(&self) -> String {
        self.expected_path
            .replace("assert_wrapping_sum_gf2", "assert_wrapping_sum_prime")
    }
}

pub fn all_sha256msg_corruptors() -> Vec<Sha256MsgCorruptor> {
    let bitflips = (0..8)
        .flat_map(|word_idx| {
            (0..32).map(move |bit_idx| Sha256MsgCorruptor {
                name: format!("expected_hash[{word_idx}].bit[{bit_idx}]"),
                expected_path: format!(
                    "assert_message_hash/hash_eq/hash_eq.{}/chunk_eq",
                    1 - word_idx / 4
                ),
                corrupt: Box::new(move |g, _d| {
                    g.expected_hash[word_idx] ^= 1 << bit_idx;
                }),
            })
        })
        .chain((0..64).flat_map(|byte_idx| {
            (0..8).map(move |bit_idx| Sha256MsgCorruptor {
                name: format!("padded_preimage[{byte_idx}].bit[{bit_idx}]"),
                expected_path: format!(
                    "assert_message_hash/assert_intermediate_hashes/assert_intermediate_hashes.0/sha256/schedule/schedule.{}/assert_wrapping_sum_gf2",
                    byte_idx / 4
                ),
                corrupt: Box::new(move |g, _d| {
                    g.padded_preimage[byte_idx] ^= 1 << bit_idx;
                }),
            })
        }))
        .chain((0..64).map(|bit_idx| Sha256MsgCorruptor {
            name: format!("length_bytes.bit[{bit_idx}]"),
            expected_path: if bit_idx < 61 {
                "assert_message_hash/assert_length/len_eq/len_eq.0/chunk_eq".into()
            } else {
                format!(
                    "assert_message_hash/assert_length/shl_exact/shl_exact.{}/overflow_bit.{bit_idx}",
                    bit_idx - 61
                )
            },
            corrupt: Box::new(move |g, _d| {
                g.length_bytes ^= 1 << bit_idx;
            }),
        }));

    let explicit = vec![
        Sha256MsgCorruptor {
            name: "nblocks_zero".into(),
            expected_path: "assert_message_hash/assert_nblocks/nblocks_nz".into(),
            corrupt: Box::new(|g, _d| {
                g.nblocks = 0;
            }),
        },
        Sha256MsgCorruptor {
            name: "nblocks_too_large".into(),
            expected_path: "assert_message_hash/assert_nblocks/nblocks_max".into(),
            corrupt: Box::new(|g, _d| {
                g.nblocks = 3; // For MAX_BLOCKS = 2
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_off_by_one_56".into(),
            expected_path: "assert_message_hash/assert_nblocks/limit_upper".into(),
            corrupt: Box::new(|g, _d| {
                g.nblocks = 1;
                g.length_bytes = 56; // 56 + 9 = 65 > 64 (1 block capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_off_by_one_120".into(),
            expected_path: "assert_message_hash/assert_nblocks/limit_upper".into(),
            corrupt: Box::new(|g, _d| {
                g.nblocks = 2;
                g.length_bytes = 120; // 120 + 9 = 129 > 128 (2 blocks capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_u64_max_minus_8".into(),
            expected_path: "assert_message_hash/assert_nblocks/no_carry".into(),
            corrupt: Box::new(|g, _d| {
                g.length_bytes = u64::MAX - 8;
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_upper_u64_max".into(),
            expected_path: "assert_message_hash/assert_nblocks/no_carry".into(),
            corrupt: Box::new(|g, _d| {
                g.length_bytes = u64::MAX;
            }),
        },
        Sha256MsgCorruptor {
            name: "limit_lower_off_by_one_55".into(),
            expected_path: "assert_message_hash/assert_nblocks/limit_lower".into(),
            corrupt: Box::new(|g, _d| {
                g.nblocks = 2;
                g.length_bytes = 55; // 55 + 72 = 127 < 128 (2 blocks capacity)
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_padding_separator".into(),
            expected_path:
                "assert_message_hash/assert_sha_padding/byte_padding/byte_padding.11/byte_step/separator"
                    .into(),
            corrupt: Box::new(|g, _d| {
                let idx = g.length_bytes as usize;
                if idx < g.padded_preimage.len() {
                    g.padded_preimage[idx] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_padding_zero_byte".into(),
            expected_path:
                "assert_message_hash/assert_sha_padding/byte_padding/byte_padding.12/byte_step/pad_zero"
                    .into(),
            corrupt: Box::new(|g, _d| {
                let idx = (g.length_bytes + 1) as usize;
                if idx < g.padded_preimage.len().saturating_sub(8) {
                    g.padded_preimage[idx] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_beyond_active_block".into(),
            expected_path:
                "assert_message_hash/assert_sha_padding/byte_padding/byte_padding.64/byte_step/beyond_active"
                    .into(),
            corrupt: Box::new(|g, _d| {
                if g.padded_preimage.len() > 64 {
                    g.padded_preimage[64] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_encoded_length_field".into(),
            expected_path: "assert_message_hash/assert_length/len_eq/len_eq.0/chunk_eq".into(),
            corrupt: Box::new(|g, _d| {
                let active_end = (g.nblocks as usize) * 64;
                if active_end > 0 && active_end <= g.padded_preimage.len() {
                    g.padded_preimage[active_end - 1] ^= 1;
                }
            }),
        },
        Sha256MsgCorruptor {
            name: "corrupt_derived_intermediate_h1".into(),
            expected_path:
                "assert_message_hash/assert_intermediate_hashes/assert_intermediate_hashes.0/sha256/final/final.0/assert_wrapping_sum_gf2"
                    .into(),
            corrupt: Box::new(|_g, d| {
                if !d.sha_derived.is_empty() {
                    d.sha_derived[0].h1[0] ^= 1;
                }
            }),
        },
    ];

    bitflips.chain(explicit).collect()
}
