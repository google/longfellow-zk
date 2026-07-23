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

use circuits_analog_adder::FieldWrappingSum;
use circuits_bitvec::{Bitvec, BitvecLogic, V256, V32, V64, V8};
use circuits_boolean::Boolean;
use circuits_sha256::{Derived as Sha256Derived, Sha256};
use compile_logic::Logic;

pub struct Given<L: Logic, const S: usize> {
    pub padded_preimage: Vec<V8<L>>,
    pub nblocks: Bitvec<L, S>,
    pub length_bytes: V64<L>,
    pub expected_hash: V256<L>,
}

pub type Derived<L> = Vec<Sha256Derived<L>>;

pub struct Sha256Msg<'a, L: Logic, const MAX_BLOCKS: usize>
where L::F: FieldWrappingSum
{
    logic: &'a L,
    pub(crate) sha: Sha256<'a, L>,
    pub(crate) bv: BitvecLogic<'a, L>,
    boolean: Boolean<'a, L>,
}

impl<'a, L: Logic, const MAX_BLOCKS: usize> Sha256Msg<'a, L, MAX_BLOCKS>
where L::F: FieldWrappingSum
{
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            sha: Sha256::new(logic),
            bv: BitvecLogic::new(logic),
            boolean: Boolean::new(logic),
        }
    }

    fn initial_context(&self) -> [V32<L>; 8] {
        let initial = [
            0x6a09e667u32,
            0xbb67ae85u32,
            0x3c6ef372u32,
            0xa54ff53au32,
            0x510e527fu32,
            0x9b05688cu32,
            0x1f83d9abu32,
            0x5be0cd19u32,
        ];
        std::array::from_fn(|i| self.bv.of_u32(initial[i]))
    }

    /// Asserts that the SHA-256 compression is correctly executed for
    /// all blocks, and that any idle blocks beyond `nblocks` are
    /// properly padded with zero bytes.
    pub fn assert_intermediate_hashes(
        &self,
        input_bytes: &[V8<L>],
        derived: &[Sha256Derived<L>],
    ) -> L::Assertions {
        let mut h = self.initial_context();
        self.logic
            .assert_mapi("assert_intermediate_hashes", 0..MAX_BLOCKS, |b| {
                let inb = &input_bytes[64 * b..64 * (b + 1)];
                let tmp: [V32<L>; 16] = std::array::from_fn(|i| {
                    let mut word_bits = Vec::with_capacity(32);
                    word_bits.extend(inb[4 * i + 3].iter().cloned());
                    word_bits.extend(inb[4 * i + 2].iter().cloned());
                    word_bits.extend(inb[4 * i + 1].iter().cloned());
                    word_bits.extend(inb[4 * i].iter().cloned());
                    V32::new(word_bits)
                });

                let block_given = circuits_sha256::Given {
                    input_block: tmp,
                    h0: h.clone(),
                };
                let block_assertion = self.sha.assert_transform_block(&block_given, &derived[b]);
                h = derived[b].h1.clone();
                block_assertion
            })
    }

    /// Asserts that the SHA-256 hash output of the active message
    /// (located at the end of block `nblocks - 1`) matches the expected
    /// hash `expected_hash`.
    pub fn assert_final_hash<const S: usize>(
        &self,
        expected_hash: &V256<L>,
        nblocks: &Bitvec<L, S>,
        derived: &[Sha256Derived<L>],
    ) -> L::Assertions {
        // Create a selector vector where the b-th bit is true if and
        // only if nblocks == b + 1.  Because the number of blocks
        // `nblocks` is 1-indexed, this creates a one-hot selector
        // indicating which block index (0..MAX_BLOCKS) is the final
        // block of the message.
        let mut selector = Vec::with_capacity(MAX_BLOCKS);
        for b in 0..MAX_BLOCKS {
            let b1_wire = self.bv.of_u64((b + 1) as u64);
            selector.push(self.bv.eqb(nblocks, &b1_wire));
        }

        let mut x = Vec::with_capacity(8);
        for i in 0..8 {
            x.push(
                self.bv
                    .one_hot_mux(&selector, &|b| derived[b].h1[i].clone()),
            );
        }

        // Unpack the hash into a v256 in reverse byte-order.
        let mut mm_bits = vec![self.boolean.falseb(); 256];
        for j in 0..8 {
            for k in 0..32 {
                mm_bits[(7 - j) * 32 + k] = x[j][k].clone();
            }
        }
        let mm = V256::new(mm_bits);

        self.bv.assert_eq("hash_eq", &mm, expected_hash)
    }

    /// Asserts that `nblocks` is within valid range limits: 0 <
    /// `nblocks` <= `MAX_BLOCKS`, and mathematically consistent with
    /// the message's byte length `length_bytes`.
    pub fn assert_nblocks<const S: usize>(
        &self,
        nblocks: &Bitvec<L, S>,
        length_bytes: &V64<L>,
    ) -> L::Assertions {
        // Assert nblocks > 0 (nblocks != 0)
        let non_zero_assertion = self
            .boolean
            .assert_false("nblocks_nz", &self.bv.is_zero(nblocks));

        // Assert nblocks <= MAX_BLOCKS
        let leq_assertion = self.boolean.assert_true(
            "nblocks_max",
            &self.bv.leq(nblocks, &self.bv.of_u64(MAX_BLOCKS as u64)),
        );

        // Zero-extend nblocks to 64 bits to prevent shift overflow
        let nblocks_64 = self.bv.zext(nblocks);

        // nblocks_times_64 = nblocks << 6
        let (nblocks_times_64, shl_assertion) = self.bv.shl_safe(6, &nblocks_64);

        // length_bytes + 9 <= nblocks * 64
        let (limit_upper, carry_upper_assertion) =
            self.bv.checked_add(length_bytes, &self.bv.of_u64(9));
        let upper_bound = self
            .boolean
            .assert_true("limit_upper", &self.bv.leq(&limit_upper, &nblocks_times_64));

        // nblocks * 64 <= length_bytes + 72
        let (limit_lower, carry_lower_assertion) =
            self.bv.checked_add(length_bytes, &self.bv.of_u64(72));
        let lower_bound = self
            .boolean
            .assert_true("limit_lower", &self.bv.leq(&nblocks_times_64, &limit_lower));

        self.logic.assert_all(
            "assert_nblocks",
            &[
                non_zero_assertion,
                leq_assertion,
                shl_assertion,
                carry_upper_assertion,
                upper_bound,
                carry_lower_assertion,
                lower_bound,
            ],
        )
    }

    /// Asserts that the actual message length matches the encoded
    /// length field embedded inside the SHA-256 padded message.
    pub fn assert_length<const S: usize>(
        &self,
        nblocks: &Bitvec<L, S>,
        length_bytes: &V64<L>,
        input_bytes: &[V8<L>],
    ) -> L::Assertions {
        // block_selector[b] is true if and only if nblocks == b + 1
        let mut block_selector = Vec::with_capacity(MAX_BLOCKS);
        for b in 0..MAX_BLOCKS {
            let b1_wire = self.bv.of_u64((b + 1) as u64);
            block_selector.push(self.bv.eqb(nblocks, &b1_wire));
        }

        let encoded_len = self.bv.one_hot_mux(&block_selector, &|b| {
            // Extract the length field from the end of block `b`.
            let mut len_from_blocks = Vec::with_capacity(64);
            for j in 0..64 {
                let byte_idx = b * 64 + 63 - j / 8;
                let bit_idx = j % 8;
                len_from_blocks.push(self.boolean.b(&input_bytes[byte_idx][bit_idx]));
            }
            Bitvec::new(len_from_blocks)
        });
        // The encoded length field in SHA-256 padding is in bits,
        // so we must compare it to length_bytes * 8.
        let (length_bits, shl_assertion) = self.bv.shl_safe(3, length_bytes);
        let eq_assertion = self.bv.assert_eq("len_eq", &encoded_len, &length_bits);
        self.logic
            .assert_all("assert_length", &[eq_assertion, shl_assertion])
    }

    /// Asserts that the message padding is correct: starts with 0x80
    /// separator, followed by zero bytes up to the length field, and
    /// that all blocks beyond the active blocks `nblocks` are
    /// completely zeroed.
    pub fn assert_sha_padding<const S: usize>(
        &self,
        nblocks: &Bitvec<L, S>,
        length_bytes: &V64<L>,
        input_bytes: &[V8<L>],
    ) -> L::Assertions {
        // Zero-extend nblocks to 64 bits to prevent shift overflow
        let nblocks_64 = self.bv.zext(nblocks);

        // nblocks_times_64 = nblocks << 6
        let (nblocks_times_64, shl_assertion) = self.bv.shl_safe(6, &nblocks_64);

        let u8_80 = self.bv.of_u8(0x80);
        let u8_00 = self.bv.of_u8(0x00);

        let byte_padding_assertions =
            self.logic
                .assert_mapi("byte_padding", 0..(MAX_BLOCKS * 64), |byte_idx| {
                    let byte_idx_wire = self.bv.of_u64(byte_idx as u64);
                    let byte_idx_plus_8_wire = self.bv.of_u64((byte_idx + 8) as u64);

                    let is_separator = self.bv.eqb(length_bytes, &byte_idx_wire);

                    let is_after_msg = self.bv.lt(length_bytes, &byte_idx_wire);
                    let is_before_len_field = self.bv.gt(&nblocks_times_64, &byte_idx_plus_8_wire);
                    let is_padding_zero = self.boolean.andb(&is_after_msg, &is_before_len_field);

                    let is_beyond_active = self.bv.leq(&nblocks_times_64, &byte_idx_wire);

                    let is_80 = self.bv.eqb(&input_bytes[byte_idx], &u8_80);
                    let is_00 = self.bv.eqb(&input_bytes[byte_idx], &u8_00);

                    let sep_ok = self.boolean.impliesb(&is_separator, &is_80);
                    let pad_zero_ok = self.boolean.impliesb(&is_padding_zero, &is_00);
                    let beyond_active_zero_ok = self.boolean.impliesb(&is_beyond_active, &is_00);

                    self.logic.assert_all(
                        "byte_step",
                        &[
                            self.boolean.assert_true("separator", &sep_ok),
                            self.boolean.assert_true("pad_zero", &pad_zero_ok),
                            self.boolean
                                .assert_true("beyond_active", &beyond_active_zero_ok),
                        ],
                    )
                });

        self.logic.assert_all(
            "assert_sha_padding",
            &[shl_assertion, byte_padding_assertions],
        )
    }

    /// Verifies the full SHA-256 process of a message of byte length
    /// `length_bytes` across `nblocks` blocks, asserting that nblocks is
    /// bounds-checked and consistent with length, that the encoded padding
    /// length field matches the length in bits, and that the hash matches
    /// `expected_hash`.
    pub fn assert_message_hash<const S: usize>(
        &self,
        given: &Given<L, S>,
        derived: &[Sha256Derived<L>],
    ) -> L::Assertions {
        let nblocks_assertion = self.assert_nblocks(&given.nblocks, &given.length_bytes);
        let length_assertion =
            self.assert_length(&given.nblocks, &given.length_bytes, &given.padded_preimage);

        let intermediate_hashes_assertion =
            self.assert_intermediate_hashes(&given.padded_preimage, derived);
        let final_hash_assertion =
            self.assert_final_hash(&given.expected_hash, &given.nblocks, derived);
        let sha_padding_assertion =
            self.assert_sha_padding(&given.nblocks, &given.length_bytes, &given.padded_preimage);

        self.logic.assert_all(
            "assert_message_hash",
            &[
                nblocks_assertion,
                length_assertion,
                intermediate_hashes_assertion,
                final_hash_assertion,
                sha_padding_assertion,
            ],
        )
    }
}
