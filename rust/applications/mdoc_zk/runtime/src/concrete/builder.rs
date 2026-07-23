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

use core_algebra::Nat;
use mdoc_zk_circuits::{MdocHashRuntimeField, MdocSigRuntimeField};

use crate::config::{
    K_HASH_V256_BIT_PLUCKER, K_HASH_V8_BIT_PLUCKER, K_SHA_BIT_PLUCKER, K_SIG_MAC_BIT_PLUCKER,
};

pub struct AssignmentBuilder<'a, F: core_algebra::BareField + core_algebra::AlgebraicField> {
    pub field: &'a F,
    pub(crate) buffer: Vec<F::E>,
}

impl<'a, F: core_algebra::BareField + core_algebra::AlgebraicField> AssignmentBuilder<'a, F> {
    pub fn new(field: &'a F) -> Self {
        Self {
            field,
            buffer: Vec::new(),
        }
    }

    pub fn push_elt(&mut self, elt: &F::E) {
        self.buffer.push(elt.clone());
    }

    pub fn into_inner(self) -> Vec<F::E> {
        self.buffer
    }

    #[inline(always)]
    fn push_bit(&mut self, bit: bool) {
        self.buffer.push(if bit {
            self.field.one()
        } else {
            self.field.zero()
        });
    }

    pub fn push_bits_len(&mut self, val: u64, nbits: usize) {
        let mut cur_val = val;
        for _ in 0..nbits {
            self.push_bit((cur_val & 1) != 0);
            cur_val >>= 1;
        }
    }

    pub fn push_raw_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.push_bits_len(u64::from(b), 8);
        }
    }

    pub fn push_pad(&mut self, pad_elt: F::E, count: usize) {
        self.buffer.extend(std::iter::repeat_n(pad_elt, count));
    }

    pub fn push_ecdsa_given(&mut self, given: &circuits_ecdsa2::concrete::ConcreteGiven<F>) {
        given.push_elements(|elt| self.push_elt(elt));
    }

    pub fn push_ecdsa_derived(&mut self, derived: &circuits_ecdsa2::concrete::ConcreteDerived<F>) {
        derived.push_elements(|elt| self.push_elt(elt));
    }
}

impl<F: core_algebra::BareField + core_algebra::AlgebraicField + core_algebra::HasLookupPoints>
    AssignmentBuilder<'_, F>
{
    fn pack_bits_to_elements<const PLUCKER_WIDTH: usize>(&self, bits: &[bool]) -> Vec<F::E> {
        let num_chunks = bits.len().div_ceil(PLUCKER_WIDTH);
        let mut elts = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let mut v = 0usize;
            for j in 0..PLUCKER_WIDTH {
                let idx = i * PLUCKER_WIDTH + j;
                if idx < bits.len() && bits[idx] {
                    v |= 1 << j;
                }
            }
            elts.push(circuits_bit_plucker::encoding_point::<F, PLUCKER_WIDTH>(
                self.field, v,
            ));
        }
        elts
    }

    fn push_value_plucked<const PLUCKER_WIDTH: usize, const BIT_LEN: usize>(&mut self, val: u128) {
        let mut bits = [false; BIT_LEN];
        let mut cur_val = val;
        for item in &mut bits {
            *item = (cur_val & 1) != 0;
            cur_val >>= 1;
        }
        let elts = self.pack_bits_to_elements::<PLUCKER_WIDTH>(&bits);
        self.buffer.extend(elts);
    }

    fn push_nat_plucked<const PLUCKER_WIDTH: usize, const W: usize, N: Nat<W>>(&mut self, nat: &N) {
        let mut bytes = nat.to_bytes_le();
        bytes.resize(W * 8, 0);

        let mut bits = vec![false; W * 64];
        for (i, &byte) in bytes.iter().enumerate() {
            let mut cur_byte = byte;
            for k in 0..8 {
                bits[i * 8 + k] = (cur_byte & 1) != 0;
                cur_byte >>= 1;
            }
        }

        let elts = self.pack_bits_to_elements::<PLUCKER_WIDTH>(&bits);
        self.buffer.extend(elts);
    }
    fn pack_bits_to_elements_legacy<const PLUCKER_WIDTH: usize>(&self, bits: &[bool]) -> Vec<F::E> {
        let num_chunks = bits.len().div_ceil(PLUCKER_WIDTH);
        let mut elts = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let mut v = 0usize;
            for j in 0..PLUCKER_WIDTH {
                let idx = i * PLUCKER_WIDTH + j;
                if idx < bits.len() && bits[idx] {
                    v |= 1 << j;
                }
            }
            elts.push(self.field.lookup_point(1 << PLUCKER_WIDTH, v));
        }
        elts
    }

    fn push_value_plucked_legacy<const PLUCKER_WIDTH: usize, const BIT_LEN: usize>(
        &mut self,
        val: u128,
    ) {
        let mut bits = [false; BIT_LEN];
        let mut cur_val = val;
        for item in &mut bits {
            *item = (cur_val & 1) != 0;
            cur_val >>= 1;
        }
        let elts = self.pack_bits_to_elements_legacy::<PLUCKER_WIDTH>(&bits);
        self.buffer.extend(elts);
    }
}

impl<F: MdocHashRuntimeField> AssignmentBuilder<'_, F> {
    pub fn push_v8(&mut self, byte: u8) {
        self.push_value_plucked::<{ K_HASH_V8_BIT_PLUCKER }, 8>(u128::from(byte));
    }

    pub fn push_v32(&mut self, val: u32) {
        self.push_value_plucked::<{ K_SHA_BIT_PLUCKER }, 32>(u128::from(val));
    }

    pub fn push_v32_legacy(&mut self, val: u32) {
        let mut cur_val = val;
        for _ in 0..8 {
            let val_chunk = (cur_val & 0xf) as usize;
            let plucked = (val_chunk << 1) ^ 15;
            let mut pt = self.field.u128_to_element(0u128);
            for (j, &basis_val) in core_algebra::GF2_16_BASIS_V1.iter().enumerate() {
                if (plucked & (1 << j)) != 0 {
                    pt = self.field.addf(&pt, &self.field.u128_to_element(basis_val));
                }
            }
            self.buffer.push(pt);
            cur_val >>= 4;
        }
    }

    pub fn push_nat256<N: Nat<4>>(&mut self, nat: &N) {
        self.push_nat_plucked::<{ K_HASH_V256_BIT_PLUCKER }, 4, N>(nat);
    }

    pub fn push_u128(&mut self, val: u128) {
        self.buffer.push(self.field.u128_to_element(val));
    }

    pub fn push_sha256_derived(&mut self, derived: &circuits_sha256::concrete::ConcreteDerived) {
        for val in derived.modern_elements() {
            self.push_v32(val);
        }
    }

    pub fn push_sha256msg_derived(
        &mut self,
        derived: &circuits_sha256msg::concrete::ConcreteDerived,
    ) {
        for sha in &derived.sha_derived {
            self.push_sha256_derived(sha);
        }
    }
}

impl<F: MdocSigRuntimeField> AssignmentBuilder<'_, F> {
    pub fn push_nat_256_bits<N: Nat<4>>(&mut self, nat: &N) {
        let mut bytes = nat.to_bytes_le();
        bytes.resize(32, 0);
        for &b in &bytes {
            self.push_bits_len(u64::from(b), 8);
        }
    }

    pub fn push_plucked_128(&mut self, val: u128) {
        self.push_value_plucked::<{ K_SIG_MAC_BIT_PLUCKER }, 128>(val);
    }

    pub fn push_plucked_128_legacy(&mut self, val: u128) {
        self.push_value_plucked_legacy::<{ K_SIG_MAC_BIT_PLUCKER }, 128>(val);
    }

    pub fn push_nat_elt<const W_NAT: usize, N: Nat<W_NAT>>(&mut self, val: &N) {
        let mut bytes = val.to_bytes_le();
        bytes.resize(32, 0);
        let el = self.field.bytes_to_element(&bytes).unwrap();
        self.buffer.push(el);
    }
}
