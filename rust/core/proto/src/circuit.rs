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

use std::fmt;

pub use core_algebra::SerializableField;
use sha2::{Digest, Sha256};

pub type DigestBytes = [u8; 32];

pub use crate::layer::{canonical_term, compare_term, Layer, Term, TermDelta};

#[derive(Clone)]
pub struct RawCircuit<F: SerializableField> {
    pub ninput: usize,
    pub npublic_input: usize,
    pub noutput: usize,
    pub logv: usize,
    pub subfield_boundary: usize,
    pub constants: Vec<F::E>,
    pub layers: Vec<Layer<F>>,
}

#[derive(Clone)]
pub struct Circuit<F: SerializableField> {
    pub raw: RawCircuit<F>,
    pub id: DigestBytes,
}

fn update8(hasher: &mut Sha256, val: usize) {
    hasher.update((val as u64).to_le_bytes());
}

pub fn compute_id<F: SerializableField>(f: &F, raw: &RawCircuit<F>) -> DigestBytes {
    let mut hasher = Sha256::new();

    if f.is_binary() {
        hasher.update(2u64.to_le_bytes());
        hasher.update(((f.serialized_size_bytes() * 8) as u64).to_le_bytes());
    } else {
        hasher.update(1u64.to_le_bytes());
        hasher.update(f.serialized_mone());
    }

    update8(&mut hasher, raw.noutput);
    update8(&mut hasher, raw.logv);
    update8(&mut hasher, 1); // ncopies
    update8(&mut hasher, 0); // logc
    update8(&mut hasher, raw.layers.len());
    update8(&mut hasher, raw.ninput);
    update8(&mut hasher, raw.npublic_input);
    update8(&mut hasher, raw.subfield_boundary);

    let const_bytes: Vec<Vec<u8>> = raw.constants.iter().map(|c| f.to_bytes(c)).collect();
    let mut buf = [0u8; 8192];
    let mut buf_len = 0;

    for layer in &raw.layers {
        let l_nums = [layer.nw as u64, layer.logw as u64, layer.num_terms() as u64];
        for &val in &l_nums {
            if buf_len + 8 > buf.len() {
                hasher.update(&buf[..buf_len]);
                buf_len = 0;
            }
            buf[buf_len..buf_len + 8].copy_from_slice(&val.to_le_bytes());
            buf_len += 8;
        }

        let mut prev_g = 0u32;
        let mut prev_h0 = 0u32;
        let mut prev_h1 = 0u32;

        layer.for_each_delta_index(|d_idx| {
            let d = &layer.deltas[d_idx as usize];
            let g = prev_g.wrapping_add(d.g);
            let h0 = prev_h0.wrapping_add(d.h[0]);
            let h1 = prev_h1.wrapping_add(d.h[1]);

            let cb = &const_bytes[d.k_index as usize];
            if buf_len + 24 + cb.len() > buf.len() {
                hasher.update(&buf[..buf_len]);
                buf_len = 0;
            }

            buf[buf_len..buf_len + 8].copy_from_slice(&u64::from(g).to_le_bytes());
            buf[buf_len + 8..buf_len + 16].copy_from_slice(&u64::from(h0).to_le_bytes());
            buf[buf_len + 16..buf_len + 24].copy_from_slice(&u64::from(h1).to_le_bytes());
            buf_len += 24;

            if cb.len() > buf.len() {
                if buf_len > 0 {
                    hasher.update(&buf[..buf_len]);
                    buf_len = 0;
                }
                hasher.update(cb);
            } else {
                buf[buf_len..buf_len + cb.len()].copy_from_slice(cb);
                buf_len += cb.len();
            }

            prev_g = g;
            prev_h0 = h0;
            prev_h1 = h1;
        });
    }

    if buf_len > 0 {
        hasher.update(&buf[..buf_len]);
    }

    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

impl<F: SerializableField> fmt::Debug for RawCircuit<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawCircuit")
            .field("ninput", &self.ninput)
            .field("npublic_input", &self.npublic_input)
            .field("noutput", &self.noutput)
            .field("logv", &self.logv)
            .field("constants_len", &self.constants.len())
            .field("layers", &self.layers)
            .field("subfield_boundary", &self.subfield_boundary)
            .finish()
    }
}

impl<F: SerializableField> fmt::Debug for Circuit<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Circuit")
            .field("raw", &self.raw)
            .field("id", &self.id)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldID {
    None = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
    Gf2_128 = 4,
    Gf2_16 = 5,
    Fp128 = 6,
    Fp64 = 7,
    Goldi = 8,
    Fp64_2 = 9,
    Secp = 10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitGeometry {
    pub ninput: usize,
    pub npublic_input: usize,
    pub noutput: usize,
    pub nwires: usize,
    pub nterms: usize,
    pub nlayers: usize,
    pub nassertions: usize,
}
