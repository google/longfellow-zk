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

use std::io::Read;

use sha2::{Digest, Sha256};

use crate::{
    algebra::{Field, ceil_lg2},
    io::{read_elt_field, read_uleb128, zigzag_decode_delta},
};

const MAX_LOGW: usize = 40;
const MAX_WIRES: usize = 5_000_000;
const MAX_LAYERS: usize = 10_000;
const MAX_CONSTANTS: usize = 5_000_000;
const MAX_DELTAS: usize = 20_000_000;
const MAX_TERMS_PER_LAYER: usize = 20_000_000;
const MAX_TOTAL_TERMS: usize = 20_000_000;

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[derive(Clone, Copy, Debug)]
pub struct Term<F> {
    pub k: F,
    pub g: usize,
    pub h: [usize; 2],
}

#[derive(Clone, Debug)]
pub struct CircuitLayer<F> {
    pub logw: usize,
    pub nw: usize,
    pub quad: Vec<Term<F>>,
}

#[derive(Clone, Debug)]
pub struct Circuit<F> {
    pub id: [u8; 32],
    pub field_id: u64,
    pub noutput: usize,
    pub logv: usize,
    pub npublic_input: usize,
    pub subfield_boundary: usize,
    pub ninput: usize,
    pub layers: Vec<CircuitLayer<F>>,
}

pub fn parse_lfc2_bytes<F: Field + 'static, R: Read>(io: &mut R) -> std::io::Result<Circuit<F>> {
    let mut magic = [0u8; 4];
    io.read_exact(&mut magic)?;
    if &magic != b"LFC2" {
        return Err(invalid_data("Invalid magic header"));
    }

    let field_id = read_uleb128(io)?;
    let nv = read_uleb128(io)? as usize;
    read_uleb128(io)?;
    let logv = ceil_lg2(nv);
    if logv > MAX_LOGW {
        return Err(invalid_data("logv exceeds MAX_LOGW"));
    }
    let npub_in = read_uleb128(io)? as usize;
    let subfield_boundary = read_uleb128(io)? as usize;
    let ninput = read_uleb128(io)? as usize;
    if ninput > MAX_WIRES {
        return Err(invalid_data("ninput exceeds MAX_WIRES"));
    }
    if npub_in > ninput {
        return Err(invalid_data("npublic_input exceeds ninput"));
    }
    let nl = read_uleb128(io)? as usize;
    if nl > MAX_LAYERS {
        return Err(invalid_data("nl exceeds MAX_LAYERS"));
    }

    let num_const = read_uleb128(io)? as usize;
    if num_const > MAX_CONSTANTS {
        return Err(invalid_data("num_const exceeds MAX_CONSTANTS"));
    }
    let mut constants = Vec::with_capacity(num_const);
    for _ in 0..num_const {
        constants.push(read_elt_field(io)?);
    }

    let mut layers = Vec::with_capacity(nl);
    let mut total_terms = 0usize;
    for _ in 0..nl {
        let logw = read_uleb128(io)? as usize;
        if logw > MAX_LOGW {
            return Err(invalid_data("logw exceeds MAX_LOGW"));
        }
        let nw = read_uleb128(io)? as usize;

        let num_deltas = read_uleb128(io)? as usize;
        if num_deltas > MAX_DELTAS {
            return Err(invalid_data("num_deltas exceeds MAX_DELTAS"));
        }
        struct Delta {
            g: isize,
            h0: isize,
            h1: isize,
            k_index: usize,
        }
        let mut deltas = Vec::with_capacity(num_deltas);
        for _ in 0..num_deltas {
            deltas.push(Delta {
                g: zigzag_decode_delta(read_uleb128(io)?),
                h0: zigzag_decode_delta(read_uleb128(io)?),
                h1: zigzag_decode_delta(read_uleb128(io)?),
                k_index: read_uleb128(io)? as usize,
            });
        }

        let num_segments = read_uleb128(io)? as usize;
        if num_segments > MAX_DELTAS {
            return Err(invalid_data("num_segments exceeds MAX_DELTAS"));
        }
        let mut segments = Vec::with_capacity(num_segments);
        for _ in 0..num_segments {
            let seg_len = read_uleb128(io)? as usize;
            if seg_len > MAX_TERMS_PER_LAYER {
                return Err(invalid_data("seg_len exceeds MAX_TERMS_PER_LAYER"));
            }
            let mut seg = Vec::with_capacity(seg_len);
            for _ in 0..seg_len {
                seg.push(read_uleb128(io)? as usize);
            }
            segments.push(seg);
        }

        let token_len = read_uleb128(io)? as usize;
        if token_len > MAX_TERMS_PER_LAYER {
            return Err(invalid_data("token_len exceeds MAX_TERMS_PER_LAYER"));
        }
        let mut tokens = Vec::with_capacity(token_len);
        for _ in 0..token_len {
            tokens.push(read_uleb128(io)? as usize);
        }

        let mut hc = Vec::new();
        let (mut g, mut h0, mut h1) = (0isize, 0isize, 0isize);
        for tok in tokens {
            if tok >= segments.len() {
                return Err(invalid_data("token index out of bounds"));
            }
            for &didx in &segments[tok] {
                if didx >= deltas.len() {
                    return Err(invalid_data("delta index out of bounds"));
                }
                let d = &deltas[didx];
                if d.k_index >= constants.len() {
                    return Err(invalid_data("k_index out of bounds"));
                }
                if total_terms >= MAX_TOTAL_TERMS {
                    return Err(invalid_data("total term count exceeds MAX_TOTAL_TERMS"));
                }
                total_terms += 1;
                g += d.g;
                h0 += d.h0;
                h1 += d.h1;
                hc.push(Term {
                    k: constants[d.k_index],
                    g: g as usize,
                    h: [h0 as usize, h1 as usize],
                });
            }
        }

        layers.push(CircuitLayer { logw, nw, quad: hc });
    }

    let mut id = [0u8; 32];
    io.read_exact(&mut id)?;

    let circuit = Circuit {
        id,
        field_id,
        noutput: nv,
        logv,
        npublic_input: npub_in,
        subfield_boundary,
        ninput,
        layers,
    };

    Ok(circuit)
}

pub fn compute_circuit_id<F: Field>(circuit: &Circuit<F>) -> [u8; 32] {
    let mut hasher = Sha256::new();

    if circuit.field_id == 0 || circuit.field_id == 2 || circuit.field_id == 4 {
        hasher.update(2u64.to_le_bytes());
        hasher.update(((F::serialized_size() * 8) as u64).to_le_bytes());
    } else {
        hasher.update(1u64.to_le_bytes());
        hasher.update(F::mone().to_bytes());
    }

    hasher.update((circuit.noutput as u64).to_le_bytes());
    hasher.update((circuit.logv as u64).to_le_bytes());
    hasher.update(1u64.to_le_bytes()); // ncopies
    hasher.update(0u64.to_le_bytes()); // logc
    hasher.update((circuit.layers.len() as u64).to_le_bytes());
    hasher.update((circuit.ninput as u64).to_le_bytes());
    hasher.update((circuit.npublic_input as u64).to_le_bytes());
    hasher.update((circuit.subfield_boundary as u64).to_le_bytes());

    for layer in &circuit.layers {
        hasher.update((layer.nw as u64).to_le_bytes());
        hasher.update((layer.logw as u64).to_le_bytes());
        hasher.update((layer.quad.len() as u64).to_le_bytes());
        for term in &layer.quad {
            hasher.update((term.g as u64).to_le_bytes());
            hasher.update((term.h[0] as u64).to_le_bytes());
            hasher.update((term.h[1] as u64).to_le_bytes());
            hasher.update(term.k.to_bytes());
        }
    }

    hasher.finalize().into()
}
