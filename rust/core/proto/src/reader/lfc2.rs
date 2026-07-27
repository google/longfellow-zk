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

use util::ceil_log2;

use super::CircuitReader;
use crate::{
    circuit::{Circuit, Layer, RawCircuit, TermDelta},
    uleb::{read_uleb128_max4, read_uleb128_max4_u32},
    SerializableField,
};

pub(super) fn from_stream_lfc2_inner<R: std::io::BufRead, F: SerializableField>(
    reader: &CircuitReader<'_, F>,
    stream: &mut R,
    enforce_circuit_id: bool,
) -> Result<Circuit<F>, String> {
    let fid_as_size_t = read_uleb128_max4(stream)?;
    let nv = read_uleb128_max4(stream)?;
    if nv > super::MAX_WIRES {
        return Err(format!(
            "Excessive noutput count: {} (max {})",
            nv,
            super::MAX_WIRES
        ));
    }
    let logv = ceil_log2(nv);
    if !crate::sane_logw(logv) {
        return Err(format!(
            "Circuit logv {} exceeds MAX_LOGW {} or usize bit width",
            logv,
            crate::MAX_LOGW
        ));
    }
    let nc = read_uleb128_max4(stream)?;
    if nc != 1 {
        return Err(format!("Unsupported ncopies: expected 1, got {nc}"));
    }
    let npub_in = read_uleb128_max4(stream)?;
    if npub_in > super::MAX_WIRES {
        return Err(format!(
            "Excessive npublic_input count: {} (max {})",
            npub_in,
            super::MAX_WIRES
        ));
    }
    let subfield_boundary = read_uleb128_max4(stream)?;
    if subfield_boundary > super::MAX_WIRES {
        return Err(format!(
            "Excessive subfield_boundary: {} (max {})",
            subfield_boundary,
            super::MAX_WIRES
        ));
    }
    let ninputs = read_uleb128_max4(stream)?;
    if ninputs > super::MAX_WIRES {
        return Err(format!(
            "Excessive ninput count: {} (max {})",
            ninputs,
            super::MAX_WIRES
        ));
    }
    let nl = read_uleb128_max4(stream)?;
    if nl > super::MAX_LAYERS {
        return Err(format!(
            "Excessive layer count: {} (max {})",
            nl,
            super::MAX_LAYERS
        ));
    }

    if fid_as_size_t != reader.field_id as usize {
        return Err(format!(
            "Field ID mismatch: expected {}, got {}",
            reader.field_id as usize, fid_as_size_t
        ));
    }

    // Read constants
    let numconst = read_uleb128_max4(stream)?;
    if numconst > super::MAX_CONSTANTS {
        return Err(format!(
            "Excessive constants count: {} (max {})",
            numconst,
            super::MAX_CONSTANTS
        ));
    }
    let elt_size = SerializableField::serialized_size_bytes(reader.f);
    let mut chunk = vec![0u8; elt_size];
    let mut constants = Vec::with_capacity(numconst);
    for _ in 0..numconst {
        stream
            .read_exact(&mut chunk)
            .map_err(|e| format!("Failed to read constant: {e}"))?;
        let vv = reader
            .f
            .bytes_to_element(&chunk)
            .map_err(|e| format!("Field deserialization error: {e:?}"))?;
        constants.push(vv);
    }

    // Read layers
    let mut layers = Vec::with_capacity(nl);
    let mut total_terms = 0usize;
    for _ in 0..nl {
        let logw = read_uleb128_max4(stream)?;
        if !crate::sane_logw(logw) {
            return Err(format!(
                "Layer logw {} exceeds MAX_LOGW {} or usize bit width",
                logw,
                crate::MAX_LOGW
            ));
        }
        let nw = read_uleb128_max4(stream)?;
        if nw > super::MAX_LAYER_INPUTS {
            return Err(format!(
                "Excessive nw count: {} (max {})",
                nw,
                super::MAX_LAYER_INPUTS
            ));
        }

        // 1. Read deduplicated delta table from stream
        let ndeltas = read_uleb128_max4(stream)?;
        if ndeltas > super::MAX_DELTAS {
            return Err(format!(
                "Excessive deltas count: {} (max {})",
                ndeltas,
                super::MAX_DELTAS
            ));
        }
        let mut deltas = Vec::with_capacity(ndeltas);
        for _ in 0..ndeltas {
            let g = decode_delta_u32(read_uleb128_max4_u32(stream)?);
            let h0 = decode_delta_u32(read_uleb128_max4_u32(stream)?);
            let h1 = decode_delta_u32(read_uleb128_max4_u32(stream)?);
            let k_index = read_uleb128_max4_u32(stream)?;
            if k_index as usize >= constants.len() {
                return Err(format!(
                    "v2 delta k_index out of bounds: {} >= {}",
                    k_index,
                    constants.len()
                ));
            }
            deltas.push(TermDelta {
                g,
                h: [h0, h1],
                k_index,
            });
        }

        // 2. Read segments dictionary (sequences of delta indices)
        let n_segments = read_uleb128_max4(stream)?;
        if n_segments > super::MAX_DELTAS {
            return Err(format!(
                "Excessive segments count: {} (max {})",
                n_segments,
                super::MAX_DELTAS
            ));
        }
        let mut delta_segments = Vec::with_capacity(n_segments);
        for _ in 0..n_segments {
            let seg_len = read_uleb128_max4(stream)?;
            if seg_len > super::MAX_TERMS_PER_LAYER {
                return Err(format!(
                    "Excessive segment length: {} (max {})",
                    seg_len,
                    super::MAX_TERMS_PER_LAYER
                ));
            }
            let mut seg = Vec::with_capacity(seg_len);
            for _ in 0..seg_len {
                let d_idx = read_uleb128_max4_u32(stream)?;
                if d_idx as usize >= deltas.len() {
                    return Err(format!(
                        "v2 delta index out of bounds: {} >= {}",
                        d_idx,
                        deltas.len()
                    ));
                }
                seg.push(d_idx);
            }
            delta_segments.push(seg);
        }

        // 3. Read token sequence
        let ntokens = read_uleb128_max4(stream)?;
        if ntokens > super::MAX_TERMS_PER_LAYER {
            return Err(format!(
                "Excessive layer token count: {} (max {})",
                ntokens,
                super::MAX_TERMS_PER_LAYER
            ));
        }
        let mut delta_tokens = Vec::with_capacity(ntokens);
        for _ in 0..ntokens {
            let tok = read_uleb128_max4_u32(stream)?;
            if (tok as usize) >= delta_segments.len() {
                return Err(format!(
                    "v2 token out of bounds: {} (segments={})",
                    tok,
                    delta_segments.len()
                ));
            }
            delta_tokens.push(tok);
        }

        let mut layer_nterms = 0usize;
        for &tok in &delta_tokens {
            layer_nterms = layer_nterms.saturating_add(delta_segments[tok as usize].len());
        }

        if layer_nterms > super::MAX_TERMS_PER_LAYER {
            return Err(format!(
                "Excessive layer term count after expansion: {} (max {})",
                layer_nterms,
                super::MAX_TERMS_PER_LAYER
            ));
        }
        total_terms = total_terms.saturating_add(layer_nterms);
        if total_terms > super::MAX_TOTAL_TERMS {
            return Err(format!(
                "Total terms across layers {} exceeds MAX_TOTAL_TERMS {}",
                total_terms,
                super::MAX_TOTAL_TERMS
            ));
        }

        layers.push(Layer::new(nw, logw, deltas, delta_segments, delta_tokens));
    }

    // Read circuit ID (32 bytes)
    let mut id = [0u8; 32];
    stream
        .read_exact(&mut id)
        .map_err(|e| format!("Failed to read ID: {e}"))?;

    let raw = RawCircuit {
        ninput: ninputs,
        npublic_input: npub_in,
        noutput: nv,
        logv,
        subfield_boundary,
        constants,
        layers,
    };

    super::validate_raw_circuit(&raw)?;

    if enforce_circuit_id {
        let computed_id = crate::circuit::compute_id(reader.f, &raw);
        if computed_id != id {
            return Err("Circuit ID verification failed".to_string());
        }
    }

    Ok(Circuit { raw, id })
}

#[inline(always)]
fn decode_delta_u32(val: u32) -> u32 {
    (val >> 1) ^ ((val & 1).wrapping_neg())
}
