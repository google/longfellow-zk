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
    circuit::{Circuit, Layer, RawCircuit},
    SerializableField,
};

fn read_num_stream<R: std::io::BufRead>(stream: &mut R) -> Result<usize, String> {
    let mut buf = [0u8; 3];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("Failed to read num: {e}"))?;
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], 0]) as usize)
}

pub(super) fn from_stream_lfc1_inner<R: std::io::BufRead, F: SerializableField>(
    reader: &CircuitReader<'_, F>,
    stream: &mut R,
    enforce_circuit_id: bool,
) -> Result<Circuit<F>, String> {
    let fid_as_size_t = read_num_stream(stream)?;
    let nv = read_num_stream(stream)?; // noutput
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
    let nc = read_num_stream(stream)?; // ncopies
    if nc != 1 {
        return Err(format!("Unsupported ncopies: expected 1, got {nc}"));
    }
    let npub_in = read_num_stream(stream)?; // npublic_input
    if npub_in > super::MAX_WIRES {
        return Err(format!(
            "Excessive npublic_input count: {} (max {})",
            npub_in,
            super::MAX_WIRES
        ));
    }
    let subfield_boundary = read_num_stream(stream)?;
    if subfield_boundary > super::MAX_WIRES {
        return Err(format!(
            "Excessive subfield_boundary: {} (max {})",
            subfield_boundary,
            super::MAX_WIRES
        ));
    }
    let ninputs = read_num_stream(stream)?; // ninput
    if ninputs > super::MAX_WIRES {
        return Err(format!(
            "Excessive ninput count: {} (max {})",
            ninputs,
            super::MAX_WIRES
        ));
    }
    let nl = read_num_stream(stream)?; // layers len
    if nl > super::MAX_LAYERS {
        return Err(format!(
            "Excessive layer count: {} (max {})",
            nl,
            super::MAX_LAYERS
        ));
    }
    let numconst = read_num_stream(stream)?; // constants len
    if numconst > super::MAX_CONSTANTS {
        return Err(format!(
            "Excessive constants count: {} (max {})",
            numconst,
            super::MAX_CONSTANTS
        ));
    }

    if fid_as_size_t != reader.field_id as usize {
        return Err(format!(
            "Field ID mismatch: expected {}, got {}",
            reader.field_id as usize, fid_as_size_t
        ));
    }

    // Read constants (kvec)
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

    let mut layers = Vec::with_capacity(nl);
    let mut buf = [0u8; 12000]; // batch read buffer up to 1000 terms
    let mut total_terms = 0usize;

    for _ in 0..nl {
        let mut db = crate::cache::ApproximateDeltaTableBuilder::new(65521);
        let logw = read_num_stream(stream)?;
        if !crate::sane_logw(logw) {
            return Err(format!(
                "Layer logw {} exceeds MAX_LOGW {} or usize bit width",
                logw,
                crate::MAX_LOGW
            ));
        }
        let nw = read_num_stream(stream)?;
        if nw > super::MAX_LAYER_INPUTS {
            return Err(format!(
                "Excessive nw count: {} (max {})",
                nw,
                super::MAX_LAYER_INPUTS
            ));
        }
        let nterms = read_num_stream(stream)?; // terms len
        if nterms > super::MAX_TERMS_PER_LAYER {
            return Err(format!(
                "Excessive layer term count: {} (max {})",
                nterms,
                super::MAX_TERMS_PER_LAYER
            ));
        }
        total_terms = total_terms.saturating_add(nterms);
        if total_terms > super::MAX_TOTAL_TERMS {
            return Err(format!(
                "Total terms across layers {} exceeds MAX_TOTAL_TERMS {}",
                total_terms,
                super::MAX_TOTAL_TERMS
            ));
        }

        let mut delta_segment = Vec::with_capacity(nterms);
        let mut remaining_terms = nterms;
        while remaining_terms > 0 {
            let batch = remaining_terms.min(256);
            stream
                .read_exact(&mut buf[0..batch * 12])
                .map_err(|e| format!("Failed to read terms batch: {e}"))?;

            for i in 0..batch {
                let term_chunk = &buf[i * 12..(i + 1) * 12];
                let delta_g = read_u24_le(&term_chunk[0..3]);
                let delta_h0 = read_u24_le(&term_chunk[3..6]);
                let delta_h1 = read_u24_le(&term_chunk[6..9]);
                let vi = read_u24_le(&term_chunk[9..12]) as usize;

                if vi >= numconst {
                    return Err(format!("Constant index out of bounds: {vi} >= {numconst}"));
                }

                let dg = decode_delta_u32(delta_g);
                let dh0 = decode_delta_u32(delta_h0);
                let dh1 = decode_delta_u32(delta_h1);
                let idx = db.dedup(dg, dh0, dh1, vi as u32);
                delta_segment.push(idx);
            }
            remaining_terms -= batch;
        }

        layers.push(Layer::new_uncompressed(nw, logw, db.deltas, delta_segment));
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
fn read_u24_le(slice: &[u8]) -> u32 {
    u32::from_le_bytes([slice[0], slice[1], slice[2], 0])
}

#[inline(always)]
fn decode_delta_u32(val: u32) -> u32 {
    if val & 1 != 0 {
        (val >> 1).wrapping_neg()
    } else {
        val >> 1
    }
}
