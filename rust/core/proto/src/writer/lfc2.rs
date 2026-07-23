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

use super::CircuitWriter;
use crate::{
    circuit::Circuit,
    uleb::{serialize_uleb128_max4, serialize_uleb128_max4_u32},
    SerializableField,
};

#[inline(always)]
fn zigzag_encode_delta(delta: u32) -> u32 {
    (delta << 1) ^ ((delta as i32 >> 31) as u32)
}

pub(super) fn to_bytes_lfc2<F: SerializableField>(
    writer: &CircuitWriter<'_, F>,
    sc_c: &Circuit<F>,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Write header
    bytes.extend_from_slice(b"LFC2"); // magic header
    serialize_uleb128_max4(&mut bytes, writer.field_id as usize);
    serialize_uleb128_max4(&mut bytes, sc_c.raw.noutput); // sc_c.nv
    serialize_uleb128_max4(&mut bytes, 1); // sc_c.nc
    serialize_uleb128_max4(&mut bytes, sc_c.raw.npublic_input); // sc_c.npub_in
    serialize_uleb128_max4(&mut bytes, sc_c.raw.subfield_boundary);
    serialize_uleb128_max4(&mut bytes, sc_c.raw.ninput); // sc_c.ninputs
    serialize_uleb128_max4(&mut bytes, sc_c.raw.layers.len());

    // Write constants
    serialize_uleb128_max4(&mut bytes, sc_c.raw.constants.len());
    for v in &sc_c.raw.constants {
        writer.serialize_elt(&mut bytes, v);
    }

    // Serialize each layer
    for layer in &sc_c.raw.layers {
        assert!(crate::sane_logw(layer.logw), "layer logw must be sane");
        serialize_uleb128_max4(&mut bytes, layer.logw);
        serialize_uleb128_max4(&mut bytes, layer.nw);

        // Write the deduplicated delta table for this layer to disk.
        serialize_uleb128_max4(&mut bytes, layer.deltas().len());
        for term in layer.deltas() {
            serialize_uleb128_max4_u32(&mut bytes, zigzag_encode_delta(term.g));
            serialize_uleb128_max4_u32(&mut bytes, zigzag_encode_delta(term.h[0]));
            serialize_uleb128_max4_u32(&mut bytes, zigzag_encode_delta(term.h[1]));
            serialize_uleb128_max4_u32(&mut bytes, term.k_index);
        }

        // Write the segments dictionary (sequences of delta indices).
        serialize_uleb128_max4(&mut bytes, layer.delta_segments().len());
        for seg in layer.delta_segments() {
            serialize_uleb128_max4(&mut bytes, seg.len());
            for &idx in seg {
                serialize_uleb128_max4_u32(&mut bytes, idx);
            }
        }

        // Write the token sequence indicating which segment dictionary entries to execute.
        serialize_uleb128_max4(&mut bytes, layer.delta_tokens().len());
        for &tok in layer.delta_tokens() {
            serialize_uleb128_max4_u32(&mut bytes, tok);
        }
    }

    bytes.extend_from_slice(&sc_c.id);
    bytes
}

#[inline(always)]
#[must_use]
pub fn uleb128_len_u32(mut val: u32) -> u32 {
    let mut len = 1;
    while val >= 0x80 {
        val >>= 7;
        len += 1;
    }
    len
}
