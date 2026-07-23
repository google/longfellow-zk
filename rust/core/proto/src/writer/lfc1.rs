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

use std::collections::HashMap;

use super::CircuitWriter;
use crate::{circuit::Circuit, SerializableField};

fn serialize_num(bytes: &mut Vec<u8>, mut g: usize) {
    let max_val = (1 << (crate::BYTES_PER_SIZE_T * 8)) - 1;
    assert!(
        g <= max_val,
        "Violating small wire-label assumption: label too large for {} bytes",
        crate::BYTES_PER_SIZE_T
    );
    for _ in 0..crate::BYTES_PER_SIZE_T {
        bytes.push((g & 0xff) as u8);
        g >>= 8;
    }
}

fn serialize_field_id(bytes: &mut Vec<u8>, id: crate::FieldID) {
    serialize_num(bytes, id as usize);
}

fn serialize_size(bytes: &mut Vec<u8>, sz: usize) {
    serialize_num(bytes, sz);
}

fn serialize_index(bytes: &mut Vec<u8>, val: u32, prev_val: u32) {
    if val >= prev_val {
        serialize_num(bytes, (2 * (val - prev_val)) as usize);
    } else {
        serialize_num(bytes, (2 * (prev_val - val) + 1) as usize);
    }
}

pub(super) fn to_bytes_lfc1<F: SerializableField>(
    writer: &CircuitWriter<'_, F>,
    sc_c: &Circuit<F>,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Collect constants and build kvec
    let mut k_to_index = HashMap::new();
    let mut kvec = Vec::new();

    for layer in &sc_c.raw.layers {
        layer.for_each_term(&sc_c.raw.constants, |term| {
            let key = writer.f.to_bytes(&term.k);
            if let std::collections::hash_map::Entry::Vacant(e) = k_to_index.entry(key) {
                e.insert(kvec.len());
                kvec.push(term.k.clone());
            }
        });
    }

    // Write header
    bytes.push(0x1); // version
    serialize_field_id(&mut bytes, writer.field_id);
    serialize_size(&mut bytes, sc_c.raw.noutput); // sc_c.nv
    serialize_size(&mut bytes, 1); // sc_c.nc
    serialize_size(&mut bytes, sc_c.raw.npublic_input); // sc_c.npub_in
    serialize_size(&mut bytes, sc_c.raw.subfield_boundary);
    serialize_size(&mut bytes, sc_c.raw.ninput); // sc_c.ninputs
    serialize_size(&mut bytes, sc_c.raw.layers.len());

    // Write kvec
    serialize_size(&mut bytes, kvec.len());
    for v in &kvec {
        writer.serialize_elt(&mut bytes, v);
    }

    // Serialize layers and quads
    for layer in &sc_c.raw.layers {
        assert!(crate::sane_logw(layer.logw), "layer logw must be sane");
        serialize_size(&mut bytes, layer.logw);
        serialize_size(&mut bytes, layer.nw);
        serialize_size(&mut bytes, layer.num_terms());

        let mut prevg = 0u32;
        let mut prevh0 = 0u32;
        let mut prevh1 = 0u32;

        layer.for_each_term(&sc_c.raw.constants, |term| {
            serialize_index(&mut bytes, term.g, prevg);
            serialize_index(&mut bytes, term.h0, prevh0);
            serialize_index(&mut bytes, term.h1, prevh1);

            let key = writer.f.to_bytes(&term.k);
            let k_idx = k_to_index[&key];
            serialize_size(&mut bytes, k_idx);

            prevg = term.g;
            prevh0 = term.h0;
            prevh1 = term.h1;
        });
    }

    // Write circuit ID
    bytes.extend_from_slice(&sc_c.id);

    bytes
}
