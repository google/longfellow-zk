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

use core_algebra::SerializableField;
use core_proto::circuit::{compute_id, Circuit, Layer, RawCircuit};

/// Compresses a single layer using the Grouped Literals heuristic directly on deduplicated delta
/// indices.
///
/// Instead of a shortest-path Dynamic Programming search (which can segment the term sequence into
/// thousands of tiny, disjoint runs, leading to high token count and poor zstd back-references),
/// this algorithm uses a greedy "Grouped Literals" chunking strategy directly on deduplicated delta
/// indices:
/// 1. Unrolls all deduplicated delta indices (`u32`) in the layer.
/// 2. Identifies high-frequency macro sequences of length 32 (occurring >= 64 times) to build a
///    dictionary.
/// 3. Greedily tokens out matching dictionary macros.
/// 4. Groups any non-matching consecutive terms into contiguous literal runs.
/// 5. Sorts the deduplicated deltas and segments by frequency, and renumbers everything.
#[must_use]
pub fn segment_layer<F: SerializableField + Clone>(layer: &Layer<F>) -> Layer<F> {
    let nw = layer.nw();
    let logw = layer.logw();

    // 1. Unroll deduplicated delta indices (u32) for this layer.
    let mut terms = Vec::with_capacity(layer.num_terms());
    layer.for_each_delta_index(|idx| terms.push(idx));

    if terms.is_empty() {
        return Layer::new(nw, logw, Vec::new(), Vec::new(), Vec::new());
    }

    const W: usize = 32;
    const BASE: u64 = 0x100000001b3;

    let mut macro_segments: Vec<Vec<u32>> = Vec::new();
    let mut macro_hash_map: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();

    if terms.len() >= W {
        // Pass 1: Rolling Hash candidate frequency counting
        let mut hash_counts: std::collections::HashMap<u64, (usize, usize)> =
            std::collections::HashMap::new();
        let mut i = 0;
        while i + W <= terms.len() {
            let mut cur_hash: u64 = 0;
            for j in 0..W {
                cur_hash = cur_hash
                    .wrapping_mul(BASE)
                    .wrapping_add(terms[i + j] as u64);
            }
            hash_counts
                .entry(cur_hash)
                .and_modify(|(c, _)| *c += 1)
                .or_insert((1, i));
            i += W;
        }

        // Sort hash candidates by frequency (count descending)
        let mut candidate_hashes: Vec<(u64, usize, usize)> = hash_counts
            .into_iter()
            .filter(|&(_, (count, _))| count >= 2)
            .map(|(h, (count, first_idx))| (h, count, first_idx))
            .collect();
        candidate_hashes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));

        for (h, _count, first_idx) in candidate_hashes {
            let seg_id = macro_segments.len() as u32;
            macro_segments.push(terms[first_idx..first_idx + W].to_vec());
            macro_hash_map.insert(h, seg_id);
        }
    }

    // Pass 2: Tokenize using macros and group literal runs up to length 32
    let mut raw_segments: Vec<Vec<u32>> = Vec::new();
    let mut seg_dedup: std::collections::HashMap<Vec<u32>, u32> = std::collections::HashMap::new();
    let mut final_tokens: Vec<u32> = Vec::new();

    let mut push_segment = |seg: Vec<u32>| {
        let seg_id = *seg_dedup.entry(seg.clone()).or_insert_with(|| {
            let id = raw_segments.len() as u32;
            raw_segments.push(seg);
            id
        });
        final_tokens.push(seg_id);
    };

    let mut idx = 0;
    let mut literal_buf: Vec<u32> = Vec::with_capacity(W);

    while idx < terms.len() {
        let mut matched_macro: Option<u32> = None;
        if idx + W <= terms.len() && !macro_hash_map.is_empty() {
            let mut h: u64 = 0;
            for j in 0..W {
                h = h.wrapping_mul(BASE).wrapping_add(terms[idx + j] as u64);
            }
            if let Some(&m_id) = macro_hash_map.get(&h) {
                if terms[idx..idx + W] == macro_segments[m_id as usize][..] {
                    matched_macro = Some(m_id);
                }
            }
        }

        if let Some(m_id) = matched_macro {
            if !literal_buf.is_empty() {
                push_segment(std::mem::take(&mut literal_buf));
            }
            push_segment(macro_segments[m_id as usize].clone());
            idx += W;
        } else {
            literal_buf.push(terms[idx]);
            if literal_buf.len() == W {
                push_segment(std::mem::take(&mut literal_buf));
            }
            idx += 1;
        }
    }

    if !literal_buf.is_empty() {
        push_segment(literal_buf);
    }

    // 3. Frequency sorting of deltas and segments
    let deltas = layer.deltas();
    let mut delta_counts = vec![0usize; deltas.len()];
    for &tok in &final_tokens {
        for &d_idx in &raw_segments[tok as usize] {
            delta_counts[d_idx as usize] += 1;
        }
    }

    let mut delta_order: Vec<usize> = (0..deltas.len()).collect();
    delta_order.sort_by(|&a, &b| {
        delta_counts[b]
            .cmp(&delta_counts[a])
            .then_with(|| a.cmp(&b))
    });

    let mut old_to_new_delta = vec![0u32; deltas.len()];
    let mut sorted_deltas = Vec::with_capacity(deltas.len());
    for (new_idx, &old_idx) in delta_order.iter().enumerate() {
        old_to_new_delta[old_idx] = new_idx as u32;
        sorted_deltas.push(deltas[old_idx]);
    }

    for seg in &mut raw_segments {
        for d_idx in seg {
            *d_idx = old_to_new_delta[*d_idx as usize];
        }
    }

    let mut seg_counts = vec![0usize; raw_segments.len()];
    for &tok in &final_tokens {
        seg_counts[tok as usize] += 1;
    }

    let mut seg_order: Vec<usize> = (0..raw_segments.len()).collect();
    seg_order.sort_by(|&a, &b| seg_counts[b].cmp(&seg_counts[a]).then_with(|| a.cmp(&b)));

    let mut old_to_new_seg = vec![0u32; raw_segments.len()];
    let mut sorted_segments = Vec::with_capacity(raw_segments.len());
    for (new_idx, &old_idx) in seg_order.iter().enumerate() {
        old_to_new_seg[old_idx] = new_idx as u32;
        sorted_segments.push(std::mem::take(&mut raw_segments[old_idx]));
    }

    for tok in &mut final_tokens {
        *tok = old_to_new_seg[*tok as usize];
    }

    Layer::new(nw, logw, sorted_deltas, sorted_segments, final_tokens)
}

/// Compresses an entire circuit by invoking `compress_layer` independently on each layer,
/// sorting constants by frequency across all layers, and renumbering everything.
///
/// Asserts that the canonical circuit ID (`compute_id`) remains identical before and after
/// compression, guaranteeing that evaluation order and semantic content of all terms across
/// all layers are strictly preserved.
pub fn segment_circuit<F: SerializableField + Clone>(f: &F, circuit: &Circuit<F>) -> Circuit<F> {
    let mut compressed_layers = Vec::with_capacity(circuit.raw.layers.len());

    for layer in &circuit.raw.layers {
        compressed_layers.push(segment_layer(layer));
    }

    // Sort constants by frequency across all compressed layers, and renumber.
    let num_constants = circuit.raw.constants.len();
    let mut const_counts = vec![0usize; num_constants];

    for layer in &compressed_layers {
        layer.for_each_delta_index(|d_idx| {
            let k_idx = layer.deltas()[d_idx as usize].k_index;
            const_counts[k_idx as usize] += 1;
        });
    }

    let mut const_order: Vec<usize> = (0..num_constants).collect();
    const_order.sort_by(|&a, &b| {
        const_counts[b]
            .cmp(&const_counts[a])
            .then_with(|| a.cmp(&b))
    });

    let mut old_to_new_const = vec![0u32; num_constants];
    let mut sorted_constants = Vec::with_capacity(num_constants);
    for (new_idx, &old_idx) in const_order.iter().enumerate() {
        old_to_new_const[old_idx] = new_idx as u32;
        sorted_constants.push(circuit.raw.constants[old_idx].clone());
    }

    // Renumber k_index in all deltas of all compressed layers
    for layer in &mut compressed_layers {
        for d in layer.deltas_mut() {
            d.k_index = old_to_new_const[d.k_index as usize];
        }
    }

    let new_raw = RawCircuit {
        ninput: circuit.raw.ninput,
        npublic_input: circuit.raw.npublic_input,
        noutput: circuit.raw.noutput,
        logv: circuit.raw.logv,
        subfield_boundary: circuit.raw.subfield_boundary,
        constants: sorted_constants,
        layers: compressed_layers,
    };

    // Verify that canonical circuit ID is invariant under compression.
    let new_id = compute_id(f, &new_raw);
    assert_eq!(new_id, circuit.id, "Circuit ID changed during compression!");

    Circuit {
        raw: new_raw,
        id: circuit.id,
    }
}
