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

use compile_algebra::p256::P256Field;
use compile_compiler::{arena::CompilerArena, segment_circuit, CompilerLogic};
use compile_logic::{Logic, LogicIO};

#[test]
fn test_circuit_compression_and_recompression() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let logic = CompilerLogic::new(&arena, &f);

    // Build a circuit with repetitive patterns so DP discovers macros and creates multiple segments
    let mut x = logic.input(1);
    let y = logic.input(2);
    for _ in 0..40 {
        let sum = logic.add(&x, &y);
        let prod = logic.mul(&sum, &x);
        x = logic.add(&prod, &y);
    }
    let assert_expr = logic.assert0("assert_x", &x);

    let (original_circuit, _, _) =
        compile_compiler::top::compile(&arena, &f, assert_expr, logic.tracker, 1, 0);

    for layer in &original_circuit.raw.layers {
        assert!(
            layer.num_segments() <= 1,
            "Original circuit layers should start uncompressed"
        );
    }

    // Step 1: Compress the circuit
    let compressed_circuit = segment_circuit(&f, &original_circuit);
    assert_eq!(
        compressed_circuit.id, original_circuit.id,
        "ID changed during initial compression"
    );

    // Also verify `compress_layer` directly on individual layers
    for (orig_layer, comp_layer) in original_circuit
        .raw
        .layers
        .iter()
        .zip(compressed_circuit.raw.layers.iter())
    {
        let orig_terms = orig_layer.terms(&original_circuit.raw.constants);
        let comp_terms = comp_layer.terms(&compressed_circuit.raw.constants);
        assert_eq!(
            orig_terms, comp_terms,
            "Terms mismatch between original and compressed layer"
        );
    }

    // Step 2: Re-compress the ALREADY COMPRESSED circuit
    let recompressed_circuit = segment_circuit(&f, &compressed_circuit);
    assert_eq!(
        recompressed_circuit.id, original_circuit.id,
        "ID changed during re-compression"
    );

    // Check terms match exactly across all layers after re-compression
    for (orig_layer, recomp_layer) in original_circuit
        .raw
        .layers
        .iter()
        .zip(recompressed_circuit.raw.layers.iter())
    {
        let orig_terms = orig_layer.terms(&original_circuit.raw.constants);
        let recomp_terms = recomp_layer.terms(&recompressed_circuit.raw.constants);
        assert_eq!(
            orig_terms, recomp_terms,
            "Terms mismatch between original and recompressed layer"
        );
    }

    // Verify frequency sorting of constants across the circuit
    let num_constants = compressed_circuit.raw.constants.len();
    let mut const_counts = vec![0usize; num_constants];
    for layer in &compressed_circuit.raw.layers {
        layer.for_each_delta_index(|d_idx| {
            let k_idx = layer.deltas()[d_idx as usize].k_index;
            const_counts[k_idx as usize] += 1;
        });
    }
    for window in const_counts.windows(2) {
        assert!(
            window[0] >= window[1],
            "Constants are not sorted by frequency descending: {:?}",
            const_counts
        );
    }

    // Verify frequency sorting of deltas and segments for each layer
    for layer in &compressed_circuit.raw.layers {
        // Deltas frequency
        let mut delta_counts = vec![0usize; layer.deltas().len()];
        for &tok in layer.delta_tokens() {
            for &d_idx in &layer.delta_segments()[tok as usize] {
                delta_counts[d_idx as usize] += 1;
            }
        }
        for window in delta_counts.windows(2) {
            assert!(
                window[0] >= window[1],
                "Deltas are not sorted by frequency descending: {:?}",
                delta_counts
            );
        }

        // Segments frequency
        let mut seg_counts = vec![0usize; layer.delta_segments().len()];
        for &tok in layer.delta_tokens() {
            seg_counts[tok as usize] += 1;
        }
        for window in seg_counts.windows(2) {
            assert!(
                window[0] >= window[1],
                "Segments are not sorted by frequency descending: {:?}",
                seg_counts
            );
        }
    }
}
