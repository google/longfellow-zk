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

/// Padding for a single round of sumcheck (masks for p0 and p2 evals for both hands).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPad {
    pub hp: [[usize; 2]; 2], // hp[hand] = [p0_mask, p2_mask]
}

/// Padding for final layer claim masks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerClaimsPad {
    pub c0: usize,
    pub c1: usize,
    pub cr: usize, // Product c0 * c1
}

/// Padding for a single circuit layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerPad {
    pub rounds: Vec<RoundPad>,
    pub claims: LayerClaimsPad,
}

/// Padding for the entire circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitPad {
    pub layers: Vec<LayerPad>,
}

impl CircuitPad {
    /// Generates padded indices for the circuit.
    pub fn generate_indices(logw_layers: &[usize], pad_index: &mut usize) -> Self {
        let mut layers = Vec::with_capacity(logw_layers.len());
        for &logw in logw_layers {
            let mut rounds = Vec::with_capacity(logw);
            for _ in 0..logw {
                rounds.push(RoundPad {
                    hp: [
                        [*pad_index, *pad_index + 1],
                        [*pad_index + 2, *pad_index + 3],
                    ],
                });
                *pad_index += 4;
            }
            layers.push(LayerPad {
                rounds,
                claims: LayerClaimsPad {
                    c0: *pad_index,
                    c1: *pad_index + 1,
                    cr: *pad_index + 2,
                },
            });
            *pad_index += 3;
        }
        Self { layers }
    }

    /// Computes the total number of padding elements for the given circuit.
    pub fn pad_size<const W: usize, F: core_algebra::SerializableField>(
        circuit: &core_proto::circuit::Circuit<F>,
    ) -> usize {
        circuit
            .raw
            .layers
            .iter()
            .map(|l| core_proto::Layer::logw(l) * 4 + 3)
            .sum()
    }
}
