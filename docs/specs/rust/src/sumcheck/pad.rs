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

use crate::{
    algebra::{Field, Rng},
    circuit::Circuit,
};

/// Padding for a single round of sumcheck (masks for p0 and p2 evals for both hands).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPad<T> {
    pub hp: [[T; 2]; 2], // hp[hand] = [p0_mask, p2_mask]
}

/// Padding for final layer claim masks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerClaimsPad<T> {
    pub c0: T,
    pub c1: T,
    pub cr: T, // Product c0 * c1
}

/// Padding for a single circuit layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerPad<T> {
    pub rounds: Vec<RoundPad<T>>,
    pub claims: LayerClaimsPad<T>,
}

/// Padding for the entire circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitPad<T> {
    pub layers: Vec<LayerPad<T>>,
}

impl<F: Field> CircuitPad<F> {
    /// Samples random field element padding for all layers in the circuit and flattens them into witness padding.
    pub fn sample<R: Rng>(circuit_data: &Circuit<F>, rng: &mut R) -> (Self, Vec<F>) {
        let mut pad_witness = Vec::new();
        let mut layers = Vec::with_capacity(circuit_data.layers.len());
        for layer in &circuit_data.layers {
            let layer_pad = LayerPad::sample(layer.logw, rng);
            layer_pad.flatten_into(&mut pad_witness);
            layers.push(layer_pad);
        }
        (CircuitPad { layers }, pad_witness)
    }
}

impl CircuitPad<usize> {
    /// Generates symbolic witness indices for all layers in the circuit starting at `pad_base`.
    pub fn generate_indices<F: Field>(circuit_data: &Circuit<F>, pad_base: &mut usize) -> Self {
        let mut layers = Vec::with_capacity(circuit_data.layers.len());
        for layer in &circuit_data.layers {
            layers.push(LayerPad::generate_indices(layer.logw, pad_base));
        }
        CircuitPad { layers }
    }
}

impl<F: Field> LayerPad<F> {
    /// Samples concrete random field element masks for a single circuit layer.
    pub fn sample<R: Rng>(logw: usize, rng: &mut R) -> Self {
        let mut rounds = Vec::with_capacity(logw);
        for _ in 0..logw {
            rounds.push(RoundPad {
                hp: [
                    [F::sample(rng), F::sample(rng)],
                    [F::sample(rng), F::sample(rng)],
                ],
            });
        }
        let c0 = F::sample(rng);
        let c1 = F::sample(rng);
        let cr = c0 * c1;

        LayerPad {
            rounds,
            claims: LayerClaimsPad { c0, c1, cr },
        }
    }

    /// Appends all pad elements in order to a witness vector.
    pub fn flatten_into(&self, out: &mut Vec<F>) {
        for r in &self.rounds {
            out.extend_from_slice(&r.hp[0]);
            out.extend_from_slice(&r.hp[1]);
        }
        out.push(self.claims.c0);
        out.push(self.claims.c1);
        out.push(self.claims.cr);
    }
}

impl LayerPad<usize> {
    /// Generates the symbolic witness indices for a single circuit layer pad starting at `pad_base`.
    pub fn generate_indices(logw: usize, pad_base: &mut usize) -> Self {
        let mut rounds = Vec::with_capacity(logw);
        for _ in 0..logw {
            let hand0 = [*pad_base, *pad_base + 1];
            let hand1 = [*pad_base + 2, *pad_base + 3];
            *pad_base += 4;
            rounds.push(RoundPad { hp: [hand0, hand1] });
        }
        let c0 = *pad_base;
        let c1 = *pad_base + 1;
        let cr = *pad_base + 2;
        *pad_base += 3;

        LayerPad {
            rounds,
            claims: LayerClaimsPad { c0, c1, cr },
        }
    }
}
