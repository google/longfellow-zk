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

use runtime_algebra::{ElementOf, RuntimeField};
use runtime_random::RandomEngine;

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

impl CircuitPad<usize> {
    pub fn generate_indices(logw_layers: &[usize], pad_base: &mut usize) -> CircuitPad<usize> {
        let mut layers = Vec::with_capacity(logw_layers.len());
        for &logw in logw_layers {
            layers.push(LayerPad::generate_indices(logw, pad_base));
        }
        CircuitPad { layers }
    }
}

impl<T: Clone> LayerPad<T> {
    /// Appends all pad elements in order to a witness vector.
    pub fn flatten_into(&self, out: &mut Vec<T>) {
        for r in &self.rounds {
            out.extend_from_slice(&r.hp[0]);
            out.extend_from_slice(&r.hp[1]);
        }
        out.push(self.claims.c0.clone());
        out.push(self.claims.c1.clone());
        out.push(self.claims.cr.clone());
    }
}

impl<T> LayerPad<T> {
    /// Samples concrete random field element masks for a single circuit layer.
    pub fn sample<
        const W: usize,
        F: RuntimeField<W> + runtime_algebra::SupportsSampling<W>,
        R: RandomEngine,
    >(
        logw: usize,
        rng: &mut R,
        f: &F,
    ) -> LayerPad<ElementOf<F>> {
        let mut rounds = Vec::with_capacity(logw);
        for _ in 0..logw {
            rounds.push(RoundPad {
                hp: [
                    [rng.elt_field(f), rng.elt_field(f)],
                    [rng.elt_field(f), rng.elt_field(f)],
                ],
            });
        }
        let c0 = rng.elt_field(f);
        let c1 = rng.elt_field(f);
        let cr = f.mulf(&c0, &c1);

        LayerPad {
            rounds,
            claims: LayerClaimsPad { c0, c1, cr },
        }
    }
}

impl LayerPad<usize> {
    /// Generates the symbolic witness indices for a single circuit layer pad starting at
    /// `pad_base`.
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
