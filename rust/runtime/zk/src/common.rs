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
use core_proto::circuit::Circuit;
use runtime_algebra::{field::RuntimeField, InterpolatorFactory, ZkField};
use runtime_proto::Digest;

/// Bundles the field implementation and the interpolator factory.
pub struct ZkContext<'a, const W: usize, F: ZkField<W>, IF: InterpolatorFactory<W, F>> {
    pub f: &'a F,
    pub make_interpolator: &'a IF,
}

pub const DEFAULT_STATEMENT_HASH: Digest = Digest {
    data: [
        0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ],
};

#[must_use]
pub fn setup_lqc<const W: usize, F: RuntimeField<W> + SerializableField>(
    start_pad: usize,
    c: &Circuit<F>,
) -> Vec<runtime_ligero::param::LigeroQuadraticConstraint> {
    let mut lqc = Vec::with_capacity(c.raw.layers.len());
    let mut pi = start_pad;
    for i in 0..c.raw.layers.len() {
        let logw = c.raw.layers[i].logw();
        pi += 4 * logw;
        lqc.push(runtime_ligero::param::LigeroQuadraticConstraint {
            x: pi,
            y: pi + 1,
            z: pi + 2,
        });
        pi += 3;
    }
    lqc
}
