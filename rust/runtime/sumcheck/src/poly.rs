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
use runtime_algebra::field::RuntimeField;
pub use runtime_algebra::poly::{LagrangeBasis, Poly};
use runtime_proto::RoundPoly;

/// Extension trait for converting a 3-evaluation mathematical polynomial (`Poly<3, W, F>`)
/// into the 2-evaluation wire format (`RoundPoly<W, F>`).
///
/// Why this trait exists:
/// `Poly<3, W, F>` is defined in `runtime-algebra` and `RoundPoly<W, F>` is defined in
/// `runtime-proto`. Because neither type is defined in `runtime-sumcheck`, Rust's orphan
/// rules (E0116) prevent defining inherent methods directly on `Poly` or `RoundPoly` here.
/// This extension trait bridges the two types, allowing the prover to convert round
/// polynomials to wire format cleanly before subtracting ZK padding.
pub trait QuadRoundPoly<const W: usize, F: SerializableField> {
    fn to_wire(&self) -> RoundPoly<W, F>;
}

/// Extension trait providing arithmetic and evaluation reconstruction for 2-evaluation
/// wire polynomials (`RoundPoly<W, F>`).
///
/// Why this trait exists:
/// Due to Rust's orphan rules (E0116), we cannot implement inherent methods on `RoundPoly`
/// (which is defined in `runtime-proto`) inside `runtime-sumcheck`. This trait allows the
/// verifier and prover to perform addition, subtraction, and Lagrange reconstruction on wire
/// polynomials without manually manipulating evaluation arrays.
pub trait QuadWirePoly<const W: usize, F: RuntimeField<W> + SerializableField> {
    fn to_poly(&self, claim: &F::E, f: &F) -> Poly<3, W, F>;
    fn add(&self, other: &Self, f: &F) -> Self;
    fn sub(&self, other: &Self, f: &F) -> Self;
}

impl<const W: usize, F: SerializableField> QuadRoundPoly<W, F> for Poly<3, W, F> {
    fn to_wire(&self) -> RoundPoly<W, F> {
        RoundPoly {
            evaluations: [self.evaluations[0].clone(), self.evaluations[2].clone()],
        }
    }
}

impl<const W: usize, F: RuntimeField<W> + SerializableField> QuadWirePoly<W, F>
    for RoundPoly<W, F>
{
    fn to_poly(&self, claim: &F::E, f: &F) -> Poly<3, W, F> {
        let g0 = &self.evaluations[0];
        let g2 = &self.evaluations[1];
        let g1 = f.subf(claim, g0);
        Poly {
            evaluations: [g0.clone(), g1, g2.clone()],
        }
    }

    fn add(&self, other: &Self, f: &F) -> Self {
        let mut res = self.clone();
        f.add(&mut res.evaluations[0], &other.evaluations[0]);
        f.add(&mut res.evaluations[1], &other.evaluations[1]);
        res
    }

    fn sub(&self, other: &Self, f: &F) -> Self {
        let mut res = self.clone();
        f.sub(&mut res.evaluations[0], &other.evaluations[0]);
        f.sub(&mut res.evaluations[1], &other.evaluations[1]);
        res
    }
}
