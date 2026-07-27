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

use runtime_algebra::{ElementOf, RuntimeField, ZkField};
use runtime_ligero::param::LigeroLinearConstraint;

#[derive(Debug)]
pub(crate) struct Expression<const W: usize, F: RuntimeField<W>> {
    pub(crate) known: ElementOf<F>,
    pub(crate) base_idx: usize,
    pub(crate) symbolic: Vec<ElementOf<F>>,
}

impl<const W: usize, F: RuntimeField<W>> Clone for Expression<W, F> {
    fn clone(&self) -> Self {
        Self {
            known: self.known.clone(),
            base_idx: self.base_idx,
            symbolic: self.symbolic.clone(),
        }
    }
}

impl<const W: usize, F: RuntimeField<W>> Expression<W, F> {
    pub(crate) fn zero(f: &F) -> Self {
        Self {
            known: f.zero(),
            base_idx: 0,
            symbolic: Vec::with_capacity(64),
        }
    }

    pub(crate) fn var(witness_idx: usize, f: &F) -> Self {
        let mut symbolic = Vec::with_capacity(64);
        symbolic.push(f.one());
        Self {
            known: f.zero(),
            base_idx: witness_idx,
            symbolic,
        }
    }

    pub(crate) fn resize(&mut self, l: usize, h: usize, f: &F) {
        if l >= h {
            return;
        }
        if self.symbolic.is_empty() {
            self.base_idx = l;
            self.symbolic.resize(h - l, f.zero());
            return;
        }
        let cur_low = self.base_idx;
        let cur_high = self.base_idx + self.symbolic.len();
        debug_assert!(l >= cur_low, "resize must be monotonically increasing");
        let new_high = cur_high.max(h);
        if new_high > cur_high {
            self.symbolic.resize(new_high - cur_low, f.zero());
        }
    }

    pub(crate) fn add_scalar(&mut self, val: &ElementOf<F>, f: &F) {
        f.add(&mut self.known, val);
    }

    pub(crate) fn sub_scalar(&mut self, val: &ElementOf<F>, f: &F) {
        f.sub(&mut self.known, val);
    }

    pub(crate) fn add_var(&mut self, witness_idx: usize, coeff: ElementOf<F>, f: &F) {
        self.resize(witness_idx, witness_idx + 1, f);
        f.add(&mut self.symbolic[witness_idx - self.base_idx], &coeff);
    }

    pub(crate) fn scale(&mut self, s: &ElementOf<F>, f: &F) {
        f.mul(&mut self.known, s);
        runtime_algebra::blas::scale(&mut self.symbolic, s, f);
    }

    pub(crate) fn axpy(&mut self, other: &Self, alpha: &ElementOf<F>, f: &F) {
        f.fma(&mut self.known, alpha, &other.known);

        if other.symbolic.is_empty() {
            return;
        }
        let other_low = other.base_idx;
        let other_high = other.base_idx + other.symbolic.len();
        self.resize(other_low, other_high, f);

        let off = other.base_idx - self.base_idx;
        let zero = f.zero();
        for (i, val) in other.symbolic.iter().enumerate() {
            if *val != zero {
                f.fma(&mut self.symbolic[off + i], alpha, val);
            }
        }
    }
}

impl<const W: usize, F: ZkField<W>> Expression<W, F> {
    pub(crate) fn constrain_to_be_zero(
        &self,
        a: &mut Vec<LigeroLinearConstraint<W, F>>,
        b: &mut Vec<ElementOf<F>>,
        f: &F,
    ) {
        let c = b.len();
        let zero = f.zero();
        for (i, coeff) in self.symbolic.iter().enumerate() {
            if *coeff != zero {
                a.push(LigeroLinearConstraint {
                    c,
                    w: self.base_idx + i,
                    k: coeff.clone(),
                });
            }
        }
        b.push(self.known.clone());
    }
}
