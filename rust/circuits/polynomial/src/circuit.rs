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

use compile_logic::{Eltw, Logic};

pub struct Polynomial<'a, L: Logic> {
    logic: &'a L,
}

impl<'a, L: Logic> Polynomial<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self { logic }
    }

    pub fn powers_of_x(&self, n: usize, x: &Eltw<L>) -> Vec<Eltw<L>> {
        let mut xi = vec![self.logic.zero(); n];
        if n > 0 {
            xi[0] = self.logic.one();
            if n > 1 {
                xi[1] = x.clone();
                for k in 2..n {
                    xi[k] = self.logic.mul(&xi[k / 2], &xi[k - (k / 2)]);
                }
            }
        }
        xi
    }

    pub fn eval(&self, cc: &[Eltw<L>], x: &Eltw<L>) -> Eltw<L> {
        let n = cc.len();
        let xi = self.powers_of_x(n, x);
        self.logic.dot(cc, &xi)
    }

    // parallel Horner rule
    pub fn eval_horner(&self, cc: &[Eltw<L>], x: &Eltw<L>) -> Eltw<L> {
        if cc.is_empty() {
            return self.logic.zero();
        }
        let mut xx = x.clone();
        let mut current_cc = cc.to_vec();

        while current_cc.len() > 1 {
            current_cc = current_cc
                .chunks(2)
                .map(|chunk| match chunk {
                    [c0, c1] => self.logic.add(c0, &self.logic.mul(c1, &xx)),
                    [c0] => c0.clone(),
                    _ => unreachable!(),
                })
                .collect();
            xx = self.logic.mul(&xx, &xx);
        }

        current_cc[0].clone()
    }
}
