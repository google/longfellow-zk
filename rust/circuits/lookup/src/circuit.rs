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

use circuits_polynomial::Polynomial;
use compile_algebra::field::CompileField;
use compile_logic::{Eltw, Logic};
use core_algebra::ElementOf;

pub struct Lookup<'a, L: Logic> {
    logic: &'a L,
}

pub struct Table<'a, L: Logic> {
    logic: &'a L,
    plucker: Vec<Eltw<L>>,
    polynomial: Polynomial<'a, L>,
}

impl<L: Logic> Table<'_, L> {
    pub fn eval(&self, encoded: &Eltw<L>) -> Eltw<L> {
        let val = self.polynomial.eval(&self.plucker, encoded);
        self.logic.precious(&val)
    }

    #[must_use]
    pub fn plucker(&self) -> &[Eltw<L>] {
        &self.plucker
    }
}

impl<'a, F: CompileField, L: Logic<F = F>> Lookup<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self { logic }
    }

    #[must_use]
    pub fn point(&self, n: usize, i: usize) -> ElementOf<L::F> {
        self.logic.field().lookup_point(n, i)
    }

    pub fn table(
        &self,
        n: usize,
        mut f_init: impl FnMut(usize) -> Option<Eltw<L>>,
    ) -> Table<'a, L> {
        let f = self.logic.field();
        let mut active_indices = Vec::new();
        let mut active_values = Vec::new();
        for i in 0..n {
            if let Some(val) = f_init(i) {
                active_indices.push(i);
                active_values.push(val);
            }
        }
        let m = active_indices.len();
        assert!(m > 0, "Lookup table must have at least one active point");

        let mut x = Vec::with_capacity(m);
        for &i in &active_indices {
            x.push(self.point(n, i));
        }

        let mut basis = Vec::with_capacity(m);
        for k in 0..m {
            let mut y = vec![f.zero(); m];
            y[k] = f.one();
            basis.push(compile_algebra::interpolation::monomial_of_lagrange(
                f, &y, &x,
            ));
        }

        let mut plucker = Vec::with_capacity(m);
        for j in 0..m {
            let terms: Vec<_> = basis
                .iter()
                .zip(&active_values)
                .map(|(b_row, val)| self.logic.mulk(&b_row[j], val))
                .collect();
            let sum = self.logic.sum(&terms);
            plucker.push(self.logic.precious(&sum));
        }

        Table {
            logic: self.logic,
            plucker,
            polynomial: Polynomial::new(self.logic),
        }
    }

    pub fn table_of_array(&self, a: &[Eltw<L>]) -> Table<'a, L> {
        self.table(a.len(), |i| Some(a[i].clone()))
    }
}
