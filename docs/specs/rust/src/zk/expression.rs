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

use std::collections::HashMap;

use crate::algebra::Field;

#[derive(Clone, Debug)]
pub struct Expression<F> {
    pub known: F,
    pub terms: HashMap<usize, F>,
}

impl<F: Field> Default for Expression<F> {
    fn default() -> Self {
        Self {
            known: F::zero(),
            terms: HashMap::new(),
        }
    }
}

impl<F: Field> Expression<F> {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn axpy(&mut self, x: &Self, a: F) {
        self.known += x.known * a;
        for (&idx, &coeff) in &x.terms {
            self.add_var(idx, coeff * a);
        }
    }

    pub fn scale(&mut self, s: F) {
        self.known *= s;
        if s.is_zero() {
            self.terms.clear();
        } else {
            for val in self.terms.values_mut() {
                *val *= s;
            }
        }
    }

    pub fn add_var(&mut self, witness_idx: usize, coeff: F) {
        use std::collections::hash_map::Entry;
        match self.terms.entry(witness_idx) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() += coeff;
                if entry.get().is_zero() {
                    entry.remove();
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(coeff);
            }
        }
    }
}

#[allow(non_snake_case)]
pub fn Var<F: Field>(witness_idx: usize) -> Expression<F> {
    let mut expr = Expression::zero();
    expr.add_var(witness_idx, F::one());
    expr
}

impl<F: Field> From<F> for Expression<F> {
    fn from(val: F) -> Self {
        let mut expr = Self::zero();
        expr.known = val;
        expr
    }
}

impl<F: Field> std::ops::Add for Expression<F> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.axpy(&rhs, F::one());
        self
    }
}

impl<F: Field> std::ops::Add<F> for Expression<F> {
    type Output = Self;
    fn add(mut self, rhs: F) -> Self {
        self.known += rhs;
        self
    }
}

impl<F: Field> std::ops::Sub for Expression<F> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        self.axpy(&rhs, F::mone());
        self
    }
}

impl<F: Field> std::ops::Sub<F> for Expression<F> {
    type Output = Self;
    fn sub(mut self, rhs: F) -> Self {
        self.known -= rhs;
        self
    }
}

impl<F: Field> std::ops::Neg for Expression<F> {
    type Output = Self;
    fn neg(mut self) -> Self {
        self.scale(F::mone());
        self
    }
}

impl<F: Field> std::ops::Mul<F> for Expression<F> {
    type Output = Self;
    fn mul(mut self, rhs: F) -> Self {
        self.scale(rhs);
        self
    }
}

impl<F: Field> std::ops::AddAssign for Expression<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.axpy(&rhs, F::one());
    }
}

impl<F: Field> std::ops::AddAssign<F> for Expression<F> {
    fn add_assign(&mut self, rhs: F) {
        self.known += rhs;
    }
}

impl<F: Field> std::ops::SubAssign for Expression<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.axpy(&rhs, F::mone());
    }
}

impl<F: Field> std::ops::SubAssign<F> for Expression<F> {
    fn sub_assign(&mut self, rhs: F) {
        self.known -= rhs;
    }
}

impl<F: Field> std::ops::MulAssign<F> for Expression<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.scale(rhs);
    }
}
