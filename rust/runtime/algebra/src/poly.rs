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

use crate::field::RuntimeField;

pub trait InterpolationField<const W: usize>: RuntimeField<W> + SerializableField {
    fn poly_evaluation_point(&self, i: usize) -> Self::E;
    fn newton_denominator(&self, k: usize, i: usize) -> Self::E;
}

#[derive(Debug, Eq, PartialEq)]
pub struct Poly<const N: usize, const W: usize, F: SerializableField> {
    pub evaluations: [F::E; N],
}

impl<const N: usize, const W: usize, F: SerializableField> Clone for Poly<N, W, F> {
    fn clone(&self) -> Self {
        Self {
            evaluations: self.evaluations.clone(),
        }
    }
}

impl<const N: usize, const W: usize, F: SerializableField + RuntimeField<W>> Poly<N, W, F> {
    pub fn zero(f: &F) -> Self {
        Self {
            evaluations: std::array::from_fn(|_| f.zero()),
        }
    }

    pub fn sub_in_place(&mut self, y: &Self, f: &F) {
        for i in 0..N {
            f.sub(&mut self.evaluations[i], &y.evaluations[i]);
        }
    }

    pub fn add(&mut self, y: &Self, f: &F) {
        for i in 0..N {
            f.add(&mut self.evaluations[i], &y.evaluations[i]);
        }
    }

    pub fn eval_monomial(&self, x: &F::E, f: &F) -> F::E {
        let mut e = self.evaluations[N - 1].clone();
        for i in (0..(N - 1)).rev() {
            f.mul(&mut e, x);
            f.add(&mut e, &self.evaluations[i]);
        }
        e
    }
}

impl<const N: usize, const W: usize, F: SerializableField + InterpolationField<W>> Poly<N, W, F> {
    pub fn newton_of_lagrange(&mut self, f: &F) {
        for i in 1..N {
            for k in (i..N).rev() {
                let prev = self.evaluations[k - 1].clone();
                f.sub(&mut self.evaluations[k], &prev);
                let denom = f.newton_denominator(k, i);
                f.mul(&mut self.evaluations[k], &denom);
            }
        }
    }

    pub fn eval_newton(&self, x: &F::E, f: &F) -> F::E {
        let mut e = self.evaluations[N - 1].clone();
        for i in (0..(N - 1)).rev() {
            let mut dx = x.clone();
            f.sub(&mut dx, &f.poly_evaluation_point(i));
            f.mul(&mut e, &dx);
            f.add(&mut e, &self.evaluations[i]);
        }
        e
    }

    pub fn eval_lagrange(&self, x: &F::E, f: &F) -> F::E {
        let mut tmp = self.clone();
        tmp.newton_of_lagrange(f);
        tmp.eval_newton(x, f)
    }
}

/// Represents the Lagrange basis polynomials converted to the Newton basis.
///
/// Evaluating each basis polynomial at a point `x` yields the Lagrange
/// coefficients $[`L_0(x)`, `L_1(x)`, \dots, L_{N-1}(x)]$. Taking the dot product
/// of these coefficients with polynomial evaluations at interpolation points
/// evaluates the polynomial at `x`.
pub struct LagrangeBasis<const N: usize, const W: usize, F: InterpolationField<W>> {
    /// The Kronecker delta functions (Lagrange basis polynomials) represented in the Newton basis.
    pub delta_in_newton_basis: [Poly<N, W, F>; N],
}

impl<const N: usize, const W: usize, F: InterpolationField<W>> LagrangeBasis<N, W, F> {
    /// Computes the Lagrange basis polynomials in the Newton basis.
    pub fn new(f: &F) -> Self {
        let mut delta_in_newton_basis = std::array::from_fn(|_| Poly::zero(f));
        for (k, delta_k) in delta_in_newton_basis.iter_mut().enumerate() {
            for i in 0..N {
                delta_k.evaluations[i] = if i == k { f.one() } else { f.zero() };
            }
            delta_k.newton_of_lagrange(f);
        }
        Self {
            delta_in_newton_basis,
        }
    }

    /// Evaluates the Lagrange basis polynomials at `x` to obtain the Lagrange coefficients.
    pub fn coef(&self, x: &F::E, f: &F) -> Poly<N, W, F> {
        let mut c = Poly::zero(f);
        for k in 0..N {
            c.evaluations[k] = self.delta_in_newton_basis[k].eval_newton(x, f);
        }
        c
    }
}
