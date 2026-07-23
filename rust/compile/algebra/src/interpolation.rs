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

use core_algebra::ElementOf;

use crate::field::CompileField;

pub fn newton_of_lagrange<F: CompileField>(
    f: &F,
    a: &[ElementOf<F>],
    x: &[ElementOf<F>],
) -> Vec<ElementOf<F>> {
    assert_eq!(a.len(), x.len());
    let n = a.len();
    if n == 0 {
        return Vec::new();
    }
    let mut coeffs = a.to_vec();
    for i in 1..n {
        for k in (i..n).rev() {
            let dx = f.subf(&x[k], &x[k - i]);
            coeffs[k] = f.mulf(&f.invert(&dx), &f.subf(&coeffs[k], &coeffs[k - 1]));
        }
    }
    coeffs
}

pub fn eval_newton<F: CompileField>(
    f: &F,
    a: &[ElementOf<F>],
    x: &[ElementOf<F>],
    point: &ElementOf<F>,
) -> ElementOf<F> {
    assert_eq!(a.len(), x.len());
    let n = a.len();
    let mut accu = f.zero();
    for i in (0..n).rev() {
        accu = f.addf(&a[i], &f.mulf(&accu, &f.subf(point, &x[i])));
    }
    accu
}

pub fn monomial_of_newton<F: CompileField>(
    f: &F,
    a: &[ElementOf<F>],
    x: &[ElementOf<F>],
) -> Vec<ElementOf<F>> {
    assert_eq!(a.len(), x.len());
    let n = a.len();
    let mut coeffs = a.to_vec();
    for i in (0..n).rev() {
        for k in (i + 1)..n {
            let term = f.mulf(&coeffs[k], &x[i]);
            coeffs[k - 1] = f.subf(&coeffs[k - 1], &term);
        }
    }
    coeffs
}

pub fn eval_monomial<F: CompileField>(
    f: &F,
    a: &[ElementOf<F>],
    point: &ElementOf<F>,
) -> ElementOf<F> {
    let mut accu = f.zero();
    for e in a.iter().rev() {
        accu = f.addf(e, &f.mulf(&accu, point));
    }
    accu
}

pub fn monomial_of_lagrange<F: CompileField>(
    f: &F,
    l: &[ElementOf<F>],
    x: &[ElementOf<F>],
) -> Vec<ElementOf<F>> {
    monomial_of_newton(f, &newton_of_lagrange(f, l, x), x)
}
