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

use crate::{field::RuntimeField, permutations};

pub struct Twiddle<const W: usize, F: RuntimeField<W>> {
    pub order: usize,
    pub w: Vec<F::E>,
}

impl<const W: usize, F: RuntimeField<W>> Twiddle<W, F> {
    pub fn new(order: usize, omega_order: &F::E, f: &F) -> Self {
        let mut w = Vec::with_capacity(order / 2);
        let mut curr = f.one();
        for _ in 0..(order / 2) {
            w.push(curr.clone());
            f.mul(&mut curr, omega_order);
        }
        Self { order, w }
    }

    pub fn reroot(omega_n: &F::E, n: u64, mut r: u64, f: &F) -> F::E {
        let mut omega_r = omega_n.clone();
        while r < n {
            let tmp = omega_r.clone();
            f.mul(&mut omega_r, &tmp);
            r += r;
        }
        omega_r
    }
}

pub fn butterfly<const W: usize, F: RuntimeField<W>>(s: usize, a: &mut [F::E], f: &F) {
    let t = a[s].clone();
    a[s] = a[0].clone();
    f.sub(&mut a[s], &t);
    f.add(&mut a[0], &t);
}

pub fn butterflytw<const W: usize, F: RuntimeField<W>>(
    s: usize,
    a: &mut [F::E],
    twiddle: &F::E,
    f: &F,
) {
    let (first, second) = a.split_at_mut(s);
    f.mul(&mut second[0], twiddle);
    let t = second[0].clone();
    second[0] = first[0].clone();
    f.sub(&mut second[0], &t);
    f.add(&mut first[0], &t);
}

pub fn fftb<const W: usize, F: RuntimeField<W>>(a: &mut [F::E], omega_j: &F::E, j: u64, f: &F) {
    let n = a.len();
    if n > 1 {
        let omega_n = Twiddle::<W, F>::reroot(omega_j, j, n as u64, f);
        let roots = Twiddle::<W, F>::new(n, &omega_n, f);

        permutations::bitrev(a);

        // m = 1 iteration
        for k in (0..n).step_by(2) {
            butterfly(1, &mut a[k..], f);
        }

        // m > 1 iterations
        let mut m = 2;
        while m < n {
            let ws = roots.order / (2 * m);
            for k in (0..n).step_by(2 * m) {
                butterfly(m, &mut a[k..], f);
                for step in 1..m {
                    let twiddle = &roots.w[step * ws];
                    butterflytw(m, &mut a[k + step..], twiddle, f);
                }
            }
            m *= 2;
        }
    }
}

pub fn fftf<const W: usize, F: RuntimeField<W>>(
    a: &mut [F::E],
    omega: &F::E,
    omega_order: u64,
    f: &F,
) {
    let inv = f.invert(omega);
    fftb(a, &inv, omega_order, f);
}
