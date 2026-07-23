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

use super::Field;

pub fn lagrange_basis<F: Field>(r: F) -> Vec<F> {
    let pts = F::sumcheck_eval_points();
    let (x0, x1, x2) = (pts[0], pts[1], pts[2]);
    let l0 = ((r - x1) * (r - x2)) / ((x0 - x1) * (x0 - x2));
    let l1 = ((r - x0) * (r - x2)) / ((x1 - x0) * (x1 - x2));
    let l2 = ((r - x0) * (r - x1)) / ((x2 - x0) * (x2 - x1));
    vec![l0, l1, l2]
}

pub fn lagrange_matrix<F: Field>(pts: &[F], k: usize, n: usize) -> Vec<F> {
    let mut inv_d = vec![F::zero(); k];
    for i in 0..k {
        let mut d = F::one();
        for j in 0..k {
            if i != j {
                d *= pts[i] - pts[j];
            }
        }
        inv_d[i] = d.inv();
    }

    let mut l = vec![F::zero(); k * n];
    for i in 0..k {
        let inv_d_i = inv_d[i];
        for x in 0..n {
            let idx = i * n + x;
            if x < k {
                l[idx] = if x == i { F::one() } else { F::zero() };
            } else {
                let mut num = F::one();
                for j in 0..k {
                    if j != i {
                        num *= pts[x] - pts[j];
                    }
                }
                l[idx] = num * inv_d_i;
            }
        }
    }

    l
}
