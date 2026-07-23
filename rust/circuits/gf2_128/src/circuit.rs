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

use circuits_bitvec::V128;
use circuits_boolean::{Bitw, Boolean};
use compile_logic::Logic;

const THRESHOLD: usize = 16;

pub struct Gf2_128Mul<'a, L: Logic> {
    logic: &'a L,
    taps: Vec<Vec<usize>>,
}

impl<'a, L: Logic> Gf2_128Mul<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            taps: generate_taps::<128>(&[0, 1, 2, 7]),
        }
    }
}

impl<L: Logic> Gf2_128Mul<'_, L> {
    fn gf2_polynomial_multiplier(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let n = a.len();
        assert_eq!(n, b.len());
        let boolean = Boolean::new(self.logic);

        (0..(2 * n))
            .map(|k| {
                let t: Vec<_> = (0..n)
                    .filter(|&i| k >= i && k - i < n)
                    .map(|i| boolean.andb(&a[i], &b[k - i]))
                    .collect();
                boolean.parity(&t)
            })
            .collect()
    }

    fn gf2_polynomial_multiplier_karatsuba(&self, a: &[Bitw<L>], b: &[Bitw<L>]) -> Vec<Bitw<L>> {
        let w = a.len();
        assert_eq!(w, b.len());
        assert!(w.is_power_of_two());

        if w < THRESHOLD {
            self.gf2_polynomial_multiplier(a, b)
        } else {
            let boolean = Boolean::new(self.logic);
            let a01: Vec<_> = (0..(w / 2))
                .map(|i| boolean.xorb(&a[i], &a[i + w / 2]))
                .collect();
            let b01: Vec<_> = (0..(w / 2))
                .map(|i| boolean.xorb(&b[i], &b[i + w / 2]))
                .collect();

            let ab01_raw = self.gf2_polynomial_multiplier_karatsuba(&a01, &b01);
            let a0b0 = self.gf2_polynomial_multiplier_karatsuba(&a[..(w / 2)], &b[..(w / 2)]);
            let a1b1 = self.gf2_polynomial_multiplier_karatsuba(&a[(w / 2)..], &b[(w / 2)..]);

            let ab01: Vec<_> = ab01_raw
                .into_iter()
                .zip(&a0b0)
                .zip(&a1b1)
                .map(|((ab, a0), a1)| boolean.xor3(&ab, a0, a1))
                .collect();

            let c0 = a0b0[..(w / 2)].to_vec();
            let c1: Vec<_> = (0..(w / 2))
                .map(|i| boolean.xorb(&a0b0[i + w / 2], &ab01[i]))
                .collect();
            let c2: Vec<_> = (0..(w / 2))
                .map(|i| boolean.xorb(&ab01[i + w / 2], &a1b1[i]))
                .collect();
            let c3 = a1b1[(w / 2)..].to_vec();

            [c0, c1, c2, c3].concat()
        }
    }

    #[must_use]
    pub fn mul(&self, a: &V128<L>, b: &V128<L>) -> V128<L> {
        let t = self.gf2_polynomial_multiplier_karatsuba(a.as_array(), b.as_array());
        let boolean = Boolean::new(self.logic);

        let mut c_bits = Vec::with_capacity(128);
        for i in 0..128 {
            let mut tmp = Vec::with_capacity(self.taps[i].len());
            for &ti in &self.taps[i] {
                tmp.push(t[ti].clone());
            }
            c_bits.push(boolean.parity(&tmp));
        }
        V128::new(c_bits)
    }
}

fn shift_left<const N: usize>(mut r: [bool; N]) -> (bool, [bool; N]) {
    let carry = r[N - 1];
    r.copy_within(0..N - 1, 1);
    r[0] = false;
    (carry, r)
}

fn generate_taps<const N: usize>(lower_terms: &[usize]) -> Vec<Vec<usize>> {
    let mut taps = vec![Vec::new(); N];
    let mut r = [false; N];
    r[0] = true;

    for i in 0..(2 * N - 1) {
        for j in 0..N {
            if r[j] {
                taps[j].push(i);
            }
        }
        let carry;
        (carry, r) = shift_left(r);
        if carry {
            for &term in lower_terms {
                r[term] ^= true;
            }
        }
    }
    taps
}
