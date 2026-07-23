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

use circuits_arithmetic::Arithmetic;
use circuits_bitvec::{Bitvec, BitvecLogic};
use circuits_boolean::{Bitw, Boolean};
use compile_logic::{Eltw, Logic};

fn extend<T: Clone>(a: &[T], default: &T, i: isize) -> T {
    let n = a.len() as isize;
    if i >= 0 && i < n {
        a[i as usize].clone()
    } else {
        default.clone()
    }
}

fn really_shift<L: Logic, T: Clone, FMux>(
    mux: &FMux,
    selector: &[Bitw<L>],
    n: usize,
    k: usize,
    a: &mut [T],
    shift: usize,
    default: &T,
) where
    FMux: Fn(&[Bitw<L>], &dyn Fn(usize) -> T) -> T,
{
    let aa = a.to_vec();
    let limit = std::cmp::min(n, k + shift);
    for (i, elem) in a.iter_mut().enumerate().take(limit) {
        *elem = mux(selector, &|j| {
            extend(&aa, default, (i + j * shift) as isize)
        });
    }
}

fn really_unshift<L: Logic, T: Clone, FMux>(
    mux: &FMux,
    selector: &[Bitw<L>],
    n: usize,
    k: usize,
    a: &mut [T],
    shift: usize,
    default: &T,
) where
    FMux: Fn(&[Bitw<L>], &dyn Fn(usize) -> T) -> T,
{
    let aa = a.to_vec();
    let c = selector.len();
    let limit = std::cmp::min(n, k.saturating_add(c.saturating_mul(shift)));
    for (i, elem) in a.iter_mut().enumerate().take(limit) {
        *elem = mux(selector, &|j| {
            extend(&aa, default, (i as isize) - (j * shift) as isize)
        });
    }
}

pub struct Routing<'a, L: Logic> {
    logic: &'a L,
    boolean: Boolean<'a, L>,
    arith: Arithmetic<'a, L>,
}

impl<'a, L: Logic> Routing<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            boolean: Boolean::new(logic),
            arith: Arithmetic::new(logic),
        }
    }

    fn amount_selector(&self, logc: usize, amount: &[Bitw<L>], l: usize) -> Vec<Bitw<L>> {
        let c = 1 << logc;
        let consumed_amount: Vec<Bitw<L>> = (0..logc).map(|k| amount[l + k].clone()).collect();
        let eq_fn = |x: &[Bitw<L>], y: &[Bitw<L>]| self.arith.eqb(x, y);
        (0..c)
            .map(|val| self.arith.relint(&eq_fn, &consumed_amount, val as u64))
            .collect()
    }

    fn generic_shift<T: Clone, FMux>(
        &self,
        mux: &FMux,
        unroll: usize,
        amount: &[Bitw<L>],
        k: usize,
        a: &[T],
        default: &T,
    ) -> Vec<T>
    where
        FMux: Fn(&[Bitw<L>], &dyn Fn(usize) -> T) -> T,
    {
        let n = a.len();
        let logn = amount.len();
        let mut tmp = a.to_vec();

        assert!(unroll > 0, "unroll parameter must be > 0");
        let mut l = logn;
        let mut target_nrounds = logn.div_ceil(unroll);

        while target_nrounds > 0 {
            let consumed = l.div_ceil(target_nrounds);
            l -= consumed;
            let shift = 1 << l;
            let selector = self.amount_selector(consumed, amount, l);
            really_shift(mux, &selector, n, k, &mut tmp, shift, default);
            target_nrounds -= 1;
        }

        (0..k)
            .map(|i| {
                if i < n {
                    tmp[i].clone()
                } else {
                    default.clone()
                }
            })
            .collect()
    }

    fn generic_unshift<T: Clone, FMux>(
        &self,
        mux: &FMux,
        unroll: usize,
        amount: &[Bitw<L>],
        n: usize,
        b: &[T],
        default: &T,
    ) -> Vec<T>
    where
        FMux: Fn(&[Bitw<L>], &dyn Fn(usize) -> T) -> T,
    {
        let k = b.len();
        let logn = amount.len();
        let mut a: Vec<T> = (0..n)
            .map(|i| if i < k { b[i].clone() } else { default.clone() })
            .collect();

        let mut l = 0;
        let mut target_nrounds = logn.div_ceil(unroll);

        while target_nrounds > 0 {
            let consumed = (logn - l).div_ceil(target_nrounds);
            let shift = 1 << l;
            let selector = self.amount_selector(consumed, amount, l);
            really_unshift(mux, &selector, n, k, &mut a, shift, default);
            l += consumed;
            target_nrounds -= 1;
        }

        a
    }

    pub fn shiftb<const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        k: usize,
        a: &[Bitw<L>],
        default: &Bitw<L>,
    ) -> Vec<Bitw<L>> {
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Bitw<L>| self.boolean.one_hot_muxb(sel, data);
        self.generic_shift(&mux, unroll, amount.as_array(), k, a, default)
    }

    pub fn shift_bitvec<const N: usize, const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        k: usize,
        a: &[Bitvec<L, N>],
        default: &Bitvec<L, N>,
    ) -> Vec<Bitvec<L, N>> {
        let bv_logic = BitvecLogic::new(self.logic);
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Bitvec<L, N>| bv_logic.one_hot_mux(sel, data);
        self.generic_shift(&mux, unroll, amount.as_array(), k, a, default)
    }

    pub fn unshift_bitvec<const N: usize, const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        n: usize,
        b: &[Bitvec<L, N>],
        default: &Bitvec<L, N>,
    ) -> Vec<Bitvec<L, N>> {
        let bv_logic = BitvecLogic::new(self.logic);
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Bitvec<L, N>| bv_logic.one_hot_mux(sel, data);
        self.generic_unshift(&mux, unroll, amount.as_array(), n, b, default)
    }

    pub fn unshiftb<const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        n: usize,
        b: &[Bitw<L>],
        default: &Bitw<L>,
    ) -> Vec<Bitw<L>> {
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Bitw<L>| self.boolean.one_hot_muxb(sel, data);
        self.generic_unshift(&mux, unroll, amount.as_array(), n, b, default)
    }

    pub fn shifte<const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        k: usize,
        a: &[Eltw<L>],
        default: &Eltw<L>,
    ) -> Vec<Eltw<L>> {
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Eltw<L>| self.boolean.one_hot_muxe(sel, data);
        self.generic_shift(&mux, unroll, amount.as_array(), k, a, default)
    }

    pub fn unshifte<const M: usize>(
        &self,
        unroll: usize,
        amount: &Bitvec<L, M>,
        n: usize,
        b: &[Eltw<L>],
        default: &Eltw<L>,
    ) -> Vec<Eltw<L>> {
        let mux =
            |sel: &[Bitw<L>], data: &dyn Fn(usize) -> Eltw<L>| self.boolean.one_hot_muxe(sel, data);
        self.generic_unshift(&mux, unroll, amount.as_array(), n, b, default)
    }
}
