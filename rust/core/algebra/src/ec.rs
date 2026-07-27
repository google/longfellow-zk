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

use crate::{AlgebraicField, ElementOf, Nat};

pub trait Curve<const W: usize> {
    type F: AlgebraicField;
    type N: crate::Nat<W>;

    fn order(&self) -> Self::N;

    fn a(&self) -> &ElementOf<Self::F>;
    fn b(&self) -> &ElementOf<Self::F>;
    fn g(&self) -> &(ElementOf<Self::F>, ElementOf<Self::F>);
}

pub type Pt2<F> = (ElementOf<F>, ElementOf<F>);
pub type Pt3<F> = (ElementOf<F>, ElementOf<F>, ElementOf<F>);

pub fn zero<F: AlgebraicField>(f: &F) -> Pt3<F> {
    (f.zero(), f.one(), f.zero())
}

pub fn projective<F: AlgebraicField, const W: usize, C: Curve<W, F = F>>(
    _curve: &C,
    f: &F,
    pt: &Pt2<F>,
) -> Pt3<F> {
    let (x, y) = pt;
    (x.clone(), y.clone(), f.one())
}

pub fn affine<F: AlgebraicField>(f: &F, p: &Pt3<F>) -> Pt2<F> {
    let (x, y, z) = p;
    let zinv = f.invert(z);
    (f.mulf(x, &zinv), f.mulf(y, &zinv))
}

pub fn add<F: AlgebraicField, const W: usize, C: Curve<W, F = F>>(
    curve: &C,
    f: &F,
    p1: &Pt3<F>,
    p2: &Pt3<F>,
) -> Pt3<F> {
    let kb_val = curve.b().clone();
    let k3b_val = f.addf(&kb_val, &f.addf(&kb_val, &kb_val));
    let (x1, y1, z1) = p1;
    let (x2, y2, z2) = p2;
    let t0 = f.mulf(x1, x2);
    let t1 = f.mulf(y1, y2);
    let t2 = f.mulf(z1, z2);
    let t3_a = f.addf(x1, y1);
    let t4_a = f.addf(x2, y2);
    let t3_b = f.mulf(&t3_a, &t4_a);
    let t4_b = f.addf(&t0, &t1);
    let t3_c = f.subf(&t3_b, &t4_b);
    let t4_c = f.addf(x1, z1);
    let t5_a = f.addf(x2, z2);
    let t4_d = f.mulf(&t4_c, &t5_a);
    let t5_b = f.addf(&t0, &t2);
    let t4_e = f.subf(&t4_d, &t5_b);
    let t5_c = f.addf(y1, z1);
    let x3_tmp = f.addf(y2, z2);
    let t5_d = f.mulf(&t5_c, &x3_tmp);
    let x3_b = f.addf(&t1, &t2);
    let t5_e = f.subf(&t5_d, &x3_b);
    let a = curve.a();
    let z3_a = f.mulf(a, &t4_e);
    let x3_c = f.mulf(&k3b_val, &t2);
    let z3_b = f.addf(&x3_c, &z3_a);
    let x3_d = f.subf(&t1, &z3_b);
    let z3_c = f.addf(&t1, &z3_b);
    let y3_a = f.mulf(&x3_d, &z3_c);
    let t1_a = f.addf(&t0, &t0);
    let t1_b = f.addf(&t1_a, &t0);
    let t2_a = f.mulf(a, &t2);
    let t4_f = f.mulf(&k3b_val, &t4_e);
    let t1_c = f.addf(&t1_b, &t2_a);
    let t2_b = f.subf(&t0, &t2_a);
    let t2_c = f.mulf(a, &t2_b);
    let t4_g = f.addf(&t4_f, &t2_c);
    let t0_a = f.mulf(&t1_c, &t4_g);
    let y3_b = f.addf(&y3_a, &t0_a);
    let t0_b = f.mulf(&t5_e, &t4_g);
    let x3_e = f.mulf(&t3_c, &x3_d);
    let x3_res = f.subf(&x3_e, &t0_b);
    let t0_c = f.mulf(&t3_c, &t1_c);
    let z3_d = f.mulf(&t5_e, &z3_c);
    let z3_res = f.addf(&z3_d, &t0_c);
    (x3_res, y3_b, z3_res)
}

pub fn double<F: AlgebraicField, const W: usize, C: Curve<W, F = F>>(
    curve: &C,
    f: &F,
    pt: &Pt3<F>,
) -> Pt3<F> {
    let kb_val = curve.b();
    let k3b_val = f.addf(kb_val, &f.addf(kb_val, kb_val));
    let (x, y, z) = pt;
    let t0_a = f.mulf(x, x);
    let t1 = f.mulf(y, y);
    let t2_a = f.mulf(z, z);
    let t3_a = f.mulf(x, y);
    let t3_b = f.addf(&t3_a, &t3_a);
    let z3_a = f.mulf(x, z);
    let z3_b = f.addf(&z3_a, &z3_a);
    let a = curve.a();
    let x3_a = f.mulf(a, &z3_b);
    let y3_tmp = f.mulf(&k3b_val, &t2_a);
    let y3_a = f.addf(&x3_a, &y3_tmp);
    let x3_b = f.subf(&t1, &y3_a);
    let y3_b = f.addf(&t1, &y3_a);
    let y3_c = f.mulf(&x3_b, &y3_b);
    let x3_c = f.mulf(&t3_b, &x3_b);
    let z3_c = f.mulf(&k3b_val, &z3_b);
    let t2_b = f.mulf(a, &t2_a);
    let t3_c = f.subf(&t0_a, &t2_b);
    let t3_d = f.mulf(a, &t3_c);
    let t3_e = f.addf(&t3_d, &z3_c);
    let z3_d = f.addf(&t0_a, &t0_a);
    let t0_b = f.addf(&z3_d, &t0_a);
    let t0_c = f.addf(&t0_b, &t2_b);
    let t0_d = f.mulf(&t0_c, &t3_e);
    let y3_res = f.addf(&y3_c, &t0_d);
    let t2_c = f.mulf(y, z);
    let t2_d = f.addf(&t2_c, &t2_c);
    let t0_e = f.mulf(&t2_d, &t3_e);
    let x3_res = f.subf(&x3_c, &t0_e);
    let z3_e = f.mulf(&t2_d, &t1);
    let z3_f = f.addf(&z3_e, &z3_e);
    let z3_res = f.addf(&z3_f, &z3_f);
    (x3_res, y3_res, z3_res)
}

pub fn scalar_mul<F: AlgebraicField, const W: usize, C: Curve<W, F = F>>(
    curve: &C,
    f: &F,
    n: usize,
    scalar: &C::N,
    pt: &Pt3<F>,
) -> Pt3<F> {
    let mut res = zero(f);
    let mut temp = pt.clone();
    for i in 0..n {
        if scalar.bit(i) {
            res = add(curve, f, &res, &temp);
        }
        temp = double(curve, f, &temp);
    }
    res
}

pub fn scalar_mul_bytes<F: AlgebraicField, const W: usize, C: Curve<W, F = F>>(
    curve: &C,
    f: &F,
    scalar_bytes: &[u8],
    pt: &Pt3<F>,
) -> Pt3<F> {
    let mut res = zero(f);
    let mut temp = pt.clone();
    for &byte in scalar_bytes {
        let mut cur_byte = byte;
        for _ in 0..8 {
            if (cur_byte & 1) != 0 {
                res = add(curve, f, &res, &temp);
            }
            temp = double(curve, f, &temp);
            cur_byte >>= 1;
        }
    }
    res
}
