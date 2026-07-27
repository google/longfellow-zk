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

use compile_algebra::{field::CompileField, Curve};
use compile_logic::{Eltw, Logic};
use core_algebra::ElementOf;

pub type Pt2<T> = (T, T);
pub type Pt3<T> = (T, T, T);

pub fn iter_pt2<T, E>(pt: &(T, T), f: &mut impl FnMut(&T) -> Result<(), E>) -> Result<(), E> {
    f(&pt.0)?;
    f(&pt.1)?;
    Ok(())
}

pub fn iter_pt3<T, E>(pt: &(T, T, T), f: &mut impl FnMut(&T) -> Result<(), E>) -> Result<(), E> {
    f(&pt.0)?;
    f(&pt.1)?;
    f(&pt.2)?;
    Ok(())
}

pub struct EcCircuit<'a, const W: usize, C: Curve<W>, L: Logic<F = C::F>> {
    logic: &'a L,
    k3b_val: ElementOf<C::F>,
    curve: &'a C,
}

impl<'a, const W: usize, C, L, F> EcCircuit<'a, W, C, L>
where
    C: Curve<W, F = F>,
    L: Logic<F = F>,
    F: CompileField,
{
    pub fn new(logic: &'a L, curve: &'a C) -> Self {
        let f = logic.field();
        let kb_val = curve.b();
        let k3b_val = f.addf(kb_val, &f.addf(kb_val, kb_val));
        Self {
            logic,
            k3b_val,
            curve,
        }
    }

    pub fn g(&self) -> Pt2<Eltw<L>> {
        let g_c = self.curve.g();
        (self.logic.konst(&g_c.0), self.logic.konst(&g_c.1))
    }

    pub fn projective(&self, pt: &Pt2<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (x, y) = pt;
        let l = &self.logic;
        (x.clone(), y.clone(), l.one())
    }

    pub fn zero(&self) -> Pt3<Eltw<L>> {
        let l = &self.logic;
        (l.zero(), l.one(), l.zero())
    }

    pub fn add(&self, p1: &Pt3<Eltw<L>>, p2: &Pt3<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (x1, y1, z1) = p1;
        let (x2, y2, z2) = p2;
        let l = &self.logic;
        let t0 = l.mul(x1, x2);
        let t1 = l.mul(y1, y2);
        let t2 = l.mul(z1, z2);
        let t3_a = l.add(x1, y1);
        let t4_a = l.add(x2, y2);
        let t3_b = l.mul(&t3_a, &t4_a);
        let t4_b = l.add(&t0, &t1);
        let t3_c = l.sub(&t3_b, &t4_b);
        let t4_c = l.add(x1, z1);
        let t5_a = l.add(x2, z2);
        let t4_d = l.mul(&t4_c, &t5_a);
        let t5_b = l.add(&t0, &t2);
        let t4_e = l.sub(&t4_d, &t5_b);
        let t5_c = l.add(y1, z1);
        let x3_tmp = l.add(y2, z2);
        let t5_d = l.mul(&t5_c, &x3_tmp);
        let x3_b = l.add(&t1, &t2);
        let t5_e = l.sub(&t5_d, &x3_b);
        let a = l.konst(self.curve.a());
        let z3_a = l.mul(&a, &t4_e);
        let k3b = l.konst(&self.k3b_val);
        let x3_c = l.mul(&k3b, &t2);
        let z3_b = l.add(&x3_c, &z3_a);
        let x3_d = l.sub(&t1, &z3_b);
        let z3_c = l.add(&t1, &z3_b);
        let y3_a = l.mul(&x3_d, &z3_c);
        let t1_a = l.add(&t0, &t0);
        let t1_b = l.add(&t1_a, &t0);
        let t2_a = l.mul(&a, &t2);
        let t4_f = l.mul(&k3b, &t4_e);
        let t1_c = l.add(&t1_b, &t2_a);
        let t2_b = l.sub(&t0, &t2_a);
        let t2_c = l.mul(&a, &t2_b);
        let t4_g = l.add(&t4_f, &t2_c);
        let t0_a = l.mul(&t1_c, &t4_g);
        let y3_b = l.add(&y3_a, &t0_a);
        let t0_b = l.mul(&t5_e, &t4_g);
        let x3_e = l.mul(&t3_c, &x3_d);
        let x3_res = l.sub(&x3_e, &t0_b);
        let t0_c = l.mul(&t3_c, &t1_c);
        let z3_d = l.mul(&t5_e, &z3_c);
        let z3_res = l.add(&z3_d, &t0_c);
        (x3_res, y3_b, z3_res)
    }

    pub fn double(&self, pt: &Pt3<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (x, y, z) = pt;
        let l = &self.logic;
        let t0_a = l.mul(x, x);
        let t1 = l.mul(y, y);
        let t2_a = l.mul(z, z);
        let t3_a = l.mul(x, y);
        let t3_b = l.add(&t3_a, &t3_a);
        let z3_a = l.mul(x, z);
        let z3_b = l.add(&z3_a, &z3_a);
        let a = l.konst(self.curve.a());
        let k3b = l.konst(&self.k3b_val);
        let x3_a = l.mul(&a, &z3_b);
        let y3_tmp = l.mul(&k3b, &t2_a);
        let y3_a = l.add(&x3_a, &y3_tmp);
        let x3_b = l.sub(&t1, &y3_a);
        let y3_b = l.add(&t1, &y3_a);
        let y3_c = l.mul(&x3_b, &y3_b);
        let x3_c = l.mul(&t3_b, &x3_b);
        let z3_c = l.mul(&k3b, &z3_b);
        let t2_b = l.mul(&a, &t2_a);
        let t3_c = l.sub(&t0_a, &t2_b);
        let t3_d = l.mul(&a, &t3_c);
        let t3_e = l.add(&t3_d, &z3_c);
        let z3_d = l.add(&t0_a, &t0_a);
        let t0_b = l.add(&z3_d, &t0_a);
        let t0_c = l.add(&t0_b, &t2_b);
        let t0_d = l.mul(&t0_c, &t3_e);
        let y3_res = l.add(&y3_c, &t0_d);
        let t2_c = l.mul(y, z);
        let t2_d = l.add(&t2_c, &t2_c);
        let t0_e = l.mul(&t2_d, &t3_e);
        let x3_res = l.sub(&x3_c, &t0_e);
        let z3_e = l.mul(&t2_d, &t1);
        let z3_f = l.add(&z3_e, &z3_e);
        let z3_res = l.add(&z3_f, &z3_f);
        (x3_res, y3_res, z3_res)
    }

    pub fn point_equality(
        &self,
        pt: &Pt3<Eltw<L>>,
        zinv: &Eltw<L>,
        px: &Pt2<Eltw<L>>,
    ) -> L::Assertions {
        let (x, y, z) = pt;
        let (px_val, py_val) = px;
        let l = &self.logic;
        l.assert_all(
            "point_equality",
            &[
                l.assert_eq("px_eq", &l.mul(x, zinv), px_val),
                l.assert_eq("py_eq", &l.mul(y, zinv), py_val),
                l.assert_eq("z_zinv", &l.mul(z, zinv), &l.one()),
            ],
        )
    }

    pub fn is_on_curve(&self, pt: &Pt2<Eltw<L>>) -> L::Assertions {
        let (x, y) = pt;
        let l = &self.logic;
        let lhs = l.mul(y, y);
        let x2 = l.mul(x, x);
        let x3 = l.mul(&x2, x);
        let a = l.konst(self.curve.a());
        let ax = l.mul(&a, x);
        let b = l.konst(self.curve.b());
        let rhs = l.sum(&[x3, ax, b]);
        l.assert0("is_on_curve", &l.sub(&lhs, &rhs))
    }

    /// Converts projective point `pt` to affine witness `w` with Z=1.
    ///
    /// # Safety Note on Soundness
    /// When Z != 0, this enforces `x = z * wx` and `y = z * wy` (i.e. `wx = x/z`, `wy = y/z`).
    /// Callers using `slicing2` (such as `EcdsaCircuit`) MUST assert `is_on_curve` on the resulting
    /// affine witness `w` to guarantee that `(wx, wy)` lies on the curve, ensuring witness
    /// soundness.
    pub fn slicing2(&self, w: &Pt2<Eltw<L>>, pt: &Pt3<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (wx, wy) = w;
        let (x, y, z) = pt;
        let l = &self.logic;
        (
            l.with_assertions(l.assert_eq("slice_x", x, &l.mul(z, wx)), wx),
            l.with_assertions(l.assert_eq("slice_y", y, &l.mul(z, wy)), wy),
            l.one(),
        )
    }

    pub fn slicing3(&self, w: &Pt3<Eltw<L>>, pt: &Pt3<Eltw<L>>) -> Pt3<Eltw<L>> {
        let (wx, wy, wz) = w;
        let (x, y, z) = pt;
        (
            self.logic.slicing("slice_wx", wx, x),
            self.logic.slicing("slice_wy", wy, y),
            self.logic.slicing("slice_wz", wz, z),
        )
    }
}

pub fn pt2_wires<L: compile_logic::LogicIO>(iologic: &L, pos: &mut usize) -> Pt2<Eltw<L>> {
    let x = iologic.next(pos);
    let y = iologic.next(pos);
    (x, y)
}

pub fn pt3_wires<L: compile_logic::LogicIO>(iologic: &L, pos: &mut usize) -> Pt3<Eltw<L>> {
    let x = iologic.next(pos);
    let y = iologic.next(pos);
    let z = iologic.next(pos);
    (x, y, z)
}
