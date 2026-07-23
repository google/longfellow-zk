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

use circuits_ec::{
    concrete::{self as ec_concrete},
    Pt2, Pt3,
};
use compile_algebra::field::SupportsNatConversions;
use core_algebra::{BareField, Curve, Nat, NatOf};

#[derive(Clone, Debug)]
pub struct ConcreteSlicing<F: BareField> {
    pub g_pk: Pt2<F::E>,
    pub g_r: Pt2<F::E>,
    pub pk_r: Pt2<F::E>,
    pub g_pk_r: Pt2<F::E>,
    pub round: [Pt3<F::E>; 256],
}

#[derive(Clone, Debug)]
pub struct ConcreteGiven<F: BareField> {
    pub pkxy: Pt2<F::E>,
    pub e: F::E,
    pub rxy: Pt2<F::E>,
    pub ers: [F::E; 256],
}

#[derive(Clone, Debug)]
pub struct ConcreteDerived<F: BareField> {
    pub pkxinv: F::E,
    pub rxinv: F::E,
    pub nmsinv: F::E,
    pub yinv: F::E,
    pub slicing: ConcreteSlicing<F>,
}

pub fn given<
    const W: usize,
    F: core_algebra::AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    Fn: core_algebra::AlgebraicField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    pkxy: &(F::E, F::E),
    e: &NatOf<W, F>,
    r: &NatOf<W, F>,
    s: &NatOf<W, F>,
    f: &F,
    fn_field: &Fn,
) -> ConcreteGiven<F> {
    let s_fn = fn_field.nat_to_element(s);
    let s_inv = fn_field.invert(&s_fn);
    let e_fn = fn_field.nat_to_element(e);
    let r_fn = fn_field.nat_to_element(r);
    let te_s = fn_field.mulf(&e_fn, &s_inv);
    let tr_s = fn_field.mulf(&r_fn, &s_inv);
    let nes = fn_field.to_nat(&te_s);
    let nrs = fn_field.to_nat(&tr_s);

    let g = ec_concrete::projective(curve, f, curve.g());
    let pk = ec_concrete::projective(curve, f, pkxy);

    let nes_g = ec_concrete::scalar_mul(curve, f, 256, &nes, &g);
    let nrs_pk = ec_concrete::scalar_mul(curve, f, 256, &nrs, &pk);

    let r_proj = ec_concrete::add(curve, f, &nes_g, &nrs_pk);

    let rx = f.nat_to_element(r);
    let ry = f.mulf(&r_proj.1, &f.invert(&r_proj.2));

    let order_neg_s = fn_field.neg(&s_fn);
    let nms_nat = fn_field.to_nat(&order_neg_s);

    let e_bits = e.to_bits(256);
    let rx_bits = r.to_bits(256);
    let nms_bits = nms_nat.to_bits(256);

    let ers = std::array::from_fn(|i| {
        let idx =
            (usize::from(e_bits[i]) * 4) + (usize::from(rx_bits[i]) * 2) + usize::from(nms_bits[i]);
        f.lookup_point(9, idx)
    });

    ConcreteGiven {
        pkxy: pkxy.clone(),
        e: f.nat_to_element(e),
        rxy: (rx, ry),
        ers,
    }
}

pub fn derived<
    const W: usize,
    F: core_algebra::AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    Fn: core_algebra::AlgebraicField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    pkxy: &(F::E, F::E),
    e: &NatOf<W, F>,
    r: &NatOf<W, F>,
    s: &NatOf<W, F>,
    f: &F,
    fn_field: &Fn,
) -> ConcreteDerived<F> {
    let s_fn = fn_field.nat_to_element(s);
    let s_inv = fn_field.invert(&s_fn);
    let e_fn = fn_field.nat_to_element(e);
    let r_fn = fn_field.nat_to_element(r);
    let te_s = fn_field.mulf(&e_fn, &s_inv);
    let tr_s = fn_field.mulf(&r_fn, &s_inv);
    let nes = fn_field.to_nat(&te_s);
    let nrs = fn_field.to_nat(&tr_s);

    let g = ec_concrete::projective(curve, f, curve.g());
    let pk = ec_concrete::projective(curve, f, pkxy);

    let nes_g = ec_concrete::scalar_mul(curve, f, 256, &nes, &g);
    let nrs_pk = ec_concrete::scalar_mul(curve, f, 256, &nrs, &pk);

    let r_proj = ec_concrete::add(curve, f, &nes_g, &nrs_pk);

    let rx = f.nat_to_element(r);
    let ry = f.mulf(&r_proj.1, &f.invert(&r_proj.2));

    let r_pt = (rx.clone(), ry.clone(), f.one());

    let g_pk_proj = ec_concrete::add(curve, f, &g, &pk);
    let g_r_proj = ec_concrete::add(curve, f, &g, &r_pt);
    let pk_r_proj = ec_concrete::add(curve, f, &pk, &r_pt);

    let g_pk = ec_concrete::affine(f, &g_pk_proj);
    let g_r = ec_concrete::affine(f, &g_r_proj);
    let pk_r = ec_concrete::affine(f, &pk_r_proj);

    let pk_r_projective = ec_concrete::projective(curve, f, &pk_r);
    let g_pk_r_proj = ec_concrete::add(curve, f, &g, &pk_r_projective);
    let g_pk_r = ec_concrete::affine(f, &g_pk_r_proj);

    let order_neg_s = fn_field.neg(&s_fn);
    let nms_nat = fn_field.to_nat(&order_neg_s);

    let e_bits = e.to_bits(256);
    let rx_bits = r.to_bits(256);
    let nms_bits = nms_nat.to_bits(256);

    let opts = [
        ec_concrete::zero(f),
        r_pt.clone(),
        pk.clone(),
        pk_r_projective,
        g.clone(),
        ec_concrete::projective(curve, f, &g_r),
        ec_concrete::projective(curve, f, &g_pk),
        ec_concrete::projective(curve, f, &g_pk_r),
    ];

    let mut round = std::array::from_fn(|_| ec_concrete::zero(f));
    let mut p = ec_concrete::zero(f);
    for i in (0..256).rev() {
        let idx =
            (usize::from(e_bits[i]) * 4) + (usize::from(rx_bits[i]) * 2) + usize::from(nms_bits[i]);
        let b = &opts[idx];
        let sum_val = ec_concrete::add(curve, f, &ec_concrete::double(curve, f, &p), b);
        p = sum_val;
        round[i] = p.clone();
    }

    let pkxinv = f.invert(&pkxy.0);
    let rxinv = f.invert(&rx);
    let nms_val = f.nat_to_element(&nms_nat);
    let nmsinv = f.invert(&nms_val);
    let yinv = f.invert(&p.1);

    ConcreteDerived {
        pkxinv,
        rxinv,
        nmsinv,
        yinv,
        slicing: ConcreteSlicing {
            g_pk,
            g_r,
            pk_r,
            g_pk_r,
            round,
        },
    }
}

impl<F: BareField> ConcreteGiven<F> {
    pub fn push_elements(&self, mut push: impl FnMut(&F::E)) {
        push(&self.pkxy.0);
        push(&self.pkxy.1);
        push(&self.e);
        push(&self.rxy.0);
        push(&self.rxy.1);
        for elt in &self.ers {
            push(elt);
        }
    }
}

impl<F: BareField> ConcreteDerived<F> {
    pub fn push_elements(&self, mut push: impl FnMut(&F::E)) {
        push(&self.pkxinv);
        push(&self.rxinv);
        push(&self.nmsinv);
        push(&self.yinv);
        push(&self.slicing.g_pk.0);
        push(&self.slicing.g_pk.1);
        push(&self.slicing.g_r.0);
        push(&self.slicing.g_r.1);
        push(&self.slicing.pk_r.0);
        push(&self.slicing.pk_r.1);
        push(&self.slicing.g_pk_r.0);
        push(&self.slicing.g_pk_r.1);
        for pt in &self.slicing.round {
            push(&pt.0);
            push(&pt.1);
            push(&pt.2);
        }
    }
}
