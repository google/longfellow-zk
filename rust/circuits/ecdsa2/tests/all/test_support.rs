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

#![allow(dead_code)]

use circuits_ec::concrete::{affine, projective, scalar_mul};
use circuits_ecdsa2::concrete::{derived, given, ConcreteDerived, ConcreteGiven};
use core_algebra::{AlgebraicField, BareField, Curve, SupportsNatConversions};

pub(crate) fn sign_and_generate_given_derived<
    const W: usize,
    F: AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    S: AlgebraicField + SupportsNatConversions<W, N = F::N>,
    C: Curve<W, F = F, N = F::N>,
>(
    curve: &C,
    field: &F,
    scalar_field: &S,
    d: &C::N,
    k: &C::N,
    e: &C::N,
) -> (ConcreteGiven<F>, ConcreteDerived<F>) {
    let g_val = curve.g().clone();
    let g_proj = projective(curve, field, &g_val);

    // Q = d * G
    let q_proj = scalar_mul(curve, field, 256, d, &g_proj);
    let q_normalized = affine(field, &q_proj);

    // R = k * G
    let r_proj = scalar_mul(curve, field, 256, k, &g_proj);
    let r_normalized = affine(field, &r_proj);
    let rx = field.to_nat(&r_normalized.0);

    // Convert rx to scalar field to get r = rx mod order
    let rx_scalar = scalar_field.reduce_nat(&rx);
    let r = scalar_field.to_nat(&rx_scalar);

    // s = k^-1 * (e + r * d)
    let e_scalar = scalar_field.reduce_nat(e);
    let r_scalar = rx_scalar;
    let d_scalar = scalar_field.reduce_nat(d);
    let k_scalar = scalar_field.reduce_nat(k);
    let rd = scalar_field.mulf(&r_scalar, &d_scalar);
    let e_rd = scalar_field.addf(&e_scalar, &rd);
    let k_inv = scalar_field.invert(&k_scalar);
    let s_scalar = scalar_field.mulf(&k_inv, &e_rd);
    let s = scalar_field.to_nat(&s_scalar);

    let concrete_given = given(curve, &q_normalized, e, &r, &s, field, scalar_field);
    let concrete_derived = derived(curve, &q_normalized, e, &r, &s, field, scalar_field);

    (concrete_given, concrete_derived)
}

pub struct EcdsaCorruptor<F: BareField> {
    pub name: &'static str,
    pub expected_path: &'static str,
    pub corrupt: Box<dyn Fn(&mut ConcreteGiven<F>, &mut ConcreteDerived<F>)>,
}

pub fn all_ecdsa_corruptors<
    const W: usize,
    F: AlgebraicField + SupportsNatConversions<W> + core_algebra::HasLookupPoints + Clone + 'static,
>(
    fr: &F,
) -> Vec<EcdsaCorruptor<F>> {
    vec![
        EcdsaCorruptor {
            name: "flip_ers0",
            expected_path: "ecdsa/e_eq",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.ers[0] = fr.addf(&g.ers[0], &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "out_of_range_ers0",
            expected_path: "ecdsa/range_check/range_check.0",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.ers[0] = fr.lookup_point(9, 8);
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_rxy0",
            expected_path: "ecdsa/rx_eq",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.rxy.0 = fr.addf(&g.rxy.0, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_pkxy0",
            expected_path: "ecdsa/pkxinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.pkxy.0 = fr.addf(&g.pkxy.0, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "zero_rxy0",
            expected_path: "ecdsa/rxinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.rxy.0 = fr.zero();
                }
            }),
        },
        EcdsaCorruptor {
            name: "zero_pkxy0",
            expected_path: "ecdsa/pkxinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.pkxy.0 = fr.zero();
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_yinv",
            expected_path: "ecdsa/yinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.yinv = fr.addf(&d.yinv, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_rxinv",
            expected_path: "ecdsa/rxinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.rxinv = fr.addf(&d.rxinv, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_nmsinv",
            expected_path: "ecdsa/nmsinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.nmsinv = fr.addf(&d.nmsinv, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_pkxinv",
            expected_path: "ecdsa/pkxinv",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.pkxinv = fr.addf(&d.pkxinv, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_pkxy1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.pkxy.1 = fr.addf(&g.pkxy.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_rxy1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    g.rxy.1 = fr.addf(&g.rxy.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_g_pk1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.g_pk.1 = fr.addf(&d.slicing.g_pk.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_g_r1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.g_r.1 = fr.addf(&d.slicing.g_r.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_pk_r1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.pk_r.1 = fr.addf(&d.slicing.pk_r.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "flip_g_pk_r1",
            expected_path: "ecdsa/is_on_curve",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.g_pk_r.1 = fr.addf(&d.slicing.g_pk_r.1, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "round255_0",
            expected_path: "ecdsa/ax_zero",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.round[255].0 = fr.addf(&d.slicing.round[255].0, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "round255_2",
            expected_path: "ecdsa/az_zero",
            corrupt: Box::new({
                let fr = fr.clone();
                move |_g, d| {
                    d.slicing.round[255].2 = fr.addf(&d.slicing.round[255].2, &fr.one());
                }
            }),
        },
        EcdsaCorruptor {
            name: "nms_overflow",
            expected_path: "ecdsa/nms_lt_order",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    let p = fr.lookup_point(9, 1);
                    for i in 0..256 {
                        g.ers[i] = p.clone();
                    }
                }
            }),
        },
        EcdsaCorruptor {
            name: "rx_nms_overflow",
            expected_path: "ecdsa/rx_lt_order",
            corrupt: Box::new({
                let fr = fr.clone();
                move |g, _d| {
                    let p = fr.lookup_point(9, 7);
                    for i in 0..256 {
                        g.ers[i] = p.clone();
                    }
                }
            }),
        },
    ]
}
