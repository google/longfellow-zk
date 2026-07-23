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
use circuits_bitvec::{BitvecLogic, V256};
use circuits_boolean::Boolean;
use circuits_ec::{EcCircuit, Pt2, Pt3};
use compile_algebra::{
    field::{CompileField, SupportsNatConversions},
    Curve,
};
use compile_logic::{Eltw, Logic, LogicIO};

#[derive(Clone)]
pub struct Slicing<L: Logic> {
    pub g_pk: Pt2<Eltw<L>>,
    pub g_r: Pt2<Eltw<L>>,
    pub pk_r: Pt2<Eltw<L>>,
    pub g_pk_r: Pt2<Eltw<L>>,
    pub round: [Pt3<Eltw<L>>; 256],
}

#[derive(Clone)]
pub struct Given<L: Logic> {
    pub pkxy: Pt2<Eltw<L>>,
    pub e: Eltw<L>,
    pub rxy: Pt2<Eltw<L>>,
    pub ers: [Eltw<L>; 256],
}

#[derive(Clone)]
pub struct Derived<L: Logic> {
    pub pkxinv: Eltw<L>,
    pub rxinv: Eltw<L>,
    pub nmsinv: Eltw<L>,
    pub yinv: Eltw<L>,
    pub slicing: Slicing<L>,
}

pub struct EcdsaCircuit<'a, const W: usize, C: Curve<W>, L: Logic<F = C::F>> {
    pub(crate) ec: EcCircuit<'a, W, C, L>,
    pub(crate) boolean: Boolean<'a, L>,
    pub(crate) bv: BitvecLogic<'a, L>,
    pub(crate) logic: &'a L,
    pub(crate) curve: &'a C,
}

impl<'a, const W: usize, C, L, F> EcdsaCircuit<'a, W, C, L>
where
    C: Curve<W, F = F, N = F::N>,
    L: Logic<F = F>,
    F: CompileField + SupportsNatConversions<W> + core_algebra::SupportsU64Conversions,
{
    pub fn new(logic: &'a L, curve: &'a C) -> Self {
        let ec = EcCircuit::new(logic, curve);
        let boolean = Boolean::new(logic);
        let bv = BitvecLogic::new(logic);
        Self {
            ec,
            boolean,
            bv,
            logic,
            curve,
        }
    }

    fn delta(&self, b: bool) -> Eltw<L> {
        if b {
            self.logic.one()
        } else {
            self.logic.zero()
        }
    }

    fn delta8(&self, idx: usize, b: bool) -> Option<Eltw<L>> {
        if idx < 8 {
            Some(self.delta(b))
        } else {
            None
        }
    }

    fn delta9(&self, _idx: usize, b: bool) -> Option<Eltw<L>> {
        Some(self.delta(b))
    }

    fn opt8(&self, idx: usize, f_init: impl FnOnce() -> Eltw<L>) -> Option<Eltw<L>> {
        if idx < 8 {
            Some(f_init())
        } else {
            None
        }
    }

    pub fn assert_signature(&self, given: &Given<L>, derived: &Derived<L>) -> L::Assertions {
        assert_eq!(given.ers.len(), 256);

        let order_bits = circuits_big_bitvec::BigBitvec::new(self.logic)
            .of_nat::<W, 256, F>(&self.curve.order());
        let (pkx, _pky) = &given.pkxy;

        let pk = self.ec.projective(&given.pkxy);
        let r = self.ec.projective(&given.rxy);
        let g = self.ec.projective(&self.ec.g());

        // Convert precomputed linear combinations to affine witness coordinates via slicing2.
        // Soundness note: `is_on_curve` is explicitly asserted on `g_pk`, `g_r`, `pk_r`, and
        // `g_pk_r` in `assertions` below, guaranteeing that all 4 slicing points are valid
        // curve points.
        let g_pk = self
            .ec
            .slicing2(&derived.slicing.g_pk, &self.ec.add(&g, &pk));
        let g_r = self.ec.slicing2(&derived.slicing.g_r, &self.ec.add(&g, &r));
        let pk_r = self
            .ec
            .slicing2(&derived.slicing.pk_r, &self.ec.add(&pk, &r));
        let g_pk_r = self
            .ec
            .slicing2(&derived.slicing.g_pk_r, &self.ec.add(&g, &pk_r));

        let opts = [self.ec.zero(), r, pk, pk_r, g, g_r, g_pk, g_pk_r];

        let lookup = circuits_lookup::Lookup::new(self.logic);

        let table_x = lookup.table(9, |idx| self.opt8(idx, || opts[idx].0.clone()));
        let table_y = lookup.table(9, |idx| self.opt8(idx, || opts[idx].1.clone()));
        let table_z = lookup.table(9, |idx| self.opt8(idx, || opts[idx].2.clone()));

        let table_e = lookup.table(9, |idx| self.delta8(idx, (idx & 4) != 0));
        let table_r = lookup.table(9, |idx| self.delta8(idx, (idx & 2) != 0));
        let table_nms = lookup.table(9, |idx| self.delta8(idx, (idx & 1) != 0));

        let table_range = lookup.table(9, |idx| self.delta9(idx, idx == 8));

        let mut rx_bits_vec = vec![self.boolean.falseb(); 256];
        let mut nms_bits_vec = vec![self.boolean.falseb(); 256];
        let mut e_bits_vec = vec![self.boolean.falseb(); 256];

        let mut p = self.ec.zero();

        let range_assertions = self.logic.assert_mapi("range_check", 0..256, |i| {
            let x = &given.ers[i];
            let range_ok = table_range.eval(x);
            self.logic.assert0("valid_index", &range_ok)
        });

        for i in (0..256).rev() {
            let x = &given.ers[i];

            // Evaluate coordinate lookup:
            let tx = table_x.eval(x);
            let ty = table_y.eval(x);
            let tz = table_z.eval(x);
            let b = (tx, ty, tz);

            // Evaluate exponent bits:
            let e_val = table_e.eval(x);
            let r_val = table_r.eval(x);
            let nms_val = table_nms.eval(x);

            // Soundness note: of_eltw_with_assertion attaches range_assertions to the bit,
            // proving that x is a valid index (0..8) and that table_e, table_r, and table_nms
            // evaluate to 0 or 1.
            let e_i = self
                .boolean
                .of_eltw_with_assertion(e_val, range_assertions.clone());
            let r_i = self
                .boolean
                .of_eltw_with_assertion(r_val, range_assertions.clone());
            let nms_i = self
                .boolean
                .of_eltw_with_assertion(nms_val, range_assertions.clone());

            e_bits_vec[i] = e_i;
            rx_bits_vec[i] = r_i;
            nms_bits_vec[i] = nms_i;

            let sum_val = self.ec.add(&self.ec.double(&p), &b);
            p = self.ec.slicing3(&derived.slicing.round[i], &sum_val);
        }

        let arith = Arithmetic::new(self.logic);
        let (ax, ay, az) = p;
        let nms_val = arith.as_eltw_unsafe(&nms_bits_vec);
        let e_val = arith.as_eltw_unsafe(&e_bits_vec);
        let rx_val = arith.as_eltw_unsafe(&rx_bits_vec);

        let rx_bits = V256::new(rx_bits_vec);
        let nms_bits = V256::new(nms_bits_vec);

        let mut assertions = vec![range_assertions];
        assertions.extend([
            self.logic.assert0("ax_zero", &ax),
            self.logic.assert0("az_zero", &az),
            self.logic.assert_inverse("yinv", &ay, &derived.yinv),
            self.logic.assert_eq("rx_eq", &given.rxy.0, &rx_val),
            self.logic.assert_eq("e_eq", &given.e, &e_val),
            self.ec.is_on_curve(&given.pkxy),
            self.ec.is_on_curve(&given.rxy),
            self.ec.is_on_curve(&derived.slicing.g_pk),
            self.ec.is_on_curve(&derived.slicing.g_r),
            self.ec.is_on_curve(&derived.slicing.pk_r),
            self.ec.is_on_curve(&derived.slicing.g_pk_r),
            self.logic
                .assert_inverse("rxinv", &given.rxy.0, &derived.rxinv),
            self.logic
                .assert_inverse("nmsinv", &nms_val, &derived.nmsinv),
            self.logic.assert_inverse("pkxinv", pkx, &derived.pkxinv),
            self.boolean
                .assert_true("rx_lt_order", &self.bv.lt(&rx_bits, &order_bits)),
            self.boolean
                .assert_true("nms_lt_order", &self.bv.lt(&nms_bits, &order_bits)),
        ]);

        self.logic.assert_all("ecdsa", &assertions)
    }
}

impl<const W: usize, C, L, F> EcdsaCircuit<'_, W, C, L>
where
    C: Curve<W, F = F, N = F::N>,
    L: LogicIO<F = F>,
    F: CompileField + SupportsNatConversions<W> + core_algebra::SupportsU64Conversions,
{
}
