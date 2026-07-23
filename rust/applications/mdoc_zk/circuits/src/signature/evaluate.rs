// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses///LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use circuits_bitvec::BitvecLogic;
use compile_algebra::Curve;

use super::{
    circuit::{Derived, Given},
    concrete::{ConcreteDerived, ConcreteGiven},
};
use crate::traits::MdocSigCompileField;

fn eval_v128<L: compile_logic::LogicIO>(
    bv: &BitvecLogic<L>,
    val: u128,
) -> circuits_bitvec::V128<L> {
    let boolean = circuits_boolean::Boolean::new(bv.logic());
    bv.from_fn::<128, _>(|idx| {
        let bit_val = (val.checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    })
}
pub fn evaluate_given<C, L: compile_logic::LogicIO<F = F>, F: MdocSigCompileField>(
    logic: &L,
    bv: &BitvecLogic<L>,
    given: &ConcreteGiven<F, F::N>,
    f: &F,
) -> Given<L>
where
    C: Curve<4, F = F, N = F::N>,
{
    let issuer_pk = (
        logic.konst(&f.nat_to_element(&given.sig_input.issuer_pk.0)),
        logic.konst(&f.nat_to_element(&given.sig_input.issuer_pk.1)),
    );
    let big_bv = circuits_big_bitvec::BigBitvec::new(bv.logic());
    let issuer_sig_e = big_bv.of_nat::<4, 256, F>(&given.sig_input.issuer_sig_e);
    let issuer_sig_given = circuits_ecdsa2::evaluate_given(&given.issuer_sig_given, logic);

    let device_pk = (
        big_bv.of_nat::<4, 256, F>(&given.sig_input.device_pk.0),
        big_bv.of_nat::<4, 256, F>(&given.sig_input.device_pk.1),
    );
    let device_sig_e = big_bv.of_nat::<4, 256, F>(&given.sig_input.device_sig_e);
    let device_sig_given = circuits_ecdsa2::evaluate_given(&given.device_sig_given, logic);

    let mac_e = [eval_v128(bv, given.mac_e[0]), eval_v128(bv, given.mac_e[1])];
    let mac_device_pkx = [
        eval_v128(bv, given.mac_device_pkx[0]),
        eval_v128(bv, given.mac_device_pkx[1]),
    ];
    let mac_device_pky = [
        eval_v128(bv, given.mac_device_pky[0]),
        eval_v128(bv, given.mac_device_pky[1]),
    ];

    let mac_av = eval_v128(bv, given.mac_input.mac_av);
    let mac_ap = std::array::from_fn(|i| {
        [
            eval_v128(bv, given.mac_input.mac_ap[i][0]),
            eval_v128(bv, given.mac_input.mac_ap[i][1]),
        ]
    });

    Given {
        issuer_pk,
        issuer_sig_e,
        issuer_sig_given,
        device_pk,
        device_sig_e,
        device_sig_given,
        mac_e,
        mac_device_pkx,
        mac_device_pky,
        mac_av,
        mac_ap,
    }
}

pub fn evaluate_derived<C, L: compile_logic::LogicIO<F = F>, F: MdocSigCompileField>(
    logic: &L,
    _bv: &BitvecLogic<L>,
    derived: &ConcreteDerived<F>,
) -> Derived<L>
where
    C: Curve<4, F = F, N = F::N>,
{
    let issuer_sig_derived = circuits_ecdsa2::evaluate_derived(&derived.issuer_sig_derived, logic);
    let device_sig_derived = circuits_ecdsa2::evaluate_derived(&derived.device_sig_derived, logic);

    Derived {
        issuer_sig_derived,
        device_sig_derived,
    }
}
