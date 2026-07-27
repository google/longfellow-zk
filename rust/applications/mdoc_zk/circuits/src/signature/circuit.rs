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

use circuits_bitvec::{BitvecLogic, V128, V256};
use circuits_ecdsa2::{Derived as EcdsaDerived, EcdsaCircuit, Given as EcdsaGiven};
use compile_algebra::Curve;
use compile_logic::Eltw;

use crate::traits::MdocSigCompileField;

pub struct Given<L: compile_logic::LogicIO> {
    pub issuer_pk: (Eltw<L>, Eltw<L>),
    pub issuer_sig_e: V256<L>,
    pub issuer_sig_given: EcdsaGiven<L>,
    pub device_pk: (V256<L>, V256<L>),
    pub device_sig_e: V256<L>,
    pub device_sig_given: EcdsaGiven<L>,
    pub mac_e: [V128<L>; 2],
    pub mac_device_pkx: [V128<L>; 2],
    pub mac_device_pky: [V128<L>; 2],
    pub mac_av: V128<L>,
    pub mac_ap: [[V128<L>; 2]; 3],
}

pub struct Derived<L: compile_logic::Logic> {
    pub issuer_sig_derived: EcdsaDerived<L>,
    pub device_sig_derived: EcdsaDerived<L>,
}

pub struct MdocSignature<'a, const W: usize, C: Curve<W>, L: compile_logic::LogicIO<F = C::F>> {
    pub(crate) logic: &'a L,
    pub(crate) ecdsa: EcdsaCircuit<'a, W, C, L>,
    pub(crate) mac_circuit: circuits_mac::circuit::MAC<'a, L>,
    pub(crate) bv: BitvecLogic<'a, L>,
}

impl<'a, C, L, F> MdocSignature<'a, 4, C, L>
where
    C: Curve<4, F = F, N = F::N>,
    L: compile_logic::LogicIO<F = F>,
    F: MdocSigCompileField,
{
    pub fn new(logic: &'a L, curve: &'a C) -> Self {
        Self {
            logic,
            ecdsa: EcdsaCircuit::new(logic, curve),
            mac_circuit: circuits_mac::circuit::MAC::new(logic),
            bv: BitvecLogic::new(logic),
        }
    }

    /// Asserts validity of ECDSA signatures and GF(2^128) MAC tag witness bindings across circuits.
    ///
    /// # Soundness Note
    /// In `mdoc_zk`, the `mac_ap` witness elements inside `c_sig` and `c_hash` are committed into
    /// their respective Merkle root commitments via `ZkProver::commit` BEFORE the random
    /// challenge `mac_av` is drawn from the transcript (`av_val = tp.u128()`). Because `mac_ap`
    /// is committed prior to drawing `mac_av`, an attacker cannot modify `mac_ap` to forge
    /// mismatched messages across circuits without probability at most 2^-128.
    pub fn assert_signatures_and_macs(
        &self,
        given: &Given<L>,
        derived: &Derived<L>,
    ) -> L::Assertions {
        let device_pkx = self
            .logic
            .precious(&self.bv.as_eltw_unsafe(&given.device_pk.0));
        let device_pky = self
            .logic
            .precious(&self.bv.as_eltw_unsafe(&given.device_pk.1));

        let issuer_e_elt = self
            .logic
            .precious(&self.bv.as_eltw_unsafe(&given.issuer_sig_e));
        let device_e_elt = self
            .logic
            .precious(&self.bv.as_eltw_unsafe(&given.device_sig_e));

        let assertions = vec![
            self.logic
                .assert_eq("issuer_e_eq", &given.issuer_sig_given.e, &issuer_e_elt),
            self.logic.assert_eq(
                "issuer_pkx_eq",
                &given.issuer_sig_given.pkxy.0,
                &given.issuer_pk.0,
            ),
            self.logic.assert_eq(
                "issuer_pky_eq",
                &given.issuer_sig_given.pkxy.1,
                &given.issuer_pk.1,
            ),
            self.ecdsa
                .assert_signature(&given.issuer_sig_given, &derived.issuer_sig_derived),
            self.logic
                .assert_eq("device_e_eq", &given.device_sig_given.e, &device_e_elt),
            self.logic
                .assert_eq("device_pkx_eq", &given.device_sig_given.pkxy.0, &device_pkx),
            self.logic
                .assert_eq("device_pky_eq", &given.device_sig_given.pkxy.1, &device_pky),
            self.ecdsa
                .assert_signature(&given.device_sig_given, &derived.device_sig_derived),
            self.mac_circuit.assert_mac(&circuits_mac::circuit::Given {
                message: given.issuer_sig_e.clone(),
                mac_av: given.mac_av.clone(),
                mac_ap: given.mac_ap[0].clone(),
                tag: given.mac_e.clone(),
            }),
            self.mac_circuit.assert_mac(&circuits_mac::circuit::Given {
                message: given.device_pk.0.clone(),
                mac_av: given.mac_av.clone(),
                mac_ap: given.mac_ap[1].clone(),
                tag: given.mac_device_pkx.clone(),
            }),
            self.mac_circuit.assert_mac(&circuits_mac::circuit::Given {
                message: given.device_pk.1.clone(),
                mac_av: given.mac_av.clone(),
                mac_ap: given.mac_ap[2].clone(),
                tag: given.mac_device_pky.clone(),
            }),
        ];

        self.logic.assert_all("signature", &assertions)
    }
}
