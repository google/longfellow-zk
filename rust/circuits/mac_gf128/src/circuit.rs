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

use circuits_bitvec::BitvecLogic;

pub struct Given<L: compile_logic::Logic> {
    pub message: circuits_bitvec::Bitvec<L, 256>,
    pub mac_av: compile_logic::Eltw<L>,
    pub mac_ap: [compile_logic::Eltw<L>; 2],
    pub tag: [compile_logic::Eltw<L>; 2],
}

pub type Derived = ();

pub struct MAC<'a, L: compile_logic::Logic> {
    pub logic: &'a L,
    pub bv: BitvecLogic<'a, L>,
}

impl<'a, L: compile_logic::Logic> MAC<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            bv: BitvecLogic::new(logic),
        }
    }

    pub fn assert_mac(&self, given: &Given<L>) -> L::Assertions {
        let (msg0, msg1) = self.bv.split::<256, 128, 128>(&given.message);
        let msg0_elt = self.bv.as_eltw_field(&msg0);
        let msg1_elt = self.bv.as_eltw_field(&msg1);

        let assertions = vec![
            // tag + mac_ap = mac_av * msg
            self.logic.assert_eq(
                "msg0_eq",
                &self.logic.add(&given.tag[0], &given.mac_ap[0]),
                &self.logic.mul(&given.mac_av, &msg0_elt),
            ),
            self.logic.assert_eq(
                "msg1_eq",
                &self.logic.add(&given.tag[1], &given.mac_ap[1]),
                &self.logic.mul(&given.mac_av, &msg1_elt),
            ),
        ];
        self.logic.assert_all("assert_mac", &assertions)
    }

    pub fn assert_macs(&self, givens: &[Given<L>]) -> L::Assertions {
        self.logic.assert_mapi("assert_macs", 0..givens.len(), |i| {
            self.assert_mac(&givens[i])
        })
    }
}
