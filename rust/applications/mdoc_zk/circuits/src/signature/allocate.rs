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
use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(logic: &L, bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = circuits_bitvec::BitvecIO::new(bv);
    let issuer_pk = (logic.next(pos), logic.next(pos));
    let issuer_sig_e = bitvec_io.next::<256>(pos);
    let issuer_sig_given = circuits_ecdsa2::allocate_given_wires(logic, pos);
    let device_pk = (bitvec_io.next::<256>(pos), bitvec_io.next::<256>(pos));
    let device_sig_e = bitvec_io.next::<256>(pos);
    let device_sig_given = circuits_ecdsa2::allocate_given_wires(logic, pos);
    let mac_e = [bitvec_io.next::<128>(pos), bitvec_io.next::<128>(pos)];
    let mac_device_pkx = [bitvec_io.next::<128>(pos), bitvec_io.next::<128>(pos)];
    let mac_device_pky = [bitvec_io.next::<128>(pos), bitvec_io.next::<128>(pos)];
    let mac_av = bitvec_io.next::<128>(pos);
    let mac_ap = std::array::from_fn(|_| [bitvec_io.next::<128>(pos), bitvec_io.next::<128>(pos)]);
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

pub fn allocate_derived<L: LogicIO>(logic: &L, pos: &mut usize) -> Derived<L> {
    let issuer_sig_derived = circuits_ecdsa2::allocate_derived_wires(logic, pos);
    let device_sig_derived = circuits_ecdsa2::allocate_derived_wires(logic, pos);
    Derived {
        issuer_sig_derived,
        device_sig_derived,
    }
}
