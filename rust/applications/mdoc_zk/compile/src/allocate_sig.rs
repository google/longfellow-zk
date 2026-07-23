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

use circuits_bit_plucker::BitPlucker;
use compile_compiler::CompilerLogic;
use mdoc_zk_circuits::{
    config::K_SIG_MAC_BIT_PLUCKER,
    signature::{Derived as SigDerived, Given as SigGiven},
    MdocSigCompileField,
};

use crate::allocator::WireAllocator;

pub fn allocate_sig<'b, FC, C>(
    allocator: &mut WireAllocator<'_, 'b, FC>,
    plucker: &BitPlucker<'_, CompilerLogic<'b, FC>, { K_SIG_MAC_BIT_PLUCKER }>,
    _curve: &C,
) -> (
    SigGiven<CompilerLogic<'b, FC>>,
    SigDerived<CompilerLogic<'b, FC>>,
    usize,
    usize,
)
where
    FC: MdocSigCompileField,
    C: compile_algebra::Curve<4, F = FC, N = FC::N>,
{
    let issuer_pk = (allocator.allocate_wire(), allocator.allocate_wire());
    let device_sig_e = allocator.allocate_bitvec::<256>();

    let (mac_e, _) = allocator.allocate_tag_plucked(plucker);
    let (mac_device_pkx, _) = allocator.allocate_tag_plucked(plucker);
    let (mac_device_pky, _) = allocator.allocate_tag_plucked(plucker);

    let (mac_av, _) = allocator.allocate_plucked_v128(plucker);
    let pub_inputs_count = allocator.pos;

    let issuer_sig_e = allocator.allocate_bitvec::<256>();
    let device_pk = (
        allocator.allocate_bitvec::<256>(),
        allocator.allocate_bitvec::<256>(),
    );
    let issuer_sig_given =
        circuits_ecdsa2::allocate_given_wires(allocator.iologic, &mut allocator.pos);
    let device_sig_given =
        circuits_ecdsa2::allocate_given_wires(allocator.iologic, &mut allocator.pos);
    let issuer_sig_derived =
        circuits_ecdsa2::allocate_derived_wires(allocator.iologic, &mut allocator.pos);
    let device_sig_derived =
        circuits_ecdsa2::allocate_derived_wires(allocator.iologic, &mut allocator.pos);

    let subfield_boundary_val = allocator.pos;

    let mac_ap = {
        let (ap0, _) = allocator.allocate_tag_plucked(plucker);
        let (ap1, _) = allocator.allocate_tag_plucked(plucker);
        let (ap2, _) = allocator.allocate_tag_plucked(plucker);
        [ap0, ap1, ap2]
    };

    let given = mdoc_zk_circuits::signature::Given {
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
    };

    let derived = SigDerived {
        issuer_sig_derived,
        device_sig_derived,
    };

    (given, derived, pub_inputs_count, subfield_boundary_val)
}
