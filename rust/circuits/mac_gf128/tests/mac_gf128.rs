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

use circuits_mac_gf128::{circuit::MAC, concrete::given};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field};
use core_algebra::SerializableField;

fn test_compile_mac_gf128_for_field<FC: CompileField + SerializableField>(fc: &FC, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(fc, |iologic| {
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

        let mac_circuit = MAC::new(&iologic);
        let given = circuits_mac_gf128::allocate_given(&iologic, &mac_circuit.bv, &mut pos);

        let assertion = mac_circuit.assert_mac(&given);

        (assertion, 1, 0)
    });

    compile_compiler::dump_stats(name, &circuit, &stats);
}

#[test]
fn test_compile_mac_gf128() {
    let fc_bin = Gf2_128Field::new();
    test_compile_mac_gf128_for_field(&fc_bin, "mac_gf128");
}

use circuits_bitvec::BitvecLogic;
use compile_logic::eval::EvalLogic;

#[test]
fn test_direct_eval_mac_gf128() {
    let fc = Gf2_128Field::new();
    let test_msg = [0x5au8; 32];
    let av_val: u128 = 0x112233445566778899aabbccddeeff00;
    let ap0_val: u128 = 0xabcdef0123456789abcdef0123456789;
    let ap1_val: u128 = 0xfedcba9876543210fedcba9876543210;

    let concrete_given = given(test_msg, av_val, [ap0_val, ap1_val]);

    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, FC> = EvalLogic<'a, FC>;
    let lp = L::new(&fc, &tracker);
    let bv = BitvecLogic::new(&lp);
    let mac_circuit = MAC::new(&lp);

    let boolean = circuits_boolean::Boolean::new(&lp);
    let wire_msg = bv.from_fn::<256, _>(|idx| {
        let byte = test_msg[idx / 8];
        let bit_val = ((byte >> (idx % 8)) & 1) == 1;
        boolean.konst(bit_val)
    });

    let wire_av = bv.as_eltw_field(&bv.from_fn::<128, _>(|idx| {
        let bit_val = (av_val.checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    }));
    let wire_ap0 = bv.as_eltw_field(&bv.from_fn::<128, _>(|idx| {
        let bit_val = (ap0_val.checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    }));
    let wire_ap1 = bv.as_eltw_field(&bv.from_fn::<128, _>(|idx| {
        let bit_val = (ap1_val.checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    }));
    let wire_tag0 = bv.as_eltw_field(&bv.from_fn::<128, _>(|idx| {
        let bit_val = (concrete_given.tag[0].checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    }));
    let wire_tag1 = bv.as_eltw_field(&bv.from_fn::<128, _>(|idx| {
        let bit_val = (concrete_given.tag[1].checked_shr(idx as u32).unwrap_or(0) & 1) == 1;
        boolean.konst(bit_val)
    }));

    let wire_given = circuits_mac_gf128::Given {
        message: wire_msg,
        mac_av: wire_av,
        mac_ap: [wire_ap0, wire_ap1],
        tag: [wire_tag0, wire_tag1],
    };

    let assertion = mac_circuit.assert_mac(&wire_given);
    assertion.unwrap();
}
