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

use circuits_mac::{
    circuit::MAC,
    concrete::{given, ConcreteGiven},
};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::FieldID;
use core_algebra::SerializableField;
use runtime_algebra::field::RuntimeField;

use super::test_support;

fn push_u128_bits<const W: usize, FR: RuntimeField<W>>(
    inputs: &mut Vec<FR::E>,
    val: u128,
    fr: &FR,
) {
    for k in 0..128 {
        let bit = (val >> k) & 1;
        inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
    }
}

fn make_inputs<const W: usize, FR: RuntimeField<W>>(given: &ConcreteGiven, fr: &FR) -> Vec<FR::E> {
    let mut inputs = compile_eval::initial_inputs(fr);
    for &byte in &given.message {
        for k in 0..8 {
            let bit = (byte >> k) & 1;
            inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
        }
    }
    push_u128_bits(&mut inputs, given.mac_av, fr);
    push_u128_bits(&mut inputs, given.mac_ap[0], fr);
    push_u128_bits(&mut inputs, given.mac_ap[1], fr);
    push_u128_bits(&mut inputs, given.tag[0], fr);
    push_u128_bits(&mut inputs, given.tag[1], fr);
    inputs
}

fn test_compile_mac_for_field<
    'a,
    const W: usize,
    FC: CompileField + SerializableField,
    FR: RuntimeField<W> + SerializableField,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
) {
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let mac_circuit = MAC::new(&iologic);
    let given_wires = circuits_mac::allocate_given(&mac_circuit.bv, &mut pos);

    let assertion = mac_circuit.assert_mac(&given_wires);

    let (circuit, stats, symbols) = compile_compiler::top::compile(&arena, fc, assertion, 1, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    let test_msg = [0x5au8; 32];
    let av_val: u128 = 0x112233445566778899aabbccddeeff00;
    let ap0_val: u128 = 0xabcdef0123456789abcdef0123456789;
    let ap1_val: u128 = 0xfedcba9876543210fedcba9876543210;

    let concrete_given = given(test_msg, av_val, [ap0_val, ap1_val]);

    // Verify untampered passes
    let inputs = make_inputs(&concrete_given, fr);
    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();

    // Verify all shared corruptors fail
    let corruptors = test_support::all_mac_corruptors();
    for c in corruptors {
        let mut g = concrete_given.clone();
        (c.corrupt)(&mut g);

        let inputs_tampered = make_inputs(&g, fr);
        let eval_res =
            compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs_tampered, field_id)
                .unwrap();
        assert!(
            eval_res.is_err(),
            "Corruptor '{}' failed to cause circuit evaluation error",
            c.name
        );
        let failed = eval_res.failed_paths();
        assert!(
            failed.iter().any(|path| path == &c.expected_path),
            "Corruptor '{}' expected exact compiled failure path '{}', actual failures: {failed:?}",
            c.name,
            c.expected_path
        );
    }
}

#[test]
fn test_compile_mac() {
    let fc_bin = Gf2_128Field::new();
    let fr_bin = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_mac_for_field::<2, _, _>(&fc_bin, &fr_bin, "mac_bin", FieldID::Gf2_128);

    let fc_prime = P256Field::new();
    let fr_prime = runtime_algebra::p256::P256Field::new();
    test_compile_mac_for_field::<4, _, _>(&fc_prime, &fr_prime, "mac_prime", FieldID::P256);
}
