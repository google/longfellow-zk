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

use circuits_analog_adder::FieldWrappingSum;
use circuits_sha256msg::{concrete::given, Sha256Msg};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::FieldID;
use core_algebra::SerializableField;
use runtime_algebra::field::RuntimeField;
use sha2::{Digest, Sha256 as Sha2Reference};

use super::test_support;

fn test_compile_sha256msg_for_field<
    'a,
    const W: usize,
    FC: CompileField + FieldWrappingSum + SerializableField,
    FR: RuntimeField<W> + SerializableField,
    const MAX_BLOCKS: usize,
>(
    fc: &'a FC,
    fr: &'a FR,
    name: &str,
    field_id: FieldID,
    message: &[u8],
) {
    let mut hasher = Sha2Reference::new();
    hasher.update(message);
    let _reference_hash = hasher.finalize();

    let arena = CompilerArena::new();
    let assertion = {
        let iologic = CompilerLogic::new(&arena, fc);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let sha256msg = Sha256Msg::<_, MAX_BLOCKS>::new(&iologic);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires =
            circuits_sha256msg::allocate_given::<CompilerLogic<'_, FC>, MAX_BLOCKS>(&bv, &mut pos);
        let derived_wires = circuits_sha256msg::allocate_derived::<CompilerLogic<'_, FC>, MAX_BLOCKS>(
            &bv, &mut pos,
        );

        sha256msg.assert_message_hash::<MAX_BLOCKS>(&given_wires, &derived_wires)
    };

    let given = given(message, &circuits_sha256::constants::INITIAL, MAX_BLOCKS).unwrap();
    let derived = circuits_sha256msg::concrete::derived(&given, MAX_BLOCKS);

    // Compile!
    let (circuit, stats, symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    let mut inputs = compile_eval::initial_inputs(fr);
    given.push_elements(fr, MAX_BLOCKS, |e| inputs.push(e));
    derived.push_elements(fr, |e| inputs.push(e));

    // Evaluate circuit
    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_sha256msg() {
    let p256_c = P256Field::new();
    let p256_r = runtime_algebra::p256::P256Field::new();
    test_compile_sha256msg_for_field::<4, _, _, 1>(
        &p256_c,
        &p256_r,
        "sha256msg_p256_empty",
        FieldID::P256,
        &[],
    );
    test_compile_sha256msg_for_field::<4, _, _, 2>(
        &p256_c,
        &p256_r,
        "sha256msg_p256_hello",
        FieldID::P256,
        b"hello world from Antigravity!",
    );

    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_sha256msg_for_field::<2, _, _, 1>(
        &gf2_c,
        &gf2_r,
        "sha256msg_gf2_empty",
        FieldID::Gf2_128,
        &[],
    );
    test_compile_sha256msg_for_field::<2, _, _, 2>(
        &gf2_c,
        &gf2_r,
        "sha256msg_gf2_hello",
        FieldID::Gf2_128,
        b"hello world from Antigravity!",
    );
}

#[test]
fn test_compile_sha256msg_tampering() {
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &fc);

    let message = b"hello world";
    let const_max_blocks = 2;
    let given_orig = given(
        message,
        &circuits_sha256::constants::INITIAL,
        const_max_blocks,
    )
    .unwrap();
    let derived_orig = circuits_sha256msg::concrete::derived(&given_orig, const_max_blocks);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let sha256msg = Sha256Msg::<_, 2>::new(&iologic);
    let bv = circuits_bitvec::BitvecLogic::new(&iologic);
    let given_wires =
        circuits_sha256msg::allocate_given::<CompilerLogic<'_, P256Field>, 2>(&bv, &mut pos);
    let derived_wires =
        circuits_sha256msg::allocate_derived::<CompilerLogic<'_, P256Field>, 2>(&bv, &mut pos);

    let assertion = sha256msg.assert_message_hash::<2>(&given_wires, &derived_wires);
    let (circuit, _stats, symbols) = compile_compiler::top::compile(&arena, &fc, assertion, 0, 0);

    let corruptors = test_support::all_sha256msg_corruptors();

    for c in corruptors {
        let mut g = given_orig.clone();
        let mut d = derived_orig.clone();
        (c.corrupt)(&mut g, &mut d);

        let mut inputs = compile_eval::initial_inputs(&fr);
        g.push_elements(&fr, const_max_blocks, |e| inputs.push(e));
        d.push_elements(&fr, |e| inputs.push(e));

        let eval_res =
            compile_eval::eval_circuit_fc(&fc, &fr, &circuit, &symbols, &inputs, FieldID::P256)
                .unwrap();
        assert!(
            eval_res.is_err(),
            "Corruptor '{}' failed to cause circuit evaluation error",
            c.name
        );
        let failed = eval_res.failed_paths();
        let expected_path = c.expected_compiled_path();
        assert!(
            failed.iter().any(|path| path == &expected_path),
            "Corruptor '{}' expected exact compiled failure path '{}', actual failures: {failed:?}",
            c.name,
            expected_path
        );
    }
}
