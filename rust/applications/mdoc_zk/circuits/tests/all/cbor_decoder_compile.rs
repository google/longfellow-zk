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
use circuits_boolean::Boolean;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::FieldID;
use compile_logic::Logic;
use core_algebra::SerializableField;
use mdoc_zk_circuits::cbor_decoder::{allocate_given, CborByteDecoder, ConcreteGiven};
use runtime_algebra::field::RuntimeField;

fn test_compile_cbor_decoder_for_field<
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

    let bv = BitvecLogic::new(&iologic);
    let boolean = Boolean::new(&iologic);
    let decoder = CborByteDecoder::new(&iologic);
    let given_wires = allocate_given(&bv, &mut pos);

    let (decoded, add_assertion) = decoder.decode_one_v8::<8>(&given_wires.v);

    // Combine add_assertion with an assertion on invalid
    let not_invalid = boolean.assert_false("valid_cbor_byte", &decoded.invalid);
    let full_assertion = iologic.assert_all("cbor_decoder_assert", &[add_assertion, not_invalid]);

    let (circuit, stats, symbols) =
        compile_compiler::top::compile(&arena, fc, full_assertion, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);

    // Test valid byte values (e.g. 0..23 which are valid CBOR integers)
    for v in 0..=23 {
        let _concrete_given = ConcreteGiven { v };
        let mut inputs = compile_eval::initial_inputs(fr);
        for k in 0..8 {
            let bit = (v >> k) & 1;
            inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
        }

        let eval_res =
            compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id).unwrap();
        eval_res.assert_all_passed();
    }

    // Test invalid byte values (e.g. 0x1f / 31 which has invalid count in CBOR)
    {
        let invalid_v = 31u8; // count = 31 is invalid CBOR byte
        let mut inputs = compile_eval::initial_inputs(fr);
        for k in 0..8 {
            let bit = (invalid_v >> k) & 1;
            inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
        }
        let eval_res =
            compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, field_id).unwrap();
        eval_res.assert_any_failed_at("cbor_decoder_assert/valid_cbor_byte");
    }
}

#[test]
fn test_compile_cbor_decoder() {
    let fc_p256 = P256Field::new();
    let fr_p256 = runtime_algebra::p256::P256Field::new();
    test_compile_cbor_decoder_for_field::<4, _, _>(
        &fc_p256,
        &fr_p256,
        "cbor_decoder_p256",
        FieldID::P256,
    );

    let fc_gf2 = Gf2_128Field::new();
    let fr_gf2 = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_compile_cbor_decoder_for_field::<2, _, _>(
        &fc_gf2,
        &fr_gf2,
        "cbor_decoder_gf2",
        FieldID::Gf2_128,
    );
}
