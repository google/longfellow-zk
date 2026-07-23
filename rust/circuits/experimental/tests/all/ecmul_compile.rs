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

use circuits_experimental::ecmul::{
    concrete::{self, ConcreteGiven},
    EcmulCircuit,
};
use compile_algebra::{
    field::{CompilePrimeField, SupportsNatConversions},
    p256::P256Field,
    secp256r1::Secp256r1,
};
use compile_compiler::CompilerArena;
use compile_eval::FieldID;
use core_algebra::{Nat, SerializableField};
use runtime_algebra::field::RuntimeField;

use super::testvec;

fn test_compile_ecmul_generic<
    const W: usize,
    FC: CompilePrimeField + SupportsNatConversions<W> + SerializableField,
    FR: RuntimeField<W> + SupportsNatConversions<W> + SerializableField,
    CC: core_algebra::Curve<W, F = FC>,
    CR: core_algebra::Curve<W, F = FR>,
>(
    curve_c: &CC,
    curve_r: &CR,
    fc: &FC,
    fr: &FR,
) {
    use compile_compiler::CompilerLogic;

    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, fc);

    let n = 256;
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let circuit = EcmulCircuit::new(&iologic, curve_c, n);
    let given = circuits_experimental::ecmul::allocate_given(&iologic, n, &mut pos);
    let derived = circuits_experimental::ecmul::allocate_derived(&iologic, n, &mut pos);

    let assertion = circuit.assert_scalar_mul(&given, &derived);

    let (compiled_circuit, stats, symbols) =
        compile_compiler::top::compile(&arena, fc, assertion, 0, 0);

    compile_compiler::top::dump_stats("ecmul", &compiled_circuit, &stats);

    assert_eq!(stats.ninput, 1030);
    assert_eq!(stats.npublic_input, 0);
    assert_eq!(stats.noutput, 765);
    assert_eq!(stats.nlayers, 4);
    assert_eq!(stats.nwires, 11503);
    assert_eq!(stats.nterms, 22480);

    // Verify compiled circuit evaluation
    let tv = testvec::get_testvec();
    let ax_val = fr.reduce_nat(&FR::N::from_bytes_le(&tv.ax.to_bytes_le()));
    let ay_val = fr.reduce_nat(&FR::N::from_bytes_le(&tv.ay.to_bytes_le()));
    let bx_val = fr.reduce_nat(&FR::N::from_bytes_le(&tv.bx.to_bytes_le()));
    let by_val = fr.reduce_nat(&FR::N::from_bytes_le(&tv.by.to_bytes_le()));

    let concrete_given = ConcreteGiven {
        exp: tv.exp.clone(),
        a: (ax_val.clone(), ay_val.clone()),
        b: (bx_val, by_val),
    };
    let concrete_derived = concrete::derived(curve_r, n, &concrete_given, fr);

    let mut inputs = compile_eval::initial_inputs(fr);
    concrete_given.push_elements(n, fr, |e| inputs.push(e));
    concrete_derived.push_elements(|e| inputs.push(e));

    compile_eval::eval_circuit_fc(fc, fr, &compiled_circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_ecmul() {
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let curve_c = Secp256r1::new(&fc);
    let curve_r = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    test_compile_ecmul_generic::<4, _, _, _, _>(&curve_c, &curve_r, &fc, &fr);
}
