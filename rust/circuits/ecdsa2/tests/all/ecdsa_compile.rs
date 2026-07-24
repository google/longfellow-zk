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

use circuits_ecdsa2::{derived, given, EcdsaCircuit};
use compile_algebra::{
    field::{CompilePrimeField, SupportsNatConversions},
    p256::P256Field,
    secp256r1::Secp256r1,
    Curve,
};
use compile_compiler::{compile, dump_stats};
use compile_eval::FieldID;
use compile_logic::K_FIRST_WIRE_POSITION;
use core_algebra::{Nat, SerializableField};
use runtime_algebra::field::RuntimeField;

use super::test_support;

fn parse_hex<const W: usize, N: Nat<W>>(s: &str) -> N {
    let s_clean = s.strip_prefix("0x").unwrap_or(s);
    let mut bytes = [0u8; 32];
    let s_padded = format!("{s_clean:0>64}");
    for (i, byte) in bytes.iter_mut().enumerate() {
        let high = char_to_digit(s_padded.as_bytes()[2 * i]);
        let low = char_to_digit(s_padded.as_bytes()[2 * i + 1]);
        *byte = (high << 4) | low;
    }
    bytes.reverse();
    N::from_bytes_le(&bytes)
}

fn char_to_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}

fn make_inputs<const W: usize, FR: RuntimeField<W> + SerializableField>(
    given: &circuits_ecdsa2::concrete::ConcreteGiven<FR>,
    derived: &circuits_ecdsa2::concrete::ConcreteDerived<FR>,
    fr: &FR,
) -> Vec<FR::E> {
    let mut inputs = compile_eval::initial_inputs(fr);
    inputs.push(given.pkxy.0.clone());
    inputs.push(given.pkxy.1.clone());
    inputs.push(given.e.clone());
    inputs.push(given.rxy.0.clone());
    inputs.push(given.rxy.1.clone());
    for elt in &given.ers {
        inputs.push(elt.clone());
    }
    inputs.push(derived.pkxinv.clone());
    inputs.push(derived.rxinv.clone());
    inputs.push(derived.nmsinv.clone());
    inputs.push(derived.yinv.clone());
    inputs.push(derived.slicing.g_pk.0.clone());
    inputs.push(derived.slicing.g_pk.1.clone());
    inputs.push(derived.slicing.g_r.0.clone());
    inputs.push(derived.slicing.g_r.1.clone());
    inputs.push(derived.slicing.pk_r.0.clone());
    inputs.push(derived.slicing.pk_r.1.clone());
    inputs.push(derived.slicing.g_pk_r.0.clone());
    inputs.push(derived.slicing.g_pk_r.1.clone());
    for pt in &derived.slicing.round {
        inputs.push(pt.0.clone());
        inputs.push(pt.1.clone());
        inputs.push(pt.2.clone());
    }
    inputs
}

fn test_compile_ecdsa_generic<
    const W: usize,
    FC: CompilePrimeField
        + SupportsNatConversions<W>
        + SerializableField
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU64Conversions,
    FR: RuntimeField<W> + SerializableField + SupportsNatConversions<W> + core_algebra::HasLookupPoints,
    Fn: core_algebra::AlgebraicField + SupportsNatConversions<W, N = FR::N>,
    CC: Curve<W, F = FC, N = FC::N>,
    CR: Curve<W, F = FR, N = FR::N>,
>(
    curve_c: &CC,
    fc: &FC,
    curve_r: &CR,
    fr: &FR,
    fn_field: &Fn,
) {
    let pkx_str = "0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaaf686c8f9ff5e7c6368d9c";
    let pky_str = "0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b2fe38e6f58626767f9e75";
    let e_str = "0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
    let r_str = "0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671";
    let s_str = "0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd40";

    let pkx_val = parse_hex::<W, FR::N>(pkx_str);
    let pky_val = parse_hex::<W, FR::N>(pky_str);
    let e_val = parse_hex::<W, FR::N>(e_str);
    let r_val = parse_hex::<W, FR::N>(r_str);
    let s_val = parse_hex::<W, FR::N>(s_str);

    let pkxy_val_r = (fr.reduce_nat(&pkx_val), fr.reduce_nat(&pky_val));
    let concrete_given_r = given(curve_r, &pkxy_val_r, &e_val, &r_val, &s_val, fr, fn_field);
    let concrete_derived_r = derived(curve_r, &pkxy_val_r, &e_val, &r_val, &s_val, fr, fn_field);

    let (circuit, stats, symbols) = compile(fc, |iologic| {
        let mut pos = K_FIRST_WIRE_POSITION;

        let ecdsa = EcdsaCircuit::new(&iologic, curve_c);
        let circuit_given = circuits_ecdsa2::allocate_given_wires(&iologic, &mut pos);
        let circuit_derived = circuits_ecdsa2::allocate_derived_wires(&iologic, &mut pos);

        (
            ecdsa.assert_signature(&circuit_given, &circuit_derived),
            1,
            0,
        )
    });

    dump_stats("ecdsa2", &circuit, &stats);

    let inputs = make_inputs(&concrete_given_r, &concrete_derived_r, fr);

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_ecdsa() {
    let fc = P256Field::new();
    let curve_c = Secp256r1::new(&fc);
    let fr = runtime_algebra::p256::P256Field::new();
    let curve_r = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    let fn_field = runtime_algebra::Q256Field::new();
    test_compile_ecdsa_generic::<4, _, _, _, _, _>(&curve_c, &fc, &curve_r, &fr, &fn_field);
}

fn test_compile_ecdsa_signature_tampering_generic<
    const W: usize,
    FC: CompilePrimeField
        + SupportsNatConversions<W>
        + SerializableField
        + core_algebra::HasLookupPoints
        + core_algebra::SupportsU64Conversions,
    FR: RuntimeField<W>
        + SerializableField
        + SupportsNatConversions<W>
        + core_algebra::HasLookupPoints
        + Clone
        + 'static,
    FnR: core_algebra::AlgebraicField + SupportsNatConversions<W, N = FR::N>,
    CC: Curve<W, F = FC, N = FC::N>,
    CR: Curve<W, F = FR, N = FR::N>,
>(
    curve_c: &CC,
    fc: &FC,
    curve_r: &CR,
    fr: &FR,
    fn_field: &FnR,
) where
    FR::E: Clone,
{
    let d = CR::N::from_u64(123456789u64);
    let k = CR::N::from_u64(987654321u64);
    let e = CR::N::from_u64(555555555u64); // Message hash

    let (concrete_given, concrete_derived) =
        test_support::sign_and_generate_given_derived::<W, _, _, _>(
            curve_r, fr, fn_field, &d, &k, &e,
        );

    let (circuit, _stats, symbols) = compile(fc, |iologic| {
        let mut pos = K_FIRST_WIRE_POSITION;

        let ecdsa = EcdsaCircuit::new(&iologic, curve_c);
        let circuit_given = circuits_ecdsa2::allocate_given_wires(&iologic, &mut pos);
        let circuit_derived = circuits_ecdsa2::allocate_derived_wires(&iologic, &mut pos);

        (
            ecdsa.assert_signature(&circuit_given, &circuit_derived),
            1,
            0,
        )
    });

    // Verify valid inputs pass
    {
        let inputs = make_inputs(&concrete_given, &concrete_derived, fr);
        let eval_res =
            compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, FieldID::P256)
                .unwrap();
        eval_res.assert_all_passed();
    }

    let corruptors = test_support::all_ecdsa_corruptors::<W, _>(fr);

    for c in corruptors {
        let mut g = concrete_given.clone();
        let mut cd = concrete_derived.clone();
        (c.corrupt)(&mut g, &mut cd);
        let inputs = make_inputs(&g, &cd, fr);
        let eval_res =
            compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, FieldID::P256)
                .unwrap();
        assert!(
            eval_res.is_err(),
            "Corruptor '{}' failed to cause circuit evaluation error",
            c.name
        );
        let failed = eval_res.failed_paths();
        assert!(
            failed.iter().any(|path| path == c.expected_path),
            "Corruptor '{}' expected exact compiled failure path '{}', actual failures: {failed:?}",
            c.name,
            c.expected_path
        );
    }
}

#[test]
fn test_compile_ecdsa_signature_tampering() {
    let fc = P256Field::new();
    let curve_c = Secp256r1::new(&fc);
    let fr = runtime_algebra::p256::P256Field::new();
    let curve_r = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    let fn_field = runtime_algebra::Q256Field::new();
    test_compile_ecdsa_signature_tampering_generic::<4, _, _, _, _, _>(
        &curve_c, &fc, &curve_r, &fr, &fn_field,
    );
}
