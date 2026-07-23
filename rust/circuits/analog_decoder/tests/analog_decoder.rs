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

use circuits_analog_decoder::AnalogDecoder;
use circuits_boolean::Boolean;
use compile_algebra::{
    field::{CompileField, SupportsNatConversions, SupportsU64Conversions},
    p256::P256Field,
};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::{eval::EvalLogic, Logic, LogicIO};

#[test]
fn test_compile_analog_decoder() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let ad = AnalogDecoder::new(&iologic);

    let n = 5;
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let x = iologic.next(&mut pos);

    let decoder = ad.unary(n);
    let (exactly_one, _decoded) = decoder.decode(&x);
    let assertion = exactly_one;

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, &f, assertion, 0, 0);
    compile_compiler::top::dump_stats("analog_decoder_compile", &circuit, &stats);
}

#[test]
fn test_compile_analog_decoder_binary() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let ad = AnalogDecoder::new(&iologic);
    let boolean = Boolean::new(&iologic);

    let width = 3;
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let x = iologic.next(&mut pos);

    let decoder = ad.binary(width);
    let decoded = decoder.decode(&x);

    let assertion = boolean.assert_true("assert_decoded0", &decoded[0]);

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, &f, assertion, 0, 0);

    compile_compiler::top::dump_stats("analog_decoder_binary_compile", &circuit, &stats);
}

fn test_analog_decoder_unary_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
>(
    f: &F,
) {
    let iologic = EvalLogic::new(f);
    let ad = AnalogDecoder::new(&iologic);
    let boolean = Boolean::new(&iologic);

    let n = 15;
    let decoder = ad.unary(n);

    for i in 0..n {
        let pt = ad.unary_point(n, i);
        let pt_wire = iologic.konst(&pt);
        let (assertion, decoded) = decoder.decode(&pt_wire);
        assert!(
            assertion.is_ok(),
            "Assertion failed for valid point i = {i}"
        );

        assert_eq!(decoded.len(), n);
        for (k, dec_wire) in decoded.iter().enumerate() {
            let want = i == k;
            let got_elt = boolean.as_eltw(dec_wire);
            let want_val = if want { f.one() } else { f.zero() };
            assert_eq!(
                want_val, got_elt.value,
                "Mismatch at input i = {i}, check index k = {k}"
            );
        }
    }

    // Test invalid point
    let invalid_pt = f.addf(&ad.unary_point(n, 0), &f.one());
    let invalid_pt_wire = iologic.konst(&invalid_pt);
    let (assertion, _decoded) = decoder.decode(&invalid_pt_wire);
    assert!(assertion.is_err(), "Assertion succeeded for invalid point!");
}

fn test_analog_decoder_binary_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
>(
    f: &F,
) {
    let iologic = EvalLogic::new(f);
    let ad = AnalogDecoder::new(&iologic);
    let boolean = Boolean::new(&iologic);

    let width = 4;
    let n = 1 << width;
    let decoder = ad.binary(width);

    for i in 0..n {
        let pt = ad.binary_point(width, i);
        let pt_wire = iologic.konst(&pt);
        let got = decoder.decode(&pt_wire);

        assert_eq!(got.len(), width);
        for (k, got_wire) in got.iter().enumerate() {
            let want = ((i >> k) & 1) == 1;
            let got_elt = boolean.as_eltw(got_wire);
            let want_val = if want { f.one() } else { f.zero() };
            assert_eq!(
                want_val, got_elt.value,
                "Mismatch at input i = {i}, check bit index k = {k}"
            );
        }
    }
}

struct F1009Tag;
type F1009Field = compile_algebra::fp::FpField<F1009Tag>;

fn new_f1009_field() -> F1009Field {
    compile_algebra::fp::FpField::new_field(compile_algebra::fp::FpParameters {
        length_bytes: 2,
        modulo: compile_algebra::CompileNat::<4>::from(1009),
        id: 1009,
    })
}

fn test_analog_decoder_exhaustive_field_1009_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
) {
    let iologic = EvalLogic::new(f);
    let ad = AnalogDecoder::new(&iologic);
    let boolean = Boolean::new(&iologic);

    // Test all unary lengths from 2 up to 10
    for n in 2..=10 {
        let decoder = ad.unary(n);

        // Collect all valid points for this unary decoder
        let mut valid_points = Vec::with_capacity(n);
        for i in 0..n {
            valid_points.push(ad.unary_point(n, i));
        }

        // Exhaustively check all 1009 possible elements in the field.
        for val in 0..1009 {
            let pt = f.u64_to_element((val) as u64);
            let pt_wire = iologic.konst(&pt);
            let (assertion, decoded) = decoder.decode(&pt_wire);

            if let Some(i) = valid_points.iter().position(|vp| vp == &pt) {
                // It is a valid point: assertion must succeed
                assert!(
                    assertion.is_ok(),
                    "Unary(n={n}) assertion failed for valid point val = {val} (index {i})"
                );
                // Result must be one-hot with 1 at index i
                for (k, dec_wire) in decoded.iter().enumerate() {
                    let got_elt = boolean.as_eltw(dec_wire);
                    let want_val = if k == i { f.one() } else { f.zero() };
                    assert_eq!(
                        want_val, got_elt.value,
                        "Unary(n={n}) value mismatch for valid point val = {val}, check index {k}"
                    );
                }
            } else {
                // It is an invalid point: assertion must fail
                assert!(
                    assertion.is_err(),
                    "Unary(n={n}) assertion succeeded for invalid point val = {val}"
                );
            }
        }
    }

    // Test all binary widths up to 5
    for width in 1..=5 {
        let n = 1 << width;
        let decoder = ad.binary(width);

        // Collect all valid points for this binary decoder
        let mut valid_points = Vec::with_capacity(n);
        for i in 0..n {
            valid_points.push(ad.binary_point(width, i));
        }

        // Exhaustively check all 1009 possible elements in the field.
        for val in 0..1009 {
            let pt = f.u64_to_element((val) as u64);
            let pt_wire = iologic.konst(&pt);
            let got = decoder.decode(&pt_wire);

            // Collect internal bit assertions for the decoded bits
            let mut bit_assertions = Ok(());
            for bit in &got {
                let eltw = boolean.as_eltw(bit);
                bit_assertions = bit_assertions.and(eltw.error);
            }

            if let Some(i) = valid_points.iter().position(|vp| vp == &pt) {
                // It is a valid point: bit assertions must succeed
                assert!(
                    bit_assertions.is_ok(),
                    "Binary(w={width}) assertions failed for valid point val = {val} (index {i})"
                );
                // Result must match bit representation of index i
                assert_eq!(got.len(), width);
                for (k, got_wire) in got.iter().enumerate() {
                    let want = ((i >> k) & 1) == 1;
                    let got_elt = boolean.as_eltw(got_wire);
                    let want_val = if want { f.one() } else { f.zero() };
                    assert_eq!(
                        want_val, got_elt.value,
                        "Binary(w={width}) value mismatch at valid point val = {val}, bit index {k}"
                    );
                }
            } else {
                // It is an invalid point: at least one bit assertion must fail
                // (since the values will not be 0 or 1)
                assert!(
                    bit_assertions.is_err(),
                    "Binary(w={width}) assertions succeeded for invalid point val = {val}"
                );
            }
        }
    }
}

#[test]
fn test_analog_decoder_exhaustive_field_1009() {
    let f = new_f1009_field();
    test_analog_decoder_exhaustive_field_1009_generic::<4, _>(&f);
}

#[test]
fn test_analog_decoder_evaluation() {
    let f = P256Field::new();
    test_analog_decoder_unary_generic::<4, _>(&f);
    test_analog_decoder_binary_generic::<4, _>(&f);
}
