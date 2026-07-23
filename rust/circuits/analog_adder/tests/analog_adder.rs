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

use circuits_analog_adder::{AnalogAdder, FieldWrappingSum};
use circuits_bitvec::{Bitvec, BitvecIO, BitvecLogic};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::{eval::EvalLogic, Logic};
use core_algebra::SerializableField;

fn test_compile_for_field<F: CompileField + FieldWrappingSum + SerializableField>(
    f: &F,
    name: &str,
) {
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, f);
    let bv = BitvecLogic::new(&iologic);
    let bitvec_io = BitvecIO::new(&bv);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let addends: Vec<Bitvec<_, 32>> = (0..7).map(|_| bitvec_io.next(&mut pos)).collect();
    let expected: Bitvec<_, 32> = bitvec_io.next(&mut pos);

    let adder = AnalogAdder::new(&iologic);
    let assertion = f.assert_wrapping_sum(&adder, &expected, &[&addends]);
    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, f, assertion, 0, 0);

    compile_compiler::top::dump_stats(name, &circuit, &stats);
}

#[test]
fn test_analog_adder_compilation() {
    let p256 = P256Field::new();
    test_compile_for_field(&p256, "analog_adder_7_addends_p256");
    let gf2 = Gf2_128Field::new();
    test_compile_for_field(&gf2, "analog_adder_7_addends_gf2_128");
}

fn test_assert_sum_correct_for_logic<F: CompileField + FieldWrappingSum>(logic: &EvalLogic<F>) {
    let bv = BitvecLogic::new(logic);
    let a: Bitvec<_, 32> = bv.of_u64(10);
    let b: Bitvec<_, 32> = bv.of_u64(20);
    let c: Bitvec<_, 32> = bv.of_u64(30);
    let expected: Bitvec<_, 32> = bv.of_u64(60);

    let adder = AnalogAdder::new(logic);
    let assertion = logic
        .field()
        .assert_wrapping_sum(&adder, &expected, &[&[a, b, c]]);
    assert!(assertion.is_ok());
}

fn test_assert_sum_incorrect_for_logic<F: CompileField + FieldWrappingSum>(logic: &EvalLogic<F>) {
    let bv = BitvecLogic::new(logic);
    let a: Bitvec<_, 32> = bv.of_u64(10);
    let b: Bitvec<_, 32> = bv.of_u64(20);
    let c: Bitvec<_, 32> = bv.of_u64(30);
    let expected: Bitvec<_, 32> = bv.of_u64(61); // Incorrect sum

    let adder = AnalogAdder::new(logic);
    let assertion = logic
        .field()
        .assert_wrapping_sum(&adder, &expected, &[&[a, b, c]]);
    assert!(assertion.is_err());
}

fn test_assert_sum_7_addends_for_logic<F: CompileField + FieldWrappingSum>(logic: &EvalLogic<F>) {
    let bv = BitvecLogic::new(logic);

    // Test all 7 carry wrap-around cases (i from 0 to 6)
    for i in 0..7 {
        let mut addends = Vec::with_capacity(7);
        for _ in 0..i {
            // i terms of 2^32 - 100
            addends.push(bv.of_u64((1u64 << 32) - 100));
        }
        addends.push(bv.of_u64(1000));
        for _ in 0..(6 - i) {
            addends.push(bv.of_u64(200));
        }

        let expected: Bitvec<_, 32> = bv.of_u64(2200 - 300 * (i as u64));

        let adder = AnalogAdder::new(logic);
        let assertion = logic
            .field()
            .assert_wrapping_sum(&adder, &expected, &[&addends]);
        assert!(assertion.is_ok());
    }
}

fn test_assert_sum_7_addends_fail_for_logic<F: CompileField + FieldWrappingSum>(
    logic: &EvalLogic<F>,
) {
    let bv = BitvecLogic::new(logic);

    // Test all 7 carry wrap-around cases with incorrect expected sum
    for i in 0..7 {
        let mut addends = Vec::with_capacity(7);
        for _ in 0..i {
            addends.push(bv.of_u64((1u64 << 32) - 100));
        }
        addends.push(bv.of_u64(1000));
        for _ in 0..(6 - i) {
            addends.push(bv.of_u64(200));
        }

        // Incorrect expected sum (2201 - 300i instead of 2200 - 300i)
        let expected: Bitvec<_, 32> = bv.of_u64(2201 - 300 * (i as u64));

        let adder = AnalogAdder::new(logic);
        let assertion = logic
            .field()
            .assert_wrapping_sum(&adder, &expected, &[&addends]);
        assert!(assertion.is_err());
    }
}

#[test]
fn test_analog_adder_evaluation() {
    let f_prime = P256Field::new();
    type LPrime<'a> = EvalLogic<'a, P256Field>;
    let l_prime = LPrime::new(&f_prime);
    test_assert_sum_correct_for_logic(&l_prime);
    test_assert_sum_incorrect_for_logic(&l_prime);
    test_assert_sum_7_addends_for_logic(&l_prime);
    test_assert_sum_7_addends_fail_for_logic(&l_prime);

    let f_bin = Gf2_128Field::new();
    type LBin<'a> = EvalLogic<'a, Gf2_128Field>;
    let l_binary = LBin::new(&f_bin);
    test_assert_sum_correct_for_logic(&l_binary);
    test_assert_sum_incorrect_for_logic(&l_binary);
    test_assert_sum_7_addends_for_logic(&l_binary);
    test_assert_sum_7_addends_fail_for_logic(&l_binary);
}
