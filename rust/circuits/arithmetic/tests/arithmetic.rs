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

use circuits_arithmetic::Arithmetic;
use circuits_boolean::{Bitw, Boolean, BooleanIO};
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field};
use compile_logic::{eval::EvalLogic, Eltw, Logic};
use core_algebra::SerializableField;

fn compile_and_dump_add<F: CompileField + SerializableField>(f: &F, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(f, |iologic| {
        let boolean = Boolean::new(&iologic);
        let boolean_io = BooleanIO::new(&iologic);
        let arith = Arithmetic::new(&iologic);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mut a = Vec::with_capacity(64);
        for _ in 0..64 {
            a.push(boolean_io.next(&mut pos));
        }
        let mut b = Vec::with_capacity(64);
        for _ in 0..64 {
            b.push(boolean_io.next(&mut pos));
        }

        let (sum, carry) = arith.unchecked_add(&a, &b);
        let a1 = arith.assert_false("sum_zero", &sum);
        let a2 = boolean.assert_false("no_carry", &carry);
        (
            iologic.assert_all("test_add", &[a1, a2]),
            iologic.tracker,
            1,
            0,
        )
    });
    compile_compiler::dump_stats(name, &circuit, &stats);
}

fn compile_and_dump_sub<F: CompileField + SerializableField>(f: &F, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(f, |iologic| {
        let boolean = Boolean::new(&iologic);
        let boolean_io = BooleanIO::new(&iologic);
        let arith = Arithmetic::new(&iologic);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mut a = Vec::with_capacity(64);
        for _ in 0..64 {
            a.push(boolean_io.next(&mut pos));
        }
        let mut b = Vec::with_capacity(64);
        for _ in 0..64 {
            b.push(boolean_io.next(&mut pos));
        }

        let (diff, carry) = arith.unchecked_sub(&a, &b);
        let a1 = arith.assert_false("diff_zero", &diff);
        let a2 = boolean.assert_false("no_carry", &carry);
        (
            iologic.assert_all("test_sub", &[a1, a2]),
            iologic.tracker,
            1,
            0,
        )
    });
    compile_compiler::dump_stats(name, &circuit, &stats);
}

fn compile_and_dump_lt<F: CompileField + SerializableField>(f: &F, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(f, |iologic| {
        let boolean = Boolean::new(&iologic);
        let boolean_io = BooleanIO::new(&iologic);
        let arith = Arithmetic::new(&iologic);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mut a = Vec::with_capacity(256);
        for _ in 0..256 {
            a.push(boolean_io.next(&mut pos));
        }
        let mut b = Vec::with_capacity(256);
        for _ in 0..256 {
            b.push(boolean_io.next(&mut pos));
        }

        let res = arith.lt(&a, &b);
        (
            boolean.assert_false("lt_false", &res),
            iologic.tracker,
            1,
            0,
        )
    });
    compile_compiler::dump_stats(name, &circuit, &stats);
}

fn compile_and_dump_leq<F: CompileField + SerializableField>(f: &F, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(f, |iologic| {
        let boolean = Boolean::new(&iologic);
        let boolean_io = BooleanIO::new(&iologic);
        let arith = Arithmetic::new(&iologic);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mut a = Vec::with_capacity(256);
        for _ in 0..256 {
            a.push(boolean_io.next(&mut pos));
        }
        let mut b = Vec::with_capacity(256);
        for _ in 0..256 {
            b.push(boolean_io.next(&mut pos));
        }

        let res = arith.leq(&a, &b);
        (
            boolean.assert_false("leq_false", &res),
            iologic.tracker,
            1,
            0,
        )
    });
    compile_compiler::dump_stats(name, &circuit, &stats);
}

fn compile_and_dump_eq<F: CompileField + SerializableField>(f: &F, name: &str) {
    let (circuit, stats, _symbols) = compile_compiler::compile(f, |iologic| {
        let boolean = Boolean::new(&iologic);
        let boolean_io = BooleanIO::new(&iologic);
        let arith = Arithmetic::new(&iologic);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mut a = Vec::with_capacity(256);
        for _ in 0..256 {
            a.push(boolean_io.next(&mut pos));
        }
        let mut b = Vec::with_capacity(256);
        for _ in 0..256 {
            b.push(boolean_io.next(&mut pos));
        }

        let res = arith.eqb(&a, &b);
        (
            boolean.assert_false("eq_false", &res),
            iologic.tracker,
            1,
            0,
        )
    });
    compile_compiler::dump_stats(name, &circuit, &stats);
}

#[test]
fn test_compile_arithmetic() {
    let p256 = P256Field::new();
    let gf2 = Gf2_128Field::new();

    compile_and_dump_add(&p256, "adder_64_p256");
    compile_and_dump_add(&gf2, "adder_64_gf2_128");

    compile_and_dump_sub(&p256, "sub_64_p256");
    compile_and_dump_sub(&gf2, "sub_64_gf2_128");

    compile_and_dump_lt(&p256, "lt_256_p256");
    compile_and_dump_lt(&gf2, "lt_256_gf2_128");

    compile_and_dump_leq(&p256, "leq_256_p256");
    compile_and_dump_leq(&gf2, "leq_256_gf2_128");

    compile_and_dump_eq(&p256, "eq_256_p256");
    compile_and_dump_eq(&gf2, "eq_256_gf2_128");
}

fn of_u64<L: Logic>(boolean: &Boolean<L>, n: usize, z: u64) -> Vec<Bitw<L>> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let bit_val = ((z >> i) & 1) == 1;
        v.push(boolean.konst(bit_val));
    }
    v
}

fn assert_eq_bits<L: Logic>(boolean: &Boolean<L>, want: &[Bitw<L>], got: &[Bitw<L>])
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    assert_eq!(want.len(), got.len());
    for i in 0..want.len() {
        let w = boolean.as_eltw(&want[i]);
        let g = boolean.as_eltw(&got[i]);
        assert_eq!(w, g, "Mismatch at bit index {i}");
    }
}

fn test_add_eval_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let a = of_u64(&boolean, 8, 5);
    let b = of_u64(&boolean, 8, 7);

    // 5 + 7 = 12
    let (sum, carry) = arith.unchecked_add(&a, &b);
    let expected_sum = of_u64(&boolean, 8, 12);

    assert_eq_bits(&boolean, &expected_sum, &sum);
    assert_eq!(boolean.as_eltw(&carry), logic.zero());
}

fn test_sub_eval_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let a = of_u64(&boolean, 8, 20);
    let b = of_u64(&boolean, 8, 8);

    // 20 - 8 = 12
    let (diff, carry) = arith.unchecked_sub(&a, &b);
    let expected_diff = of_u64(&boolean, 8, 12);

    assert_eq_bits(&boolean, &expected_diff, &diff);
    assert_eq!(boolean.as_eltw(&carry), logic.zero());
}

fn test_lt_eval_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let a = of_u64(&boolean, 8, 5);
    let b = of_u64(&boolean, 8, 7);

    // 5 < 7 is true
    let res_true = arith.lt(&a, &b);
    assert_eq!(boolean.as_eltw(&res_true), logic.one());

    // 7 < 5 is false
    let res_false = arith.lt(&b, &a);
    assert_eq!(boolean.as_eltw(&res_false), logic.zero());
}

fn test_leq_eval_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let a = of_u64(&boolean, 8, 5);
    let b = of_u64(&boolean, 8, 7);

    // 5 <= 7 is true
    let res_true1 = arith.leq(&a, &b);
    assert_eq!(boolean.as_eltw(&res_true1), logic.one());

    // 7 <= 7 is true
    let res_true2 = arith.leq(&b, &b);
    assert_eq!(boolean.as_eltw(&res_true2), logic.one());

    // 7 <= 5 is false
    let res_false = arith.leq(&b, &a);
    assert_eq!(boolean.as_eltw(&res_false), logic.zero());
}

fn test_eq_eval_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let a = of_u64(&boolean, 8, 5);
    let b = of_u64(&boolean, 8, 7);

    // 5 == 5 is true
    let res_true = arith.eqb(&a, &a);
    assert_eq!(boolean.as_eltw(&res_true), logic.one());

    // 5 == 7 is false
    let res_false = arith.eqb(&a, &b);
    assert_eq!(boolean.as_eltw(&res_false), logic.zero());
}

fn test_exactly_one_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let boolean = Boolean::new(logic);
    let arithmetic = Arithmetic::new(logic);
    for len in 1..=6 {
        let n_combinations = 1 << len;
        for mask in 0..n_combinations {
            let inputs: Vec<_> = util::array::init(len, |i| boolean.konst(((mask >> i) & 1) == 1));
            let popcount = (0..len).filter(|i| ((mask >> i) & 1) == 1).count();

            let assertion = arithmetic.assert_exactly_one(&inputs);

            if popcount == 1 {
                assert!(assertion.is_ok());
            } else {
                assert!(assertion.is_err());
            }
        }
    }
}

fn test_empty_vectors_relations_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let boolean = Boolean::new(logic);
    let arith = Arithmetic::new(logic);

    let empty: &[Bitw<L>] = &[];

    let lt_res = arith.lt(empty, empty);
    let leq_res = arith.leq(empty, empty);
    let gt_res = arith.gt(empty, empty);
    let geq_res = arith.geq(empty, empty);
    let eq_res = arith.eqb(empty, empty);

    assert_eq!(boolean.as_eltw(&lt_res), boolean.as_eltw(&boolean.falseb()));
    assert_eq!(boolean.as_eltw(&leq_res), boolean.as_eltw(&boolean.trueb()));
    assert_eq!(boolean.as_eltw(&gt_res), boolean.as_eltw(&boolean.falseb()));
    assert_eq!(boolean.as_eltw(&geq_res), boolean.as_eltw(&boolean.trueb()));
    assert_eq!(boolean.as_eltw(&eq_res), boolean.as_eltw(&boolean.trueb()));
}

#[test]
fn test_arithmetic_evaluation() {
    let f_prime = P256Field::new();
    let tracker_prime = compile_logic::scope::AssertionScope::new();
    type LPrime<'a> = EvalLogic<'a, P256Field>;
    let l_prime = LPrime::new(&f_prime, &tracker_prime);
    test_add_eval_for_logic(&l_prime);
    test_sub_eval_for_logic(&l_prime);
    test_lt_eval_for_logic(&l_prime);
    test_leq_eval_for_logic(&l_prime);
    test_eq_eval_for_logic(&l_prime);
    test_exactly_one_for_logic(&l_prime);
    test_empty_vectors_relations_for_logic(&l_prime);

    let f_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    type LBin<'a> = EvalLogic<'a, Gf2_128Field>;
    let l_binary = LBin::new(&f_bin, &tracker_bin);
    test_add_eval_for_logic(&l_binary);
    test_sub_eval_for_logic(&l_binary);
    test_lt_eval_for_logic(&l_binary);
    test_leq_eval_for_logic(&l_binary);
    test_eq_eval_for_logic(&l_binary);
    test_exactly_one_for_logic(&l_binary);
    test_empty_vectors_relations_for_logic(&l_binary);
}

#[test]
fn test_as_eltw_no_overflow_prime() {
    let f = P256Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let bits = vec![boolean.falseb(); 255];
    arith.as_eltw_field(&bits);
}

#[test]
#[should_panic(expected = "Bitvector length 256 exceeds field capacity 255")]
fn test_as_eltw_overflow_prime() {
    let f = P256Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let bits = vec![boolean.falseb(); 256];
    arith.as_eltw_field(&bits);
}

#[test]
fn test_as_eltw_no_overflow_binary() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let serialized_size_bits = vec![boolean.falseb(); 128];
    arith.as_eltw_field(&serialized_size_bits);
}

#[test]
#[should_panic(expected = "Bitvector length 129 exceeds field capacity 128")]
fn test_as_eltw_overflow_binary() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let bits = vec![boolean.falseb(); 129];
    arith.as_eltw_field(&bits);
}

#[test]
#[should_panic(expected = "unchecked_add: slice lengths must match")]
fn test_unchecked_add_length_mismatch() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let a = vec![boolean.falseb(); 4];
    let b = vec![boolean.falseb(); 5];
    let _ = arith.unchecked_add(&a, &b);
}

#[test]
#[should_panic(expected = "fold2: slice lengths must match")]
fn test_fold2_empty_a_nonempty_b_length_mismatch() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let a = vec![];
    let b = vec![boolean.falseb(); 5];
    arith.fold2(
        &a,
        &b,
        &|x, y| boolean.andb(&x, &y),
        &|x, y| boolean.eqb(x, y),
        boolean.trueb(),
    );
}

#[test]
#[should_panic(expected = "eqb: slice lengths must match")]
fn test_eqb_length_mismatch() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let a = vec![boolean.falseb(); 2];
    let b = vec![boolean.falseb(); 3];
    arith.eqb(&a, &b);
}

#[test]
#[should_panic(expected = "muxb: condition and iftrue lengths must match")]
fn test_muxb_length_mismatch() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let logic = EvalLogic::new(&f, &tracker);
    let arith = Arithmetic::new(&logic);
    let boolean = Boolean::new(&logic);
    let cond = vec![boolean.falseb(); 2];
    let iftrue = vec![boolean.falseb(); 3];
    let iffalse = vec![boolean.falseb(); 2];
    arith.muxb(&cond, &iftrue, &iffalse);
}
