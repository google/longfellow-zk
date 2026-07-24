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

use circuits_bitvec::{Bitvec, BitvecIO, BitvecLogic};
use circuits_boolean::Boolean;
use compile_algebra::p256::P256Field;

#[test]
fn test_compile_bitvec() {
    let f = P256Field::new();
    let (circuit, stats, _symbols) = compile_compiler::compile(&f, |iologic| {
        let bv = BitvecLogic::new(&iologic);
        let bitvec_io = BitvecIO::new(&bv);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let a: Bitvec<_, 8> = bitvec_io.next(&mut pos);
        let b: Bitvec<_, 8> = bitvec_io.next(&mut pos);

        let (sum, _carry) = bv.unchecked_add(&a, &b);
        (bv.assert_false("sum_zero", &sum), iologic.tracker, 1, 0)
    });
    compile_compiler::dump_stats("bitvec_add_compile", &circuit, &stats);
}

#[test]
fn test_compile_bitvec_leq() {
    use compile_algebra::p256::P256Field;
    use compile_eval::FieldID;
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let (circuit, _stats, symbols) = compile_compiler::compile(&fc, |iologic| {
        let bv = BitvecLogic::new(&iologic);
        let bitvec_io = BitvecIO::new(&bv);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let a: Bitvec<_, 64> = bitvec_io.next(&mut pos);
        let b: Bitvec<_, 64> = bitvec_io.next(&mut pos);

        let boolean = Boolean::new(&iologic);
        let leq = bv.leq(&a, &b);
        (boolean.assert_true("leq_true", &leq), iologic.tracker, 1, 0)
    });

    // Let's test a = 65, b = 119
    let mut inputs = compile_eval::initial_inputs(&fr);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 65, 64, &mut inputs);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 119, 64, &mut inputs);

    compile_eval::eval_circuit_fc(&fc, &fr, &circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_bitvec_is_zero() {
    use compile_algebra::p256::P256Field;
    use compile_eval::FieldID;
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let (circuit, _stats, symbols) = compile_compiler::compile(&fc, |iologic| {
        let bv = BitvecLogic::new(&iologic);
        let bitvec_io = BitvecIO::new(&bv);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let a: Bitvec<_, 8> = bitvec_io.next(&mut pos);

        let boolean = Boolean::new(&iologic);
        let is_zero = bv.is_zero(&a);
        (
            boolean.assert_true("zero_true", &is_zero),
            iologic.tracker,
            1,
            0,
        )
    });

    // Test a = 0 (should pass)
    let mut inputs = compile_eval::initial_inputs(&fr);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 0, 8, &mut inputs);
    compile_eval::eval_circuit_fc(&fc, &fr, &circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();

    // Test a = 5 (should fail)
    let mut inputs_fail = compile_eval::initial_inputs(&fr);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 5, 8, &mut inputs_fail);
    assert!(compile_eval::eval_circuit_fc(
        &fc,
        &fr,
        &circuit,
        &symbols,
        &inputs_fail,
        FieldID::P256
    )
    .unwrap()
    .result
    .is_err());
}

#[test]
fn test_compile_bitvec_lt() {
    use compile_algebra::p256::P256Field;
    use compile_eval::FieldID;
    let fc = P256Field::new();
    let fr = runtime_algebra::p256::P256Field::new();
    let (circuit, _stats, symbols) = compile_compiler::compile(&fc, |iologic| {
        let bv = BitvecLogic::new(&iologic);
        let bitvec_io = BitvecIO::new(&bv);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let a: Bitvec<_, 64> = bitvec_io.next(&mut pos);
        let b: Bitvec<_, 64> = bitvec_io.next(&mut pos);

        let boolean = Boolean::new(&iologic);
        (
            boolean.assert_true("lt_true", &bv.lt(&a, &b)),
            iologic.tracker,
            1,
            0,
        )
    });

    // Test a = 65, b = 66 (should pass since 65 < 66)
    let mut inputs = compile_eval::initial_inputs(&fr);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 65, 64, &mut inputs);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 66, 64, &mut inputs);
    compile_eval::eval_circuit_fc(&fc, &fr, &circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();

    // Test a = 65, b = 65 (should fail since 65 < 65 is false)
    let mut inputs_fail = compile_eval::initial_inputs(&fr);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 65, 64, &mut inputs_fail);
    circuits_bitvec::concrete::push_bitvec_u64(&fr, 65, 64, &mut inputs_fail);
    assert!(compile_eval::eval_circuit_fc(
        &fc,
        &fr,
        &circuit,
        &symbols,
        &inputs_fail,
        FieldID::P256
    )
    .unwrap()
    .result
    .is_err());
}

use circuits_boolean::Bitw;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field};
use compile_logic::{eval::EvalLogic, Eltw, Logic};
use test_helpers::{compare_bitw as compare, new_f65537_field, LPrime};

use super::test_helpers;

type LBinary<'a> = EvalLogic<'a, Gf2_128Field>;

const BIT_WIDTH: usize = 8;

fn bitw<L: Logic>(boolean: &Boolean<L>, x: i64, i: usize) -> Bitw<L> {
    let bit_val = ((x >> i) & 1) == 1;
    boolean.konst(bit_val)
}

fn mkbv<L: Logic>(bv: &BitvecLogic<L>, boolean: &Boolean<L>, x: i64) -> Bitvec<L, BIT_WIDTH> {
    bv.from_fn(|i| bitw(boolean, x, i))
}

fn bvcompare<L: Logic, const K: usize>(
    boolean: &Boolean<L>,
    want: &Bitvec<L, K>,
    got: &Bitvec<L, K>,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    for i in 0..K {
        compare(boolean, want.bit(i), got.bit(i));
    }
}

fn arithmetic<L: Logic>(
    bv: &BitvecLogic<L>,
    boolean: &Boolean<L>,
    op: &dyn Fn(&Bitvec<L, BIT_WIDTH>, &Bitvec<L, BIT_WIDTH>) -> (Bitvec<L, BIT_WIDTH>, Bitw<L>),
    ref_op: &dyn Fn(i64, i64) -> i64,
    a: i64,
    b: i64,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let c = ref_op(a, b);
    let want_arr: Vec<Bitw<L>> = (0..=BIT_WIDTH).map(|i| bitw(boolean, c, i)).collect();
    let aa = mkbv(bv, boolean, a);
    let bb = mkbv(bv, boolean, b);
    let (got, carry) = op(&aa, &bb);

    for (i, want_bit) in want_arr.iter().enumerate().take(BIT_WIDTH) {
        compare(boolean, want_bit, got.bit(i));
    }
    compare(boolean, &want_arr[BIT_WIDTH], &carry);
}

fn unary<L: Logic>(
    bv: &BitvecLogic<L>,
    boolean: &Boolean<L>,
    op: &dyn Fn(&Bitvec<L, BIT_WIDTH>) -> Bitvec<L, BIT_WIDTH>,
    ref_op: &dyn Fn(i64) -> i64,
    a: i64,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let want = mkbv(bv, boolean, ref_op(a));
    let aa = mkbv(bv, boolean, a);
    let got = op(&aa);
    bvcompare(boolean, &want, &got);
}

fn binary<L: Logic>(
    bv: &BitvecLogic<L>,
    boolean: &Boolean<L>,
    op: &dyn Fn(&Bitvec<L, BIT_WIDTH>, &Bitvec<L, BIT_WIDTH>) -> Bitvec<L, BIT_WIDTH>,
    ref_op: &dyn Fn(i64, i64) -> i64,
    a: i64,
    b: i64,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let want = mkbv(bv, boolean, ref_op(a, b));
    let aa = mkbv(bv, boolean, a);
    let bb = mkbv(bv, boolean, b);
    let got = op(&aa, &bb);
    bvcompare(boolean, &want, &got);
}

fn relation<L: Logic>(
    bv: &BitvecLogic<L>,
    boolean: &Boolean<L>,
    op: &dyn Fn(&Bitvec<L, BIT_WIDTH>, &Bitvec<L, BIT_WIDTH>) -> Bitw<L>,
    ref_op: &dyn Fn(i64, i64) -> bool,
    a: i64,
    b: i64,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let want = boolean.konst(ref_op(a, b));
    let aa = mkbv(bv, boolean, a);
    let bb = mkbv(bv, boolean, b);
    let got = op(&aa, &bb);
    compare(boolean, &want, &got);
}

fn reduction<L: Logic>(
    bv: &BitvecLogic<L>,
    boolean: &Boolean<L>,
    op: &dyn Fn(&Bitvec<L, BIT_WIDTH>) -> Bitw<L>,
    ref_op: &dyn Fn(i64) -> bool,
    a: i64,
) where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let want = boolean.konst(ref_op(a));
    let aa = mkbv(bv, boolean, a);
    let got = op(&aa);
    compare(boolean, &want, &got);
}

fn test_bitvec_for_logic<F: CompileField>(logic: &EvalLogic<F>) {
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);
    let n = 1 << BIT_WIDTH;
    for a in 0..n {
        unary(&bv, &boolean, &|x| bv.notb(x), &|x| !x, a);
        reduction(
            &bv,
            &boolean,
            &|x| bv.all(x, &|e| boolean.notb(e)),
            &|x| x == 0,
            a,
        );
        reduction(
            &bv,
            &boolean,
            &|x| bv.any(x, &|e| boolean.b(e)),
            &|x| x != 0,
            a,
        );

        for b in 0..n {
            arithmetic(
                &bv,
                &boolean,
                &|x, y| {
                    let (sum, carry) = bv.unchecked_add(x, y);
                    (sum, carry)
                },
                &|x, y| x + y,
                a,
                b,
            );
            arithmetic(
                &bv,
                &boolean,
                &|x, y| {
                    let (diff, borrow) = bv.unchecked_sub(x, y);
                    (diff, borrow)
                },
                &|x, y| x - y,
                a,
                b,
            );

            binary(&bv, &boolean, &|x, y| bv.andb(x, y), &|x, y| x & y, a, b);
            binary(&bv, &boolean, &|x, y| bv.orb(x, y), &|x, y| x | y, a, b);
            binary(&bv, &boolean, &|x, y| bv.xorb(x, y), &|x, y| x ^ y, a, b);

            relation(&bv, &boolean, &|x, y| bv.eqb(x, y), &|x, y| x == y, a, b);
            relation(&bv, &boolean, &|x, y| bv.lt(x, y), &|x, y| x < y, a, b);
            relation(&bv, &boolean, &|x, y| bv.leq(x, y), &|x, y| x <= y, a, b);
            relation(&bv, &boolean, &|x, y| bv.gt(x, y), &|x, y| x > y, a, b);
            relation(&bv, &boolean, &|x, y| bv.geq(x, y), &|x, y| x >= y, a, b);
        }
    }
}

#[test]
fn test_bitvec() {
    let field = new_f65537_field();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l_prime = LPrime::new(&field, &tracker);
    test_bitvec_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    let l_bin = LBinary::new(&field_bin, &tracker_bin);
    test_bitvec_for_logic(&l_bin);
}

fn test_assert_wrapping_add_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);
    let w = 4;
    let n = 1 << w;
    for a in 0..n {
        for b in 0..n {
            for c in 0..n {
                let want = (a + b) & (n - 1);
                let aa = bv.from_fn::<4, _>(|i| bitw(&boolean, a, i));
                let bb = bv.from_fn::<4, _>(|i| bitw(&boolean, b, i));
                let cc = bv.from_fn::<4, _>(|i| bitw(&boolean, c, i));

                let assertion = bv.assert_wrapping_add(&cc, &aa, &bb);

                if c == want {
                    assert!(assertion.is_ok());
                } else {
                    assert!(assertion.is_err());
                }
            }
        }
    }
}

fn test_assert_add_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);
    let w = 4;
    let n = 1 << w;
    for a in 0..n {
        for b in 0..n {
            for c in 0..n {
                let want = a + b;
                let aa = bv.from_fn::<4, _>(|i| bitw(&boolean, a, i));
                let bb = bv.from_fn::<4, _>(|i| bitw(&boolean, b, i));
                let cc = bv.from_fn::<4, _>(|i| bitw(&boolean, c, i));

                let assertion = bv.assert_checked_add(&cc, &aa, &bb);

                if want < n && c == want {
                    assert!(assertion.is_ok());
                } else {
                    assert!(assertion.is_err());
                }
            }
        }
    }
}

#[test]
fn test_assert_add() {
    let field = new_f65537_field();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l_prime = LPrime::new(&field, &tracker);
    test_assert_wrapping_add_for_logic(&l_prime);
    test_assert_add_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    let l_bin = LBinary::new(&field_bin, &tracker_bin);
    test_assert_wrapping_add_for_logic(&l_bin);
    test_assert_add_for_logic(&l_bin);
}

fn test_is_zero_for_logic<L: Logic>(logic: &L)
where
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);

    let zero = mkbv(&bv, &boolean, 0);
    let five = mkbv(&bv, &boolean, 5);

    let is_zero_zero = bv.is_zero(&zero);
    let is_zero_five = bv.is_zero(&five);

    compare(&boolean, &is_zero_zero, &boolean.trueb());
    compare(&boolean, &is_zero_five, &boolean.falseb());
}

#[test]
fn test_is_zero() {
    let field = new_f65537_field();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l_prime = LPrime::new(&field, &tracker);
    test_is_zero_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    let l_bin = LBinary::new(&field_bin, &tracker_bin);
    test_is_zero_for_logic(&l_bin);
}

fn test_assert_neq_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);

    let five = mkbv(&bv, &boolean, 5);
    let six = mkbv(&bv, &boolean, 6);
    let five_dup = mkbv(&bv, &boolean, 5);

    let assertion1 = bv.assert_neq("five_neq_six", &five, &six);
    assert!(assertion1.is_ok());

    let assertion2 = bv.assert_neq("five_neq_five", &five, &five_dup);
    assert!(assertion2.is_err());
}

#[test]
fn test_assert_neq() {
    let field = new_f65537_field();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l_prime = LPrime::new(&field, &tracker);
    test_assert_neq_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    let l_bin = LBinary::new(&field_bin, &tracker_bin);
    test_assert_neq_for_logic(&l_bin);
}

fn test_checked_add_sub_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let bv = BitvecLogic::new(logic);
    let boolean = Boolean::new(logic);

    let five = mkbv(&bv, &boolean, 5);
    let six = mkbv(&bv, &boolean, 6);

    // 5 + 6 = 11 (no overflow/carry)
    let (sum, add_assert) = bv.checked_add(&five, &six);
    assert!(add_assert.is_ok());
    bvcompare(&boolean, &mkbv(&bv, &boolean, 11), &sum);

    // 6 - 5 = 1 (no underflow/borrow)
    let (diff, sub_assert) = bv.checked_sub(&six, &five);
    assert!(sub_assert.is_ok());
    bvcompare(&boolean, &mkbv(&bv, &boolean, 1), &diff);

    // 5 - 6 underflows (borrow is true)
    let (_diff, underflow_assert) = bv.checked_sub(&five, &six);
    assert!(underflow_assert.is_err());

    // 255 + 1 overflows (width is 8, so 255 + 1 carries)
    let max_val = mkbv(&bv, &boolean, 255);
    let one = mkbv(&bv, &boolean, 1);
    let (_sum, overflow_assert) = bv.checked_add(&max_val, &one);
    assert!(overflow_assert.is_err());
}

#[test]
fn test_checked_add_sub() {
    let field = new_f65537_field();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l_prime = LPrime::new(&field, &tracker);
    test_checked_add_sub_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let tracker_bin = compile_logic::scope::AssertionScope::new();
    let l_bin = LBinary::new(&field_bin, &tracker_bin);
    test_checked_add_sub_for_logic(&l_bin);
}
