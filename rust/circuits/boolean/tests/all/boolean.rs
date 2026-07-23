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

use circuits_boolean::Boolean;
use compile_algebra::{field::SupportsU64Conversions, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::LogicIO;

#[test]
fn test_compile_boolean() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let boolean = Boolean::new(&iologic);

    let a = iologic.input(1);
    let b = iologic.input(2);

    let ab = boolean.of_eltw(a);
    let bb = boolean.of_eltw(b);

    let x = boolean.xorb(&ab, &bb);
    let assertion = boolean.assert_true("assert_x", &x);

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, &f, assertion, 1, 0);

    compile_compiler::top::dump_stats("boolean_xor_compile", &circuit, &stats);
}

use circuits_boolean::Bitw;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field};
use compile_logic::{eval::EvalLogic, Eltw, Logic};
use test_helpers::{compare_bool as compare, new_f65537_field, LPrime};

use super::test_helpers;

type LBinary<'a> = EvalLogic<'a, Gf2_128Field>;

fn unary<L: Logic, F, RF>(boolean: &Boolean<L>, a: bool, ref_f: RF, f: F)
where
    F: Fn(&Bitw<L>) -> Bitw<L>,
    RF: Fn(bool) -> bool,
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    compare(boolean, ref_f(a), &f(&boolean.konst(a)));
}

fn binary<L: Logic, F, RF>(boolean: &Boolean<L>, a: bool, b: bool, ref_f: RF, f: F)
where
    F: Fn(&Bitw<L>, &Bitw<L>) -> Bitw<L>,
    RF: Fn(bool, bool) -> bool,
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    compare(
        boolean,
        ref_f(a, b),
        &f(&boolean.konst(a), &boolean.konst(b)),
    );
}

fn ternary<L: Logic, F, RF>(boolean: &Boolean<L>, a: bool, b: bool, c: bool, ref_f: RF, f: F)
where
    F: Fn(&Bitw<L>, &Bitw<L>, &Bitw<L>) -> Bitw<L>,
    RF: Fn(bool, bool, bool) -> bool,
    Eltw<L>: PartialEq + std::fmt::Debug,
{
    compare(
        boolean,
        ref_f(a, b, c),
        &f(&boolean.konst(a), &boolean.konst(b), &boolean.konst(c)),
    );
}

fn test_boolean_for_logic<F: CompileField>(logic: &EvalLogic<'_, F>) {
    let boolean = Boolean::new(logic);
    let bools = [false, true];
    for &a in &bools {
        unary(&boolean, a, |x| !x, |x| boolean.notb(x));
        for &b in &bools {
            binary(&boolean, a, b, |x, y| x && y, |x, y| boolean.andb(x, y));
            binary(
                &boolean,
                a,
                b,
                |x, y| x && y,
                |x, y| boolean.tree_andb(x, y),
            );
            binary(&boolean, a, b, |x, y| x || y, |x, y| boolean.orb(x, y));
            binary(&boolean, a, b, |x, y| x || y, |x, y| boolean.tree_orb(x, y));
            if !(a && b) {
                binary(
                    &boolean,
                    a,
                    b,
                    |x, y| x || y,
                    |x, y| boolean.or_assuming_at_most_one_true(x, y),
                );
            }
            binary(
                &boolean,
                a,
                b,
                |x, y| if x { !y } else { y },
                |x, y| boolean.xorb(x, y),
            );
            binary(&boolean, a, b, |x, y| x == y, |x, y| boolean.eqb(x, y));
            binary(&boolean, a, b, |x, y| !x & y, |x, y| boolean.ltb(x, y));
            binary(
                &boolean,
                a,
                b,
                |x, y| if x { y } else { true },
                |x, y| boolean.impliesb(x, y),
            );
            for &c in &bools {
                ternary(
                    &boolean,
                    a,
                    b,
                    c,
                    |selector, x, y| if selector { x } else { y },
                    |x, y, z| boolean.muxb(x, y, z),
                );
                ternary(
                    &boolean,
                    a,
                    b,
                    c,
                    |x, y, z| (if x { !y } else { y }) != z,
                    |x, y, z| boolean.xor3(x, y, z),
                );
                ternary(
                    &boolean,
                    a,
                    b,
                    c,
                    |x, y, z| (i32::from(x) + i32::from(y) + i32::from(z)) >= 2,
                    |x, y, z| boolean.maj(x, y, z),
                );
            }
        }
    }
}

#[test]
fn test_boolean() {
    let field = new_f65537_field();
    let l_prime = LPrime::new(&field);
    test_boolean_for_logic(&l_prime);
    let field_bin = Gf2_128Field::new();
    let l_bin = LBinary::new(&field_bin);
    test_boolean_for_logic(&l_bin);
}

#[test]
fn test_muxe_binary() {
    let field = Gf2_128Field::new();
    let l = LBinary::new(&field);
    run_test_muxe(&l);
}

fn run_test_muxe<F: CompileField + SupportsU64Conversions>(logic: &EvalLogic<'_, F>) {
    let boolean = Boolean::new(logic);
    let field = logic.field();
    let bools = [false, true];
    for &a in &bools {
        let b = field.u64_to_element(3_u64);
        let c = field.u64_to_element(4_u64);
        let want = if a { b.clone() } else { c.clone() };
        let got = boolean.muxe(&boolean.konst(a), &logic.konst(&b), &logic.konst(&c));
        assert_eq!(got.value, want);
    }
}

#[test]
fn test_muxe() {
    let field = new_f65537_field();
    let l = LPrime::new(&field);
    run_test_muxe(&l);
}

fn run_test_of_eltw<F: CompileField + SupportsU64Conversions>(logic: &EvalLogic<'_, F>) {
    let boolean = Boolean::new(logic);
    let field = logic.field();

    // Value 0: should pass
    let zero = logic.konst(&field.zero());
    let bit_zero = boolean.of_eltw(zero);
    compare(&boolean, false, &bit_zero);
    assert!(boolean.as_eltw(&bit_zero).error.is_ok());

    // Value 1: should pass
    let one = logic.konst(&field.one());
    let bit_one = boolean.of_eltw(one);
    compare(&boolean, true, &bit_one);
    assert!(boolean.as_eltw(&bit_one).error.is_ok());

    // Value 2: should record an error on evaluation
    let two = logic.konst(&field.u64_to_element(2_u64));
    let bit_two = boolean.of_eltw(two);
    assert!(boolean.as_eltw(&bit_two).error.is_err());
}

#[test]
fn test_of_eltw() {
    let field = new_f65537_field();
    let l = LPrime::new(&field);
    run_test_of_eltw(&l);
}

fn run_test_one_hot_muxes<F: CompileField + SupportsU64Conversions>(logic: &EvalLogic<'_, F>) {
    let boolean = Boolean::new(logic);
    let field = logic.field();
    let zero = logic.konst(&field.zero());
    let one = logic.konst(&field.one());

    let (t, fa) = (boolean.trueb(), boolean.falseb());
    let (t_elt, fa_elt) = (one.clone(), zero.clone());

    // 2 inputs
    let cases2 = [
        (&[t.clone(), fa.clone()][..], t_elt.clone()),
        (&[fa.clone(), t.clone()][..], fa_elt.clone()),
    ];
    let inputs2 = [one.clone(), zero.clone()];
    for (sel, expected) in cases2 {
        let got = boolean.one_hot_muxe(sel, &|idx| inputs2[idx].clone());
        assert_eq!(got, expected);
    }

    // 3 inputs
    let v2 = logic.konst(&field.u64_to_element(2_u64));
    let cases3 = [
        (&[t.clone(), fa.clone(), fa.clone()][..], t_elt.clone()),
        (&[fa.clone(), t.clone(), fa.clone()][..], fa_elt.clone()),
        (&[fa.clone(), fa.clone(), t.clone()][..], v2.clone()),
    ];
    let inputs3 = [one.clone(), zero.clone(), v2.clone()];
    for (sel, expected) in cases3 {
        let got = boolean.one_hot_muxe(sel, &|idx| inputs3[idx].clone());
        assert_eq!(got, expected);
    }
}

#[test]
fn test_one_hot_muxes() {
    let field = new_f65537_field();
    let l = LPrime::new(&field);
    run_test_one_hot_muxes(&l);
}

#[test]
fn test_precious() {
    let field = new_f65537_field();
    let l = LPrime::new(&field);
    let boolean = Boolean::new(&l);

    let t = boolean.trueb();
    let f = boolean.falseb();

    compare(&boolean, true, &boolean.precious(&t));
    compare(&boolean, false, &boolean.precious(&f));
}

#[test]
fn test_assertions() {
    let field = new_f65537_field();
    let l = LPrime::new(&field);
    let boolean = Boolean::new(&l);

    let t = boolean.trueb();
    let f = boolean.falseb();

    // assert_true
    assert!(boolean.assert_true("t_true", &t).is_ok());
    assert!(boolean.assert_true("f_true", &f).is_err());

    // assert_false
    assert!(boolean.assert_false("f_false", &f).is_ok());
    assert!(boolean.assert_false("t_false", &t).is_err());

    // assert_eq
    assert!(boolean.assert_eq("tt_eq", &t, &t).is_ok());
    assert!(boolean.assert_eq("ff_eq", &f, &f).is_ok());
    assert!(boolean.assert_eq("tf_eq", &t, &f).is_err());
}
