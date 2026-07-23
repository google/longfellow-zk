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

use compile_algebra::{
    field::{CompileField, SupportsU64Conversions},
    gf2_128::Gf2_128Field,
};
use compile_logic::{eval::EvalLogic, Logic};

fn run_test_eval_logic<F: CompileField + SupportsU64Conversions>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(field);
    let z = l.zero();
    let o = l.one();
    assert_eq!(z.value, field.zero());
    assert_eq!(o.value, field.one());

    let two = l.add(&o, &o);
    assert_eq!(l.to_stringw_debug(&two), "Gf2_128(0)");

    let three = l.konst(&field.u64_to_element(3));
    assert_eq!(three.value, field.u64_to_element(3));

    let three_field = l.konst(&field.u64_to_element(3));
    let expected = format!("{:?}", field.u64_to_element(3));
    assert_eq!(l.to_stringw_debug(&three_field), expected);

    let neg_one = field.mone();
    assert_eq!(neg_one, field.one());

    assert!(l.assert0("assert_z", &z).is_ok());
}

#[test]
fn test_eval_logic() {
    let field = Gf2_128Field::new();
    run_test_eval_logic(&field);
}

fn run_test_eval_assert0_panic<F: CompileField>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(field);
    let o = l.one();
    assert!(l.assert0("assert_o", &o).is_err());
}

#[test]
fn test_eval_assert0_panic() {
    let field = Gf2_128Field::new();
    run_test_eval_assert0_panic(&field);
}

fn run_test_eval_with_assertions_propagation<F: CompileField>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(field);

    let one = l.one();
    let zero = l.zero();

    // 1. A valid assertion (zero == zero) should propagate Ok
    let ok_assertion = l.assert0("assert_zero", &zero);
    let val_ok = l.with_assertions(ok_assertion, &one);
    assert!(val_ok.error.is_ok());

    // 2. An invalid assertion (one == zero) should propagate Err
    let err_assertion = l.assert0("assert_one", &one);
    let val_err = l.with_assertions(err_assertion, &one);
    assert!(val_err.error.is_err());

    // 3. Test propagation through all logic operations
    // precious
    assert!(l.precious(&val_err).error.is_err());

    // neg
    assert!(l.neg(&val_err).error.is_err());

    // add
    assert!(l.add(&val_err, &zero).error.is_err());
    assert!(l.add(&zero, &val_err).error.is_err());

    // sub
    assert!(l.sub(&val_err, &zero).error.is_err());
    assert!(l.sub(&zero, &val_err).error.is_err());

    // mul
    assert!(l.mul(&val_err, &zero).error.is_err());
    assert!(l.mul(&zero, &val_err).error.is_err());

    // mulk
    assert!(l.mulk(&field.one(), &val_err).error.is_err());

    // quadratic
    assert!(l.quadratic(&field.one(), &val_err, &zero).error.is_err());
    assert!(l.quadratic(&field.one(), &zero, &val_err).error.is_err());

    // sum
    assert!(l
        .sum(&[zero.clone(), val_err.clone(), zero.clone()])
        .error
        .is_err());

    // with_assertions (propagation of existing error inside x)
    assert!(l.with_assertions(l.ok(), &val_err).error.is_err());

    // with_assertions (propagation of new error into valid x)
    assert!(l
        .with_assertions(l.assert0("check_one", &one), &zero)
        .error
        .is_err());
}

#[test]
fn test_eval_with_assertions_propagation() {
    let field = Gf2_128Field::new();
    run_test_eval_with_assertions_propagation(&field);
}

#[test]
fn test_eval_assertion_dag_paths() {
    let field = Gf2_128Field::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(&field);

    let z = l.zero();
    let o = l.one();

    let leaf1 = l.assert0("check_zero1", &z);
    let leaf2 = l.assert0("check_non_zero", &z);
    let leaf3 = l.assert0("check_one", &o);

    let inner = l.assert_all("inner_block", &[leaf1, leaf2]);
    let outer = l.assert_all("outer_block", &[inner, leaf3]);

    let path_strings = outer.all_paths();
    assert_eq!(
        path_strings,
        vec![
            "outer_block/inner_block/check_zero1",
            "outer_block/inner_block/check_non_zero",
            "outer_block/check_one"
        ]
    );
}

#[test]
fn test_eval_assert_mapi() {
    let field = Gf2_128Field::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(&field);
    let z = l.zero();

    let mapi_assertion = l.assert_mapi("loop_check", 0..3, |_i| l.assert0("check", &z));
    let mapi_paths = mapi_assertion.all_paths();
    assert_eq!(
        mapi_paths,
        vec![
            "loop_check/loop_check.0/check",
            "loop_check/loop_check.1/check",
            "loop_check/loop_check.2/check"
        ]
    );
}

#[test]
fn test_eval_assertion_status_tracking() {
    let field = Gf2_128Field::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(&field);
    let z = l.zero();
    let o = l.one();

    let pass_a = l.assert0("good_zero", &z);
    let fail_a = l.assert0("bad_zero", &o);

    let combined = l.assert_all("top", &[pass_a, fail_a]);

    assert!(combined.is_err());
    assert_eq!(combined.passed_paths(), vec!["top/good_zero"]);
    assert_eq!(combined.failed_paths(), vec!["top/bad_zero"]);

    combined.assert_any_failed_at("top/bad_zero");
    combined.assert_all_passed_at("top/good_zero");
}
