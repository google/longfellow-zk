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
use compile_logic::{
    eval::{EvalContext, EvalLogic, EvalWire},
    Logic,
};

fn run_test_eval_logic<F: CompileField + SupportsU64Conversions>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(field, &tracker);
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

    let assert_z = l.assert0("assert_z", &z);
    assert!(tracker.is_ok(&assert_z.items));
}

#[test]
fn test_eval_logic() {
    let field = Gf2_128Field::new();
    run_test_eval_logic(&field);
}

fn run_test_eval_assert0_panic<F: CompileField>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(field, &tracker);
    let o = l.one();
    let assert_o = l.assert0("assert_o", &o);
    assert!(tracker.is_err(&assert_o.items));
}

#[test]
fn test_eval_assert0_panic() {
    let field = Gf2_128Field::new();
    run_test_eval_assert0_panic(&field);
}

fn run_test_eval_with_assertions_propagation<F: CompileField>(field: &F) {
    type L<'a, F> = EvalLogic<'a, F>;
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(field, &tracker);

    let one = l.one();
    let zero = l.zero();

    // 1. A valid assertion (zero == zero) should propagate Ok
    let ok_assertion = l.assert0("assert_zero", &zero);
    let val_ok = l.with_assertions(ok_assertion, &one);
    assert!(tracker.is_ok(&val_ok.assertions));

    // 2. An invalid attached assertion marks the wire invalid, while its
    // provenance remains distinct from computation errors.
    let err_assertion = l.assert0("assert_one", &one);
    let val_err = l.with_assertions(err_assertion, &one);
    assert!(tracker.is_err(&val_err.assertions));

    // 3. Test exact assertion propagation through all logic operations.
    let assert_propagated = |wire: EvalWire<F>| {
        assert!(tracker.is_err(&wire.assertions));
        let result = l.assert0("consumer", &wire);
        tracker.assert_any_failed_at("assert_one", &result.items);
    };

    assert_propagated(l.precious(&val_err));
    assert_propagated(l.neg(&val_err));

    assert_propagated(l.add(&val_err, &zero));
    assert_propagated(l.add(&zero, &val_err));

    assert_propagated(l.sub(&val_err, &zero));
    assert_propagated(l.sub(&zero, &val_err));

    assert_propagated(l.mul(&val_err, &zero));
    assert_propagated(l.mul(&zero, &val_err));

    assert_propagated(l.mulk(&field.one(), &val_err));

    assert_propagated(l.quadratic(&field.one(), &val_err, &zero));
    assert_propagated(l.quadratic(&field.one(), &zero, &val_err));

    assert_propagated(l.sum(&[zero.clone(), val_err.clone(), zero.clone()]));

    assert_propagated(l.with_assertions(l.ok(), &val_err));

    let newly_attached = l.with_assertions(l.assert0("check_one", &one), &zero);
    let result = l.assert0("consumer", &newly_attached);
    assert_eq!(tracker.failed_paths(&result.items), vec!["check_one"]);
    assert_eq!(tracker.passed_paths(&result.items), vec!["consumer"]);
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
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(&field, &tracker);

    let z = l.zero();
    let o = l.one();

    let leaf1 = l.assert0("check_zero1", &z);
    let leaf2 = l.assert0("check_non_zero", &z);
    let leaf3 = l.assert0("check_one", &o);

    let inner = l.assert_all("inner_block", &[leaf1, leaf2]);
    let outer = l.assert_all("outer_block", &[inner, leaf3]);

    let path_strings = tracker.all_paths(&outer.items);
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
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(&field, &tracker);
    let z = l.zero();

    let mapi_assertion = l.assert_mapi("loop_check", 0..3, |_i| l.assert0("check", &z));
    let mapi_paths = tracker.all_paths(&mapi_assertion.items);
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
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = L::new(&field, &tracker);
    let z = l.zero();
    let o = l.one();

    let pass_a = l.assert0("good_zero", &z);
    let fail_a = l.assert0("bad_zero", &o);

    let combined = l.assert_all("top", &[pass_a, fail_a]);

    assert!(tracker.is_err(&combined.items));
    assert_eq!(tracker.passed_paths(&combined.items), vec!["top/good_zero"]);
    assert_eq!(tracker.failed_paths(&combined.items), vec!["top/bad_zero"]);

    tracker.assert_any_failed_at("top/bad_zero", &combined.items);
    tracker.assert_all_passed_at("top/good_zero", &combined.items);
}

#[test]
fn test_eval_attached_assertion_keeps_exact_scoped_path() {
    let field = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = EvalLogic::new(&field, &tracker);
    let computed = l.one();
    let witness = l.zero();

    let sliced = l.slicing("slice", &witness, &computed);
    let consumer = l.assert0("consumer", &sliced);
    let root = l.assert_all("root", &[consumer]);

    assert_eq!(
        tracker.all_paths(&root.items),
        vec!["root/slice", "root/consumer"]
    );
    assert_eq!(tracker.failed_paths(&root.items), vec!["root/slice"]);
    assert_eq!(tracker.passed_paths(&root.items), vec!["root/consumer"]);
}

#[test]
fn test_eval_shared_attached_assertion_is_reported_once() {
    let field = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = EvalLogic::new(&field, &tracker);
    let bad = l.assert0("attached", &l.one());
    let wire = l.with_assertions(bad, &l.zero());

    let diamond = l.add(&wire, &wire);
    let result = l.assert0("consumer", &diamond);

    assert_eq!(tracker.failed_paths(&result.items), vec!["attached"]);
    assert_eq!(tracker.passed_paths(&result.items), vec!["consumer"]);
}

#[test]
fn test_eval_distinct_assertions_with_the_same_path_remain_distinct() {
    let field = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = EvalLogic::new(&field, &tracker);
    let left = l.with_assertions(l.assert0("same", &l.one()), &l.zero());
    let right = l.with_assertions(l.assert0("same", &l.one()), &l.zero());

    let result = l.assert0("consumer", &l.add(&left, &right));

    assert_eq!(tracker.failed_paths(&result.items), vec!["same", "same"]);
    assert_eq!(tracker.passed_paths(&result.items), vec!["consumer"]);
}

#[test]
fn test_eval_union_reports_failure_from_any_alias() {
    let field = Gf2_128Field::new();
    let tracker = compile_logic::scope::AssertionScope::new();
    let l = EvalLogic::new(&field, &tracker);
    let passed = l.assert0("passed", &l.zero());
    let failed = l.assert0("failed", &l.one());
    let passed_id = *passed.items.keys().next().unwrap();
    let failed_id = *failed.items.keys().next().unwrap();
    tracker.union(passed_id, failed_id);

    let mut fates = passed.items.clone();
    fates.extend(failed.items);

    assert!(tracker.failed_paths(&fates).iter().all(|p| p == "passed" || p == "failed"));
    assert!(!tracker.is_ok(&fates));
}

#[test]
fn test_eval_context_owns_tracker() {
    let field = Gf2_128Field::new();
    let context = EvalContext::new(&field);
    let result = context.run(|logic| logic.assert0("zero", &logic.zero()));
    result.assert_all_passed();
}
