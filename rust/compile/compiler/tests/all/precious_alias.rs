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

use compile_algebra::{gf2_128::Gf2_128Field, p256::P256Field};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::eval_circuit_fc;
use compile_logic::{Logic, LogicIO};
use core_algebra::AlgebraicField;
use core_proto::FieldID;
use runtime_algebra::{gf2_128::Gf2_128RuntimeField, p256::P256Field as RuntimeP256Field};

#[test]
fn test_precious_alias_in_prime_field() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let logic = CompilerLogic::new(&arena, &f);
    let x = logic.input(1);
    let square = logic.mul(&x, &x);
    let sum = logic.add(&square, &x);
    let precious_sum = logic.precious(&sum);
    let expression = logic.add(&sum, &precious_sum);
    let assertion = logic.assert0("alias", &expression);

    let (circuit, _, symbols) =
        compile_compiler::top::compile(&arena, &f, assertion, logic.tracker, 1, 0);
    let runtime_f = RuntimeP256Field::new();

    eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.zero()],
        FieldID::P256,
    )
    .unwrap()
    .assert_all_passed();

    let failed = eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.one()],
        FieldID::P256,
    )
    .unwrap();
    assert!(failed.is_err());
}

#[test]
fn test_precious_alias_cancels_in_binary_field() {
    let f = Gf2_128Field::new();
    let arena = CompilerArena::new();
    let logic = CompilerLogic::new(&arena, &f);
    let x = logic.input(1);
    let square = logic.mul(&x, &x);
    let sum = logic.add(&square, &x);
    let precious_sum = logic.precious(&sum);
    let expression = logic.add(&sum, &precious_sum);

    // The alias assertion is identically zero in characteristic two.
    // Keep a nontrivial assertion so the resulting circuit has a layer.
    let alias = logic.assert0("alias", &expression);
    let guard = logic.assert0("guard", &square);
    let assertions = logic.assert_all("root", &[alias, guard]);

    let (circuit, _, symbols) =
        compile_compiler::top::compile(&arena, &f, assertions, logic.tracker, 1, 0);
    let runtime_f = Gf2_128RuntimeField::new();

    eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.zero()],
        FieldID::Gf2_128,
    )
    .unwrap()
    .assert_all_passed();

    let failed = eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.one()],
        FieldID::Gf2_128,
    )
    .unwrap();
    assert!(failed.is_err());
}
