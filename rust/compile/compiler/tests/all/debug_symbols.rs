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

use compile_algebra::p256::P256Field;
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::eval_circuit_fc;
use compile_logic::{Logic, LogicIO};
use core_algebra::AlgebraicField;
use core_proto::FieldID;
use runtime_algebra::p256::P256Field as RuntimeP256Field;

#[test]
fn test_compiled_circuit_debug_symbols() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);

    let w1 = l.input(1);
    let w2 = l.input(2);

    let q1 = l.mul(&w1, &w1);
    let q2 = l.mul(&w2, &w2);

    let assert1 = l.assert0("check_w1", &q1);
    let assert2 = l.assert0("check_w2", &q2);

    let block_a = l.assert_all("block_a", &[assert1]);
    let block_b = l.assert_all("block_b", &[assert2]);
    let root = l.assert_all("root", &[block_a, block_b]);

    let (circuit, _info, symbols) = compile_compiler::top::compile(&arena, &f, root, 1, 0);

    assert_eq!(symbols.symbols.len(), 2);
    let paths: Vec<String> = symbols.symbols.iter().map(|s| s.formatted_path()).collect();
    assert!(paths.contains(&"root/block_a/check_w1".to_string()));
    assert!(paths.contains(&"root/block_b/check_w2".to_string()));

    let rf = RuntimeP256Field::new();

    // Passing test: inputs w1 = 0, w2 = 0
    {
        let inputs = vec![rf.one(), rf.zero(), rf.zero()];
        let eval_res =
            eval_circuit_fc(&f, &rf, &circuit, &symbols, &inputs, FieldID::P256).unwrap();
        eval_res.assert_all_passed();
    }

    // Failing test 1: w1 = 1, w2 = 0 -> failure at "root/block_a/check_w1"
    {
        let inputs = vec![rf.one(), rf.one(), rf.zero()];
        let eval_res =
            eval_circuit_fc(&f, &rf, &circuit, &symbols, &inputs, FieldID::P256).unwrap();
        eval_res.assert_any_failed_at("root/block_a/check_w1");
    }

    // Failing test 2: w1 = 0, w2 = 1 -> failure at "root/block_b/check_w2"
    {
        let inputs = vec![rf.one(), rf.zero(), rf.one()];
        let eval_res =
            eval_circuit_fc(&f, &rf, &circuit, &symbols, &inputs, FieldID::P256).unwrap();
        eval_res.assert_any_failed_at("root/block_b/check_w2");
    }
}

#[test]
fn test_debug_symbols_record_assertion_layers() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);

    let x = l.input(1);
    let square = l.mul(&x, &x);
    let fourth_power = l.mul(&square, &square);

    let input_assertion = l.assert0("input", &x);
    let output_assertion = l.assert0("output", &fourth_power);
    let root = l.assert_all("root", &[input_assertion, output_assertion]);

    let (circuit, info, symbols) = compile_compiler::top::compile(&arena, &f, root, 1, 0);
    assert_eq!(info.nlayers, 2);
    assert_eq!(info.nassertions, 2);
    assert_eq!(symbols.symbols.len(), 2);

    let input_symbol = symbols
        .symbols
        .iter()
        .find(|symbol| symbol.formatted_path() == "root/input")
        .unwrap();
    assert_eq!(input_symbol.wire.layer, 1);

    let output_symbol = symbols
        .symbols
        .iter()
        .find(|symbol| symbol.formatted_path() == "root/output")
        .unwrap();
    assert_eq!(output_symbol.wire.layer, 0);

    let runtime_f = RuntimeP256Field::new();
    let failed = eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.one()],
        FieldID::P256,
    )
    .unwrap();
    failed.assert_any_failed_at("root/input");
}

#[test]
fn test_attached_assertion_keeps_its_path() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);

    let computed = l.input(1);
    let witness = l.input(2);
    let sliced = l.slicing("slice", &witness, &computed);
    let consumer = l.assert0("consumer", &sliced);
    let root = l.assert_all("root", &[consumer]);

    let (circuit, info, symbols) = compile_compiler::top::compile(&arena, &f, root, 1, 0);
    assert_eq!(info.nassertions, 2);
    assert_eq!(symbols.symbols.len(), 2);
    assert!(symbols
        .symbols
        .iter()
        .any(|symbol| symbol.formatted_path() == "root/slice"));

    let runtime_f = RuntimeP256Field::new();
    let failed = eval_circuit_fc(
        &f,
        &runtime_f,
        &circuit,
        &symbols,
        &[runtime_f.one(), runtime_f.one(), runtime_f.zero()],
        FieldID::P256,
    )
    .unwrap();
    assert_eq!(failed.failed_paths(), vec!["root/slice"]);
}
