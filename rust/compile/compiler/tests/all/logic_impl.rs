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
    field::{CompileField, SupportsNatConversions},
    p256::P256Field,
};
use compile_compiler::{ir::Expr, CompilerArena, CompilerLogic};
use compile_logic::{Logic, LogicIO};
use core_algebra::Nat;

fn run_test<const W: usize, F: CompileField + SupportsNatConversions<W>>(field: &F) {
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, field);
    let z = l.zero();
    let o = l.one();
    let add_node = l.add(&z, &o);

    // Constant folding checks: 0 + 1 should fold to a single constant node 1
    match &add_node.v {
        Expr::Constant(ref val) => {
            assert_eq!(field.to_nat(val), F::N::from_u64(1));
        }
        _ => panic!("Expected Constant(1), got {add_node:?}"),
    }
}

#[test]
fn test_compiler_logic_terms() {
    let field = P256Field::new();
    run_test::<4, P256Field>(&field);
}

#[test]
fn test_precious_sum_behavior() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);

    let w1 = l.input(1);
    let w2 = l.input(2);
    let w3 = l.input(3);

    // Test case 1: precious(w1 + w2) + w3 => Sum([Sum([w1, w2], true), w3],
    // false) (no flattening)
    {
        let precious_sum = l.precious(&l.add(&w1, &w2));
        let expr = l.add(&precious_sum, &w3);
        let assert_expr = l.assert0("test_case_1", &expr);
        let items_ref = arena.alloc_slice(&assert_expr.items);
        let rewritten = compile_compiler::assertion::rewrite(&arena, &f, items_ref, &l.tracker);
        assert_eq!(rewritten.len(), 1);
        let rewritten_node = rewritten[0].expr;

        match &rewritten_node.v {
            Expr::Sum(list, false) => {
                assert_eq!(list.len(), 2);
                let has_w3 = list.iter().any(|child| match &child.v {
                    Expr::Input(w) => *w == 3,
                    _ => false,
                });
                assert!(has_w3);
                let inner_sum = list
                    .iter()
                    .find(|child| matches!(&child.v, Expr::Sum(_, _)))
                    .unwrap();
                match &inner_sum.v {
                    Expr::Sum(inner_list, true) => {
                        assert_eq!(inner_list.len(), 2);
                        let has_w1 = inner_list.iter().any(|child| match &child.v {
                            Expr::Input(w) => *w == 1,
                            _ => false,
                        });
                        let has_w2 = inner_list.iter().any(|child| match &child.v {
                            Expr::Input(w) => *w == 2,
                            _ => false,
                        });
                        assert!(has_w1);
                        assert!(has_w2);
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                panic!("Expected Sum(..., false), got {rewritten_node:?}")
            }
        }
    }

    // Test case 2: w3 * precious(w1 + w2) => w3 * Sum([w1, w2], true) (no
    // distribution)
    {
        let precious_sum = l.precious(&l.add(&w1, &w2));
        let expr = l.mul(&w3, &precious_sum);
        let assert_expr = l.assert0("test_case_2", &expr);
        let items_ref = arena.alloc_slice(&assert_expr.items);
        let rewritten = compile_compiler::assertion::rewrite(&arena, &f, items_ref, &l.tracker);
        assert_eq!(rewritten.len(), 1);
        let rewritten_node = rewritten[0].expr;

        match &rewritten_node.v {
            Expr::Quadratic(_, x, y) => {
                let (input_child, sum_child) = if matches!(x.v, Expr::Input(_)) {
                    (x, y)
                } else {
                    (y, x)
                };
                match &input_child.v {
                    Expr::Input(w) => assert_eq!(*w, 3),
                    _ => panic!("Expected Input, got {input_child:?}"),
                }
                match &sum_child.v {
                    Expr::Sum(inner_list, true) => {
                        assert_eq!(inner_list.len(), 2);
                        let has_w1 = inner_list.iter().any(|child| match &child.v {
                            Expr::Input(w) => *w == 1,
                            _ => false,
                        });
                        let has_w2 = inner_list.iter().any(|child| match &child.v {
                            Expr::Input(w) => *w == 2,
                            _ => false,
                        });
                        assert!(has_w1);
                        assert!(has_w2);
                    }
                    _ => panic!("Expected Sum(..., true), got {sum_child:?}"),
                }
            }
            _ => panic!("Expected Quadratic, got {rewritten_node:?}"),
        }
    }

    // Test case 3: precious(w1) => w1 (strips precious when not a sum)
    {
        let precious_val = l.precious(&w1);
        let assert_expr = l.assert0("test_case_3", &precious_val);
        let items_ref = arena.alloc_slice(&assert_expr.items);
        let rewritten = compile_compiler::assertion::rewrite(&arena, &f, items_ref, &l.tracker);
        assert_eq!(rewritten.len(), 1);
        let rewritten_node = rewritten[0].expr;
        match &rewritten_node.v {
            Expr::Input(w) => assert_eq!(*w, 1),
            _ => panic!("Expected Input, got {rewritten_node:?}"),
        }
    }
}

#[test]
fn test_compiler_assertion_path_and_simplification() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);

    let w1 = l.input(1);
    let w2 = l.input(2);

    let leaf1 = l.assert0("check_input2_zero", &w2);
    let leaf2 = l.assert0("check_input1_zero", &w1);

    let inner = l.assert_all("trivial_checks", &[leaf1]);
    let root = l.assert_all("root_block", &[inner, leaf2]);

    assert_eq!(root.items.len(), 2);

    let items_ref = arena.alloc_slice(&root.items);
    let simplified = compile_compiler::assertion::rewrite(&arena, &f, items_ref, &l.tracker);
    assert_eq!(simplified.len(), 2);
}

#[test]
fn test_assertion_paths_do_not_expand_through_shared_groups() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);
    let x = l.input(1);

    let mut assertion = l.assert0("leaf", &x);
    for _ in 0..32 {
        assertion = l.assert_all("shared", &[assertion, assertion]);
        assert_eq!(assertion.items.len(), 1);
    }

    let (_, info, symbols) = compile_compiler::top::compile(&arena, &f, assertion, l.tracker, 1, 0);
    assert_eq!(info.nassertions, 1);
    assert_eq!(symbols.symbols.len(), 1);
}

#[test]
fn test_duplicate_assertion_paths_keep_first_path() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let l = CompilerLogic::new(&arena, &f);
    let x = l.input(1);

    let first = l.assert0("first", &x);
    let second = l.assert0("second", &x);
    let root = l.assert_all("root", &[first, second]);

    assert_eq!(root.items.len(), 2);

    let (_, info, symbols) = compile_compiler::top::compile(&arena, &f, root, l.tracker, 1, 0);
    assert_eq!(info.nassertions, 1);
    assert_eq!(symbols.symbols.len(), 1);
}
