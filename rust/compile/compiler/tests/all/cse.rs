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
use compile_compiler::{
    arena::CompilerArena,
    cse::Cse,
    ir::{AssertionItem, RewriteT},
};

fn run_test_cse<const W: usize, F: CompileField + SupportsNatConversions<W>>(f: &F) {
    let arena = CompilerArena::<F>::new();
    let cse = Cse::new(&arena);
    let input_node1 = cse.input(1);
    let input_node2 = cse.input(1);
    assert_eq!(input_node1, input_node2);

    let sum1 = cse.sum(&[input_node1, input_node2], false);
    let sum2 = cse.sum(&[input_node2, input_node1], false);
    assert_eq!(sum1, sum2);

    // Constant collapsing
    let two = f.addf(&f.one(), &f.one());
    let const1 = cse.constant(&two);
    let const2 = cse.constant(&two);
    assert_eq!(const1, const2);

    // Linear collapsing
    let lin1 = cse.linear(&two, &input_node1);
    let lin2 = cse.linear(&two, &input_node2);
    assert_eq!(lin1, lin2);

    // Quadratic collapsing (including sorting commutativity)
    let quad1 = cse.quadratic(&two, &input_node1, &const1);
    let quad2 = cse.quadratic(&two, &const1, &input_node2);
    assert_eq!(quad1, quad2);
}

#[test]
fn test_cse() {
    let f = P256Field::new();
    run_test_cse::<4, P256Field>(&f);
}

fn run_test_cse_assertions<const W: usize, F: CompileField + SupportsNatConversions<W>>(f: &F) {
    let tracker = compile_logic::scope::AssertionScope::new();
    let aid1 = tracker.new_leaf("assert_input");
    let _aid2 = tracker.new_leaf("assert_one");
    let arena = CompilerArena::<F>::new();
    let cse = Cse::new(&arena);
    let input_node = cse.input(1);
    let const_node = cse.constant(&f.one());

    // Create two individual assertions
    let assert_input = cse.assert0(&input_node);
    let assert_one = cse.assert0(&const_node);

    // Union them in different orders
    let assertions1 = cse.assertions(&[assert_input, assert_one]);
    let assertions2 = cse.assertions(&[assert_one, assert_input]);
    let raw_items1: Vec<_> = assertions1
        .iter()
        .map(|&expr| AssertionItem { id: aid1, expr })
        .collect();
    let raw_items2: Vec<_> = assertions2
        .iter()
        .map(|&expr| AssertionItem { id: aid1, expr })
        .collect();
    let assertion_items1 = arena.alloc_slice(&raw_items1);
    let assertion_items2 = arena.alloc_slice(&raw_items2);

    // Construct expressions with assertions in different orders
    let expr1 = cse.with_assertions(&assertion_items1, &input_node);
    let expr2 = cse.with_assertions(&assertion_items2, &input_node);

    // Assert that they are collapsed into the same node
    assert_eq!(expr1, expr2);
}

#[test]
fn test_cse_assertions() {
    let f = P256Field::new();
    run_test_cse_assertions::<4, P256Field>(&f);
}
