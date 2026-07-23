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
    field::{CompileField, SupportsNatConversions, SupportsU64Conversions},
    gf2_128::Gf2_128Field,
    p256::P256Field,
    AlgebraicField,
};
use compile_compiler::{
    algsimp::AlgebraicRewriter,
    cse::Cse,
    ir::{Expr, RewriteT},
    CompilerArena,
};
use core_algebra::Nat;

fn run_test<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
) {
    let arena = CompilerArena::new();
    let cse = Cse::new(&arena);
    let algebraic = AlgebraicRewriter::new(f, cse);

    // Constant folding
    let c1 = algebraic.constant(&f.u64_to_element(10));
    let c2 = algebraic.constant(&f.u64_to_element(20));
    let sum_nodes = algebraic.sum(&[c1, c2], false);

    match &sum_nodes.v {
        Expr::Constant(ref val) => {
            assert_eq!(f.to_nat(val), F::N::from_u64(30));
        }
        _ => panic!("Expected Constant(30), got {sum_nodes:?}"),
    }
}

#[test]
fn test_rewrite_algebraic_simplification() {
    let f = P256Field::new();
    run_test::<4, P256Field>(&f);
}

#[test]
fn test_algsimp_prime_cancel() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let cse = Cse::new(&arena);
    let algebraic = AlgebraicRewriter::new(&f, cse);

    let x = algebraic.input(1);
    let neg_x = algebraic.linear(&f.mone(), &x);
    let sum = algebraic.sum(&[x, neg_x], false);

    match &sum.v {
        Expr::Constant(ref val) => {
            assert!(f.is_zero(val));
        }
        _ => panic!("Expected Constant(0), got {sum:?}"),
    }
}

#[test]
fn test_algsimp_binary_x_plus_x() {
    let f = Gf2_128Field::new();
    let arena = CompilerArena::new();
    let cse = Cse::new(&arena);
    let algebraic = AlgebraicRewriter::new(&f, cse);

    let x = algebraic.input(1);
    let sum = algebraic.sum(&[x, x], false);

    match &sum.v {
        Expr::Constant(ref val) => {
            assert!(f.is_zero(val));
        }
        _ => panic!("Expected Constant(0), got {sum:?}"),
    }
}
