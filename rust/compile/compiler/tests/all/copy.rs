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
    p256::P256Field,
};
use compile_compiler::{
    copy::CopyRewriter,
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

    let copy_rewriter = CopyRewriter::new(f, cse);

    // Constant folding to quadratic
    let c1 = copy_rewriter.constant(&f.u64_to_element(10));
    match &c1.v {
        Expr::Quadratic(ref val, x, y) => {
            assert_eq!(f.to_nat(val), F::N::from_u64(10));
            assert!(matches!(x.v, Expr::One));
            assert!(matches!(y.v, Expr::One));
        }
        _ => panic!("Expected Quadratic(10, One, One), got {c1:?}"),
    }
}

#[test]
fn test_rewrite_copy() {
    let f = P256Field::new();
    run_test::<4, P256Field>(&f);
}
