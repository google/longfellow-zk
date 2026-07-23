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
use compile_compiler::{ir::Assertions, ir_to_quad::rewrite, quad::WExpr, CompilerArena};

#[test]
fn test_ir_to_quad_one() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let x: Assertions<P256Field> = &[];
    let (quad, _) = rewrite(&arena, &f, x);
    // Assert that the quadratic circuit has the defaulted One node at index 0
    assert_eq!(quad.nodes.len(), 1);
    match &quad.nodes[0] {
        WExpr::Input {
            position_in_input_array,
        } => {
            assert_eq!(*position_in_input_array, 0);
        }
        _ => panic!("Expected Input(One) at index 0"),
    }
}
