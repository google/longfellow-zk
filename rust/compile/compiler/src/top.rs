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

use compile_algebra::field::CompileField;
use compile_logic::AssertionScope;
use core_proto::circuit::{Circuit, CircuitGeometry};

use crate::{
    logic_impl::{CompilerAssertions, CompilerLogic},
    arena::CompilerArena,
};

pub fn compile_new<'a, F, Build>(
    f: &'a F,
    build: Build,
) -> (
    Circuit<F>,
    CircuitGeometry,
    crate::debug::CircuitDebugSymbols,
)
where
    F: CompileField + core_algebra::SerializableField,
    Build: for<'src> FnOnce(
        CompilerLogic<'src, F>,
    ) -> (CompilerAssertions<'src, F>, AssertionScope, usize, usize),
{
    let source_arena = crate::arena::CompilerArena::new();
    let source_logic = CompilerLogic::new(&source_arena, f);

    let (circuit, info, symbols) = {
        let (assertions, tracker, npublic_input, subfield_boundary) = build(source_logic);
        let arena1 = CompilerArena::new();
        let simplified = crate::assertion::rewrite(&arena1, f, assertions.items, &tracker);
        let _ = assertions;

        // Source arena is no longer needed as soon as source assertions have
        // been rewritten.
        drop(source_arena);

        // Pass 2: copy rewrite into arena2 (inserts term copies and depth alignment)
        let arena2 = CompilerArena::new();
        let copy_propagated = crate::copy::rewrite(&arena2, f, simplified);

        // Safe Rust: drop arena1 immediately after Pass 2!
        drop(arena1);

        // Pass 3: ir_to_quad rewrite into owned QuadCircuit representation
        let (quad_circuit, quad_asserts) =
            crate::ir_to_quad::rewrite(&arena2, f, copy_propagated, &tracker);

        // Safe Rust: drop arena2 immediately after Pass 3!
        drop(arena2);

        let (circuit, info, mut symbols) = crate::scheduler::schedule(
            f,
            quad_circuit,
            &quad_asserts,
            npublic_input,
            subfield_boundary,
        );

        assert!(info.ninput > 0);
        assert!(info.nterms > 0);

        symbols.tracker = tracker;
        (circuit, info, symbols)
    };

    (circuit, info, symbols)
}

pub fn dump_stats<F: CompileField + core_algebra::SerializableField>(
    name: &str,
    _circuit: &Circuit<F>,
    info: &CircuitGeometry,
) {
    println!(
        "{}: nin:{} pubin:{} nout:{} w:{} w+in:{} t:{} l:{} assertions:{}",
        name,
        info.ninput,
        info.npublic_input,
        info.noutput,
        info.nwires,
        info.ninput + info.nwires,
        info.nterms,
        info.nlayers,
        info.nassertions,
    );
}
