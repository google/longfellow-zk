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

pub mod algsimp;
mod arena;
pub mod assertion;
pub mod copy;
pub mod cse;
pub mod ir;
pub mod ir_to_quad;
pub mod logic_impl;
pub mod node;
pub mod quad;
pub mod scheduler;
pub mod segment;
pub mod top;

pub use compile_proto::debug;
pub use debug::{
    AssertionSymbol, CircuitDebugSymbols, CompiledAssertionStatus, CompiledEvalAssertions,
    EvaluatedCompiledAssertion, WireRef,
};
pub use ir::AssertionItem;
pub use logic_impl::{CompilerAssertions, CompilerLogic};
pub use segment::{segment_circuit, segment_layer};

#[cfg(test)]
extern crate self as compile_compiler;

#[cfg(test)]
#[path = "../tests/all/mod.rs"]
mod compiler_tests;
