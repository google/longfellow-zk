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

pub use compile_proto::debug;
pub mod eval;

pub use compile_algebra::field::{CompileField, SupportsNatConversions};
pub use compile_proto::debug::{
    AssertionSymbol, CircuitDebugSymbols, CompiledAssertionStatus, CompiledEvalAssertions,
    EvaluatedCompiledAssertion, WireRef,
};
pub use core_algebra::SerializableField;
pub use core_proto::circuit::{
    canonical_term, compare_term, compute_id, Circuit, CircuitGeometry, DigestBytes, FieldID,
    Layer, RawCircuit, Term, TermDelta,
};

pub use crate::eval::{eval_circuit, eval_circuit_fc, initial_inputs};
