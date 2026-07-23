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
