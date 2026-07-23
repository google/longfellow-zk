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

//! Debug symbol definitions and evaluation assertion types for compiled circuits.

/// Reference to a specific wire index within a circuit layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireRef {
    /// Layer index (e.g. 0 for circuit output layer).
    pub layer: usize,
    /// Wire index within the specified layer.
    pub index: usize,
}

impl WireRef {
    /// Creates a new wire reference at `(layer, index)`.
    pub fn new(layer: usize, index: usize) -> Self {
        Self { layer, index }
    }
}

/// Mapping from a specific circuit output wire to its hierarchical assertion path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionSymbol {
    /// Target wire reference in the compiled circuit.
    pub wire: WireRef,
    /// Hierarchical scope path (e.g., `["root", "block_a", "check_w1"]`).
    pub path: Vec<String>,
}

impl AssertionSymbol {
    /// Creates a new assertion symbol pairing a wire reference with a path.
    pub fn new(wire: WireRef, path: Vec<String>) -> Self {
        Self { wire, path }
    }

    /// Formats the hierarchical path into a single slash-separated string (e.g.,
    /// `"root/block_a/check_w1"`).
    pub fn formatted_path(&self) -> String {
        self.path.join("/")
    }
}

/// Collection of debug symbols associated with a compiled circuit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CircuitDebugSymbols {
    /// List of assertion symbols for output wires.
    pub symbols: Vec<AssertionSymbol>,
}

impl CircuitDebugSymbols {
    /// Creates a new container of circuit debug symbols.
    pub fn new(symbols: Vec<AssertionSymbol>) -> Self {
        Self { symbols }
    }

    /// Looks up the assertion symbol for a given wire reference.
    pub fn get_symbol(&self, wire: &WireRef) -> Option<&AssertionSymbol> {
        self.symbols.iter().find(|s| &s.wire == wire)
    }

    /// Looks up the hierarchical path slice for a given wire reference.
    pub fn get_path(&self, wire: &WireRef) -> Option<&[String]> {
        self.get_symbol(wire).map(|s| s.path.as_slice())
    }

    /// Looks up and returns the formatted slash-separated path for a given wire reference.
    pub fn get_formatted_path(&self, wire: &WireRef) -> Option<String> {
        self.get_symbol(wire).map(|s| s.formatted_path())
    }
}

/// Status of an assertion evaluation during circuit simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompiledAssertionStatus {
    /// The assertion passed (output wire evaluated to zero).
    Passed,
    /// The assertion failed with an error message (output wire evaluated to non-zero).
    Failed(String),
}

/// Detailed evaluation result for a specific output wire assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedCompiledAssertion {
    /// Evaluated wire reference.
    pub wire: WireRef,
    /// Formatted scope path for the assertion.
    pub path: String,
    /// Evaluation status (Passed or Failed).
    pub status: CompiledAssertionStatus,
}

/// Aggregate result of evaluating a compiled circuit, detailing overall pass/fail status and
/// per-assertion evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledEvalAssertions<E = String> {
    /// Overall result of the circuit evaluation.
    pub result: Result<(), E>,
    /// Individual per-assertion evaluations.
    pub evaluations: Vec<EvaluatedCompiledAssertion>,
}

impl<E: std::fmt::Debug> CompiledEvalAssertions<E> {
    /// Returns `true` if the overall evaluation succeeded.
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns `true` if the overall evaluation failed.
    pub fn is_err(&self) -> bool {
        self.result.is_err()
    }

    /// Unwraps the evaluation result, panicking if it is an `Err`.
    pub fn unwrap(self) {
        self.result.unwrap()
    }

    /// Expects the evaluation result to be `Ok`, panicking with `msg` if it is an `Err`.
    pub fn expect(self, msg: &str) {
        self.result.expect(msg)
    }

    /// Returns a list of formatted paths for all evaluated assertions.
    pub fn all_paths(&self) -> Vec<String> {
        self.evaluations.iter().map(|e| e.path.clone()).collect()
    }

    /// Returns a list of formatted paths for assertions that passed.
    pub fn passed_paths(&self) -> Vec<String> {
        self.evaluations
            .iter()
            .filter(|e| matches!(e.status, CompiledAssertionStatus::Passed))
            .map(|e| e.path.clone())
            .collect()
    }

    /// Returns a list of formatted paths for assertions that failed.
    pub fn failed_paths(&self) -> Vec<String> {
        self.evaluations
            .iter()
            .filter(|e| matches!(e.status, CompiledAssertionStatus::Failed(_)))
            .map(|e| e.path.clone())
            .collect()
    }

    /// Asserts that all evaluations passed, panicking with details if any failed.
    pub fn assert_all_passed(&self) {
        let failed = self.failed_paths();
        assert!(
            self.is_ok() && failed.is_empty(),
            "Expected all compiled assertions to pass, but the following failed: {failed:?}"
        );
    }

    /// Asserts that all evaluations under a specific path prefix passed.
    pub fn assert_all_passed_at(&self, expected_path: &str) {
        let failed_under_path: Vec<_> = self
            .failed_paths()
            .into_iter()
            .filter(|p| p == expected_path || p.contains(expected_path))
            .collect();
        assert!(
            failed_under_path.is_empty(),
            "Expected all compiled assertions at '{expected_path}' to pass, but found failures: {failed_under_path:?}"
        );
    }

    /// Asserts that at least one assertion failed at the given expected path prefix.
    pub fn assert_any_failed_at(&self, expected_path: &str) {
        let failed_under_path: Vec<_> = self
            .failed_paths()
            .into_iter()
            .filter(|p| p == expected_path || p.contains(expected_path))
            .collect();
        assert!(
            !failed_under_path.is_empty(),
            "Expected compiled assertion at '{expected_path}' to fail, but none failed."
        );
    }
}
