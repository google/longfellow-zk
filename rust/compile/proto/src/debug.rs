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

use compile_logic::scope::{AssertionId, AssertionScope, AssertionStatus};

/// Mapping from a specific circuit output wire to its assertion ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionSymbol {
    /// Target wire reference in the compiled circuit.
    pub wire: WireRef,
    /// Assertion ID tracked in AssertionScope.
    pub id: AssertionId,
}

impl AssertionSymbol {
    /// Creates a new assertion symbol pairing a wire reference with an assertion ID.
    pub fn new(wire: WireRef, id: AssertionId) -> Self {
        Self { wire, id }
    }
}

/// Collection of debug symbols associated with a compiled circuit.
#[derive(Debug, Default)]
pub struct CircuitDebugSymbols {
    /// List of assertion symbols for output wires.
    symbols: Vec<AssertionSymbol>,
    /// Associated assertion scope.
    tracker: AssertionScope,
}

impl CircuitDebugSymbols {
    /// Creates a new container of circuit debug symbols.
    pub fn new(symbols: Vec<AssertionSymbol>, tracker: AssertionScope) -> Self {
        Self { symbols, tracker }
    }

    /// Returns the number of assertion symbols.
    pub fn assertion_count(&self) -> usize {
        self.symbols.len()
    }

    /// Returns all assertion symbols recorded for this circuit.
    pub fn assertion_symbols(&self) -> &[AssertionSymbol] {
        &self.symbols
    }

    /// Returns the tracker path for an assertion identifier, if any.
    pub fn get_path(&self, id: AssertionId) -> Option<String> {
        if id.is_nil() {
            return None;
        }
        let path = self.tracker.get_path(id);
        (!path.is_empty()).then_some(path)
    }

    /// Looks up the assertion symbol for a given wire reference.
    pub fn get_symbol(&self, wire: &WireRef) -> Option<&AssertionSymbol> {
        self.symbols.iter().find(|s| &s.wire == wire)
    }

    /// Looks up the assertion ID for a given wire reference.
    pub fn get_id(&self, wire: &WireRef) -> Option<AssertionId> {
        self.get_symbol(wire).map(|s| s.id)
    }

    /// Looks up the assertion symbol by path.
    pub fn get_symbol_by_path(&self, path: &str) -> Option<&AssertionSymbol> {
        self.symbols
            .iter()
            .find(|symbol| self.get_path(symbol.id).as_deref() == Some(path))
    }

    pub fn tracker(&self) -> &AssertionScope {
        &self.tracker
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

use std::collections::HashMap;

/// Aggregate result of evaluating a compiled circuit, detailing overall pass/fail status and
/// per-assertion evaluation.
#[derive(Clone)]
pub struct CompiledEvalAssertions<'a, E = String> {
    /// Overall result of the circuit evaluation.
    pub result: Result<(), E>,
    /// Map of assertion ID to status.
    pub fates: HashMap<AssertionId, AssertionStatus>,
    /// Reference to the assertion scope.
    pub tracker: &'a AssertionScope,
}

impl<'a, E: std::fmt::Debug> CompiledEvalAssertions<'a, E> {
    /// Returns `true` if the overall evaluation succeeded.
    pub fn is_ok(&self) -> bool {
        self.result.is_ok() && self.tracker.is_ok(&self.fates)
    }

    /// Returns `true` if the overall evaluation failed.
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    /// Unwraps the evaluation result, panicking if it is an `Err`.
    pub fn unwrap(&self) {
        self.result.as_ref().unwrap();
        self.assert_all_passed();
    }

    /// Expects the evaluation result to be `Ok`, panicking with `msg` if it is an `Err`.
    pub fn expect(self, msg: &str) {
        if let Err(e) = &self.result {
            panic!("{msg}: {e:?}");
        }
        self.assert_all_passed();
    }

    /// Returns a list of formatted paths for all evaluated assertions.
    pub fn all_paths(&self) -> Vec<String> {
        self.tracker.all_paths(&self.fates)
    }

    /// Returns a list of formatted paths for assertions that passed.
    pub fn passed_paths(&self) -> Vec<String> {
        self.tracker.passed_paths(&self.fates)
    }

    /// Returns a list of formatted paths for assertions that failed.
    pub fn failed_paths(&self) -> Vec<String> {
        self.tracker.failed_paths(&self.fates)
    }

    /// Asserts that all evaluations passed, panicking with details if any failed.
    pub fn assert_all_passed(&self) {
        self.tracker.assert_all_passed(&self.fates);
    }

    /// Asserts that all evaluations under a specific path prefix passed.
    pub fn assert_all_passed_at(&self, expected_path: &str) {
        self.tracker
            .assert_all_passed_at(expected_path, &self.fates);
    }

    /// Asserts that at least one assertion failed at exactly `expected_path`.
    pub fn assert_any_failed_at(&self, expected_path: &str) {
        self.tracker
            .assert_any_failed_at(expected_path, &self.fates);
    }
}
