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

//! Direct evaluation of circuit logic with exact assertion provenance.
//!
//! A wire carries two different kinds of failure information:
//!
//! * `computation_error` means that the wire's value could not be computed. A later assertion over
//!   such a wire fails at that later assertion.
//! * `assertions` contains constraints attached with `with_assertions`. These constraints are
//!   independent of the wire's value: a failed attached constraint must keep its original name,
//!   while later assertions still evaluate their own equations normally.
//!
//! The public `EvalWire::error` combines both kinds so callers can cheaply ask
//! whether a wire is valid. It must not be used to attribute an assertion
//! failure, because doing so would rename an attached failure after whichever
//! assertion happens to consume the wire.
//!
//! Assertion provenance is represented by a persistent `Rc` DAG. Leaves are
//! individual assertion occurrences, groups represent `assert_all` scopes, and
//! joins propagate assertions through arithmetic without copying path vectors.
//! Cloning an assertion preserves node identity, so a shared assertion reached
//! through several expression paths is reported once. Separately constructed
//! assertions remain distinct even when they use the same textual name.
//!
//! Paths are resolved only when requested. The iterative traversal carries the
//! active group scope and skips trace nodes already visited by identity. This
//! gives the first deterministic path for a shared assertion without
//! enumerating the potentially exponential number of paths through the wire
//! DAG. In particular, `assert_all("ecdsa", ...)` prefixes attached assertions
//! just like ordinary assertions, producing paths such as `ecdsa/slice_wx`.

use std::rc::Rc;

use compile_algebra::field::CompileField;
use core_algebra::ElementOf;

use crate::Logic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    AssertionFailure(String),
}

pub struct EvalWire<F: CompileField> {
    pub value: ElementOf<F>,
    /// Aggregate validity, including both computation errors and attached
    /// assertion failures.
    pub error: Result<(), EvalError>,
    computation_error: Result<(), EvalError>,
    assertions: AssertionTrace,
}

impl<F: CompileField> Clone for EvalWire<F> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            error: self.error.clone(),
            computation_error: self.computation_error.clone(),
            assertions: self.assertions.clone(),
        }
    }
}

impl<F: CompileField> EvalWire<F> {
    pub fn ok(value: ElementOf<F>) -> Self {
        Self {
            value,
            error: Ok(()),
            computation_error: Ok(()),
            assertions: None,
        }
    }

    pub fn err(value: ElementOf<F>, err: EvalError) -> Self {
        Self {
            value,
            error: Err(err.clone()),
            computation_error: Err(err),
            assertions: None,
        }
    }
}

impl<F: CompileField> PartialEq for EvalWire<F> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value) && self.error.eq(&other.error)
    }
}

impl<F: CompileField> Eq for EvalWire<F> {}

impl<F: CompileField> std::fmt::Debug for EvalWire<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalWire")
            .field("value", &self.value)
            .field("error", &self.error)
            .field("has_attached_assertions", &self.assertions.is_some())
            .finish()
    }
}

pub struct EvalLogic<'a, F: CompileField> {
    f: &'a F,
}

impl<'a, F: CompileField> EvalLogic<'a, F> {
    pub fn new(f: &'a F) -> Self {
        Self { f }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionStatus {
    Passed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatedAssertion {
    pub path: String,
    pub status: AssertionStatus,
}

type AssertionTrace = Option<Rc<AssertionTraceNode>>;

/// Cached summary plus one node of the persistent assertion-provenance DAG.
///
/// `first_failure` makes `EvalAssertions::result` available without resolving
/// paths or walking the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AssertionTraceNode {
    first_failure: Option<EvalError>,
    kind: AssertionTraceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssertionTraceKind {
    Leaf(EvaluatedAssertion),
    Group {
        name: String,
        child: Rc<AssertionTraceNode>,
    },
    Join {
        left: Rc<AssertionTraceNode>,
        right: Rc<AssertionTraceNode>,
    },
}

fn assertion_leaf(evaluation: EvaluatedAssertion) -> AssertionTrace {
    let first_failure = match &evaluation.status {
        AssertionStatus::Passed => None,
        AssertionStatus::Failed(message) => Some(EvalError::AssertionFailure(message.to_string())),
    };
    Some(Rc::new(AssertionTraceNode {
        first_failure,
        kind: AssertionTraceKind::Leaf(evaluation),
    }))
}

fn join_assertions(left: &AssertionTrace, right: &AssertionTrace) -> AssertionTrace {
    match (left, right) {
        (None, _) => right.clone(),
        (_, None) => left.clone(),
        (Some(left), Some(right)) if Rc::ptr_eq(left, right) => Some(left.clone()),
        (Some(left), Some(right)) => Some(Rc::new(AssertionTraceNode {
            first_failure: left
                .first_failure
                .clone()
                .or_else(|| right.first_failure.clone()),
            kind: AssertionTraceKind::Join {
                left: left.clone(),
                right: right.clone(),
            },
        })),
    }
}

fn group_assertions(name: &str, child: &AssertionTrace) -> AssertionTrace {
    child.as_ref().map(|child| {
        Rc::new(AssertionTraceNode {
            first_failure: child.first_failure.clone(),
            kind: AssertionTraceKind::Group {
                name: name.to_string(),
                child: child.clone(),
            },
        })
    })
}

#[derive(Clone)]
struct AssertionScope {
    name: String,
    parent: Option<Rc<AssertionScope>>,
}

fn format_assertion_path(scope: &Option<Rc<AssertionScope>>, leaf: &str) -> String {
    let mut names = Vec::new();
    let mut current = scope.clone();
    while let Some(node) = current {
        names.push(node.name.clone());
        current = node.parent.clone();
    }
    names.reverse();
    names.push(leaf.to_string());
    names.join("/")
}

fn path_is_at_or_below(path: &str, expected_path: &str) -> bool {
    path == expected_path
        || path
            .strip_prefix(expected_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn materialize_assertions(trace: &AssertionTrace) -> Vec<EvaluatedAssertion> {
    let Some(root) = trace else {
        return Vec::new();
    };

    let mut evaluations = Vec::new();
    // Visiting by allocation identity is the direct-evaluator counterpart of
    // compiler assertion coalescing: aliases share an Rc node, whereas two
    // separately constructed assertions with the same name have different
    // nodes and are both retained.
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![(root.clone(), None)];

    while let Some((node, scope)) = stack.pop() {
        if !visited.insert(Rc::as_ptr(&node)) {
            continue;
        }
        match &node.kind {
            AssertionTraceKind::Leaf(evaluation) => {
                evaluations.push(EvaluatedAssertion {
                    path: format_assertion_path(&scope, &evaluation.path),
                    status: evaluation.status.clone(),
                });
            }
            AssertionTraceKind::Group { name, child } => {
                let scope = Some(Rc::new(AssertionScope {
                    name: name.clone(),
                    parent: scope,
                }));
                stack.push((child.clone(), scope));
            }
            AssertionTraceKind::Join { left, right } => {
                stack.push((right.clone(), scope.clone()));
                stack.push((left.clone(), scope));
            }
        }
    }

    evaluations
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalAssertions {
    pub result: Result<(), EvalError>,
    trace: AssertionTrace,
}

impl EvalAssertions {
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    pub fn is_err(&self) -> bool {
        self.result.is_err()
    }

    pub fn unwrap(self) {
        self.result.unwrap()
    }

    pub fn expect(self, msg: &str) {
        self.result.expect(msg)
    }

    /// Returns all evaluated assertions with their fully resolved paths.
    pub fn evaluations(&self) -> Vec<EvaluatedAssertion> {
        materialize_assertions(&self.trace)
    }

    /// Returns path strings for all evaluated assertions.
    pub fn all_paths(&self) -> Vec<String> {
        self.evaluations().into_iter().map(|e| e.path).collect()
    }

    /// Returns path strings for all passing assertions.
    pub fn passed_paths(&self) -> Vec<String> {
        self.evaluations()
            .into_iter()
            .filter(|e| matches!(e.status, AssertionStatus::Passed))
            .map(|e| e.path)
            .collect()
    }

    /// Returns path strings for all failing assertions.
    pub fn failed_paths(&self) -> Vec<String> {
        self.evaluations()
            .into_iter()
            .filter(|e| matches!(e.status, AssertionStatus::Failed(_)))
            .map(|e| e.path)
            .collect()
    }

    /// Asserts that evaluation succeeded and all assertions passed.
    pub fn assert_all_passed(&self) {
        let failed = self.failed_paths();
        assert!(
            self.is_ok() && failed.is_empty(),
            "Expected all assertions to pass, but the following failed: {failed:?}"
        );
    }

    /// Asserts that all assertions matching or under `expected_path` passed (and none failed).
    pub fn assert_all_passed_at(&self, expected_path: &str) {
        let failed_under_path: Vec<_> = self
            .failed_paths()
            .into_iter()
            .filter(|p| path_is_at_or_below(p, expected_path))
            .collect();
        assert!(
            failed_under_path.is_empty(),
            "Expected all assertions at '{expected_path}' to pass, but found failures: {failed_under_path:?}"
        );

        let passed_under_path: Vec<_> = self
            .passed_paths()
            .into_iter()
            .filter(|p| path_is_at_or_below(p, expected_path))
            .collect();
        assert!(
            !passed_under_path.is_empty(),
            "Expected passing assertions at '{expected_path}', but no assertions matching '{expected_path}' were found!"
        );
    }

    /// Asserts that evaluation failed at exactly `expected_path`.
    pub fn assert_any_failed_at(&self, expected_path: &str) {
        let failed = self.failed_paths();
        assert!(
            self.is_err(),
            "Expected assertion failure at '{expected_path}', but evaluation passed successfully!"
        );
        let matches = failed.iter().any(|p| p == expected_path);
        assert!(
            matches,
            "Expected assertion failure at '{expected_path}', but actual failed assertion paths were: {failed:?}"
        );
    }
}

impl std::ops::Deref for EvalAssertions {
    type Target = Result<(), EvalError>;
    fn deref(&self) -> &Self::Target {
        &self.result
    }
}

impl<F: CompileField> Logic for EvalLogic<'_, F> {
    type F = F;
    type Wire = EvalWire<F>;
    type Assertions = EvalAssertions;

    fn field(&self) -> &Self::F {
        self.f
    }

    fn zero(&self) -> Self::Wire {
        EvalWire::ok(self.f.zero())
    }

    fn one(&self) -> Self::Wire {
        EvalWire::ok(self.f.one())
    }

    fn konst(&self, x: &ElementOf<F>) -> Self::Wire {
        EvalWire::ok(x.clone())
    }

    fn precious(&self, x: &Self::Wire) -> Self::Wire {
        x.clone()
    }

    fn sum(&self, xs: &[Self::Wire]) -> Self::Wire {
        let mut accu_val = self.f.zero();
        let mut accu_err = Ok(());
        let mut accu_computation_err = Ok(());
        let mut assertions = None;
        for x in xs {
            accu_val = self.f.addf(&accu_val, &x.value);
            accu_err = accu_err.and(x.error.clone());
            accu_computation_err = accu_computation_err.and(x.computation_error.clone());
            assertions = join_assertions(&assertions, &x.assertions);
        }
        EvalWire {
            value: accu_val,
            error: accu_err,
            computation_error: accu_computation_err,
            assertions,
        }
    }

    fn neg(&self, x: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.neg(&x.value),
            error: x.error.clone(),
            computation_error: x.computation_error.clone(),
            assertions: x.assertions.clone(),
        }
    }

    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.addf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
            computation_error: x.computation_error.clone().and(y.computation_error.clone()),
            assertions: join_assertions(&x.assertions, &y.assertions),
        }
    }

    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.subf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
            computation_error: x.computation_error.clone().and(y.computation_error.clone()),
            assertions: join_assertions(&x.assertions, &y.assertions),
        }
    }

    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
            computation_error: x.computation_error.clone().and(y.computation_error.clone()),
            assertions: join_assertions(&x.assertions, &y.assertions),
        }
    }

    fn mulk(&self, e: &ElementOf<F>, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(e, &y.value),
            error: y.error.clone(),
            computation_error: y.computation_error.clone(),
            assertions: y.assertions.clone(),
        }
    }

    fn quadratic(&self, e: &ElementOf<F>, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(e, &self.f.mulf(&x.value, &y.value)),
            error: x.error.clone().and(y.error.clone()),
            computation_error: x.computation_error.clone().and(y.computation_error.clone()),
            assertions: join_assertions(&x.assertions, &y.assertions),
        }
    }

    fn ok(&self) -> Self::Assertions {
        EvalAssertions {
            result: Ok(()),
            trace: None,
        }
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let own_result = x.computation_error.clone().and_then(|()| {
            if x.value.eq(&self.f.zero()) {
                Ok(())
            } else {
                let msg = format!("expected zero, got {:?}", x.value);
                Err(EvalError::AssertionFailure(msg))
            }
        });

        let status = match &own_result {
            Ok(()) => AssertionStatus::Passed,
            Err(EvalError::AssertionFailure(msg)) => AssertionStatus::Failed(msg.clone()),
        };

        let own_assertion = assertion_leaf(EvaluatedAssertion {
            path: name.to_string(),
            status,
        });
        let trace = join_assertions(&x.assertions, &own_assertion);
        let result = trace
            .as_ref()
            .and_then(|trace| trace.first_failure.clone())
            .map_or(Ok(()), Err);

        EvalAssertions { result, trace }
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let mut trace = None;
        for a in assertions {
            trace = join_assertions(&trace, &a.trace);
        }
        let trace = group_assertions(name, &trace);
        let result = trace
            .as_ref()
            .and_then(|trace| trace.first_failure.clone())
            .map_or(Ok(()), Err);
        EvalAssertions { result, trace }
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: x.value.clone(),
            error: x.error.clone().and(assertions.result),
            computation_error: x.computation_error.clone(),
            assertions: join_assertions(&x.assertions, &assertions.trace),
        }
    }

    fn to_stringw_debug(&self, x: &Self::Wire) -> String {
        format!("{:?}", x.value)
    }
}

impl<F: CompileField> crate::LogicIO for EvalLogic<'_, F> {
    fn input(&self, _position_in_input_array: usize) -> Self::Wire {
        panic!("input is not supported in EvalLogic");
    }

    fn position_in_input_array(&self, _x: &Self::Wire) -> usize {
        panic!("position_in_input_array is not supported in EvalLogic");
    }
}

impl<F: CompileField> std::fmt::Debug for EvalLogic<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalLogic").finish()
    }
}
