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
use core_algebra::ElementOf;

use crate::Logic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    AssertionFailure(String),
}

pub struct EvalWire<F: CompileField> {
    pub value: ElementOf<F>,
    pub error: Result<(), EvalError>,
}

impl<F: CompileField> Clone for EvalWire<F> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            error: self.error.clone(),
        }
    }
}

impl<F: CompileField> EvalWire<F> {
    pub fn ok(value: ElementOf<F>) -> Self {
        Self {
            value,
            error: Ok(()),
        }
    }

    pub fn err(value: ElementOf<F>, err: EvalError) -> Self {
        Self {
            value,
            error: Err(err),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalAssertions {
    pub result: Result<(), EvalError>,
    pub evaluations: Vec<EvaluatedAssertion>,
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

    /// Returns path strings for all evaluated assertions.
    pub fn all_paths(&self) -> Vec<String> {
        self.evaluations.iter().map(|e| e.path.clone()).collect()
    }

    /// Returns path strings for all passing assertions.
    pub fn passed_paths(&self) -> Vec<String> {
        self.evaluations
            .iter()
            .filter(|e| matches!(e.status, AssertionStatus::Passed))
            .map(|e| e.path.clone())
            .collect()
    }

    /// Returns path strings for all failing assertions.
    pub fn failed_paths(&self) -> Vec<String> {
        self.evaluations
            .iter()
            .filter(|e| matches!(e.status, AssertionStatus::Failed(_)))
            .map(|e| e.path.clone())
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
            .filter(|p| p == expected_path || p.contains(expected_path))
            .collect();
        assert!(
            failed_under_path.is_empty(),
            "Expected all assertions at '{expected_path}' to pass, but found failures: {failed_under_path:?}"
        );

        let passed_under_path: Vec<_> = self
            .passed_paths()
            .into_iter()
            .filter(|p| p == expected_path || p.contains(expected_path))
            .collect();
        assert!(
            !passed_under_path.is_empty(),
            "Expected passing assertions at '{expected_path}', but no assertions matching '{expected_path}' were found!"
        );
    }

    /// Asserts that evaluation failed and at least one failed assertion path matches or contains
    /// `expected_path`.
    pub fn assert_any_failed_at(&self, expected_path: &str) {
        let failed = self.failed_paths();
        assert!(
            self.is_err(),
            "Expected assertion failure at '{expected_path}', but evaluation passed successfully!"
        );
        let matches = failed
            .iter()
            .any(|p| p == expected_path || p.contains(expected_path));
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
        for x in xs {
            accu_val = self.f.addf(&accu_val, &x.value);
            accu_err = accu_err.and(x.error.clone());
        }
        EvalWire {
            value: accu_val,
            error: accu_err,
        }
    }

    fn neg(&self, x: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.neg(&x.value),
            error: x.error.clone(),
        }
    }

    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.addf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
        }
    }

    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.subf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
        }
    }

    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(&x.value, &y.value),
            error: x.error.clone().and(y.error.clone()),
        }
    }

    fn mulk(&self, e: &ElementOf<F>, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(e, &y.value),
            error: y.error.clone(),
        }
    }

    fn quadratic(&self, e: &ElementOf<F>, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(e, &self.f.mulf(&x.value, &y.value)),
            error: x.error.clone().and(y.error.clone()),
        }
    }

    fn ok(&self) -> Self::Assertions {
        EvalAssertions {
            result: Ok(()),
            evaluations: Vec::new(),
        }
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        let res = x.error.clone().and_then(|()| {
            if x.value.eq(&self.f.zero()) {
                Ok(())
            } else {
                let msg = format!("expected zero, got {:?}", x.value);
                Err(EvalError::AssertionFailure(msg))
            }
        });

        let status = match &res {
            Ok(()) => AssertionStatus::Passed,
            Err(EvalError::AssertionFailure(msg)) => AssertionStatus::Failed(msg.clone()),
        };

        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let evaluations = vec![EvaluatedAssertion {
            path: name.to_string(),
            status,
        }];

        EvalAssertions {
            result: res,
            evaluations,
        }
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let mut res = Ok(());
        let mut evaluations = Vec::new();

        for a in assertions {
            if res.is_ok() {
                if let Err(e) = &a.result {
                    res = Err(e.clone());
                }
            }

            for eval in &a.evaluations {
                let new_path = if eval.path.is_empty() {
                    name.to_string()
                } else {
                    format!("{name}/{}", eval.path)
                };
                evaluations.push(EvaluatedAssertion {
                    path: new_path,
                    status: eval.status.clone(),
                });
            }
        }

        EvalAssertions {
            result: res,
            evaluations,
        }
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: x.value.clone(),
            error: x.error.clone().and(assertions.result),
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
