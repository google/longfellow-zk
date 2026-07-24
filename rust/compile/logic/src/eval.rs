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

use compile_algebra::field::CompileField;
use core_algebra::ElementOf;

use crate::Logic;

pub struct EvalWire<F: CompileField> {
    pub value: ElementOf<F>,
    pub assertions:
        std::collections::HashMap<crate::scope::AssertionId, crate::scope::AssertionStatus>,
}

impl<F: CompileField> Clone for EvalWire<F> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            assertions: self.assertions.clone(),
        }
    }
}

impl<F: CompileField> EvalWire<F> {
    pub fn ok(value: ElementOf<F>) -> Self {
        Self {
            value,
            assertions: std::collections::HashMap::new(),
        }
    }
}

impl<F: CompileField> PartialEq for EvalWire<F> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<F: CompileField> Eq for EvalWire<F> {}

impl<F: CompileField> std::fmt::Debug for EvalWire<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvalWire")
            .field("value", &self.value)
            .field("has_attached_assertions", &!self.assertions.is_empty())
            .finish()
    }
}

pub struct EvalLogic<'a, F: CompileField> {
    f: &'a F,
    pub tracker: &'a crate::scope::AssertionScope,
}

impl<'a, F: CompileField> EvalLogic<'a, F> {
    pub fn new(f: &'a F, tracker: &'a crate::scope::AssertionScope) -> Self {
        Self { f, tracker }
    }

    pub fn new_with_tracker(f: &'a F, tracker: &'a crate::scope::AssertionScope) -> Self {
        Self::new(f, tracker)
    }
}

use crate::scope::AssertionId;

#[derive(Debug, Clone)]
pub struct EvalAssertions<'a> {
    pub items: std::collections::HashMap<AssertionId, crate::scope::AssertionStatus>,
    pub tracker: &'a crate::scope::AssertionScope,
}

impl<'a> EvalAssertions<'a> {
    pub fn is_ok(&self) -> bool {
        self.tracker.is_ok(&self.items)
    }

    pub fn is_err(&self) -> bool {
        self.tracker.is_err(&self.items)
    }

    pub fn unwrap(self) {
        self.assert_all_passed();
    }

    pub fn failed_paths(&self) -> Vec<String> {
        self.tracker.failed_paths(&self.items)
    }

    pub fn assert_all_passed(&self) {
        self.tracker.assert_all_passed(&self.items);
    }

    pub fn assert_any_failed_at(&self, expected_path: &str) {
        self.tracker
            .assert_any_failed_at(expected_path, &self.items);
    }
}

impl<'a, F: CompileField> Logic for EvalLogic<'a, F> {
    type F = F;
    type Wire = EvalWire<F>;
    type Assertions = EvalAssertions<'a>;

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
        let mut assertions = std::collections::HashMap::new();
        for x in xs {
            accu_val = self.f.addf(&accu_val, &x.value);
            assertions.extend(x.assertions.clone());
        }
        EvalWire {
            value: accu_val,
            assertions,
        }
    }

    fn neg(&self, x: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.neg(&x.value),
            assertions: x.assertions.clone(),
        }
    }

    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        let mut assertions = x.assertions.clone();
        assertions.extend(y.assertions.clone());
        EvalWire {
            value: self.f.addf(&x.value, &y.value),
            assertions,
        }
    }

    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        let mut assertions = x.assertions.clone();
        assertions.extend(y.assertions.clone());
        EvalWire {
            value: self.f.subf(&x.value, &y.value),
            assertions,
        }
    }

    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        let mut assertions = x.assertions.clone();
        assertions.extend(y.assertions.clone());
        EvalWire {
            value: self.f.mulf(&x.value, &y.value),
            assertions,
        }
    }

    fn mulk(&self, e: &ElementOf<F>, y: &Self::Wire) -> Self::Wire {
        EvalWire {
            value: self.f.mulf(e, &y.value),
            assertions: y.assertions.clone(),
        }
    }

    fn quadratic(&self, e: &ElementOf<F>, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        let mut assertions = x.assertions.clone();
        assertions.extend(y.assertions.clone());
        EvalWire {
            value: self.f.mulf(e, &self.f.mulf(&x.value, &y.value)),
            assertions,
        }
    }

    fn ok(&self) -> Self::Assertions {
        EvalAssertions {
            items: std::collections::HashMap::new(),
            tracker: self.tracker,
        }
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let status = if x.value.eq(&self.f.zero()) {
            crate::scope::AssertionStatus::Passed
        } else {
            crate::scope::AssertionStatus::Failed(format!("expected zero, got {:?}", x.value))
        };
        let id = self.tracker.new_leaf(name);
        let mut items = x.assertions.clone();
        items.insert(id, status);
        EvalAssertions {
            items,
            tracker: self.tracker,
        }
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let mut items = std::collections::HashMap::new();
        for a in assertions {
            items.extend(a.items.clone());
        }
        for &id in items.keys() {
            self.tracker.prepend_scope(id, name);
        }
        EvalAssertions {
            items,
            tracker: self.tracker,
        }
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        let mut new_assertions = x.assertions.clone();
        new_assertions.extend(assertions.items);
        EvalWire {
            value: x.value.clone(),
            assertions: new_assertions,
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
