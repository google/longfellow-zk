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

use std::{collections::HashMap, ops::Deref, sync::Arc};

use compile_algebra::field::CompileField;
use core_algebra::ElementOf;

use crate::{
    scope::{AssertionId, AssertionScope, AssertionStatus},
    Logic,
};

#[derive(Clone, Debug, Default)]
pub struct AssertionMap(Arc<HashMap<AssertionId, AssertionStatus>>);

impl Deref for AssertionMap {
    type Target = HashMap<AssertionId, AssertionStatus>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AssertionMap {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, id: AssertionId, status: AssertionStatus) {
        Arc::make_mut(&mut self.0).insert(id, status);
    }
}

impl IntoIterator for AssertionMap {
    type Item = (AssertionId, AssertionStatus);
    type IntoIter = std::collections::hash_map::IntoIter<AssertionId, AssertionStatus>;

    fn into_iter(self) -> Self::IntoIter {
        match Arc::try_unwrap(self.0) {
            Ok(map) => map.into_iter(),
            Err(shared) => (*shared).clone().into_iter(),
        }
    }
}

impl Extend<(AssertionId, AssertionStatus)> for AssertionMap {
    fn extend<T: IntoIterator<Item = (AssertionId, AssertionStatus)>>(&mut self, iter: T) {
        Arc::make_mut(&mut self.0).extend(iter);
    }
}

pub struct EvalWire<F: CompileField> {
    pub value: ElementOf<F>,
    pub assertions: AssertionMap,
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
        Self::new(value, AssertionMap::new())
    }

    fn new(value: ElementOf<F>, assertions: AssertionMap) -> Self {
        Self { value, assertions }
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
    tracker: &'a AssertionScope,
}

/// Owns the assertion scope for one direct-evaluation session.
pub struct EvalContext<'a, F: CompileField> {
    f: &'a F,
    tracker: AssertionScope,
}

impl<'a, F: CompileField> EvalContext<'a, F> {
    pub fn new(f: &'a F) -> Self {
        Self {
            f,
            tracker: AssertionScope::new(),
        }
    }

    pub fn run<'ctx>(
        &'ctx self,
        build: impl FnOnce(&EvalLogic<'ctx, F>) -> EvalAssertions<'ctx>,
    ) -> EvalAssertions<'ctx> {
        let logic = EvalLogic::new(self.f, &self.tracker);
        build(&logic)
    }
}

impl<'a, F: CompileField> EvalLogic<'a, F> {
    pub fn new(f: &'a F, tracker: &'a AssertionScope) -> Self {
        Self { f, tracker }
    }

    pub fn new_with_tracker(f: &'a F, tracker: &'a AssertionScope) -> Self {
        Self::new(f, tracker)
    }

    fn wire(&self, value: ElementOf<F>, assertions: AssertionMap) -> EvalWire<F> {
        EvalWire::new(value, assertions)
    }

    fn combine(&self, x: &EvalWire<F>, y: &EvalWire<F>, value: ElementOf<F>) -> EvalWire<F> {
        let assertions = merge_assertions(&x.assertions, &y.assertions);
        self.wire(value, assertions)
    }

    fn result(&self, scoped: AssertionMap, unscoped: AssertionMap) -> EvalAssertions<'a> {
        EvalAssertions {
            scoped,
            unscoped,
            tracker: self.tracker,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvalAssertions<'a> {
    pub scoped: AssertionMap,
    pub unscoped: AssertionMap,
    pub tracker: &'a AssertionScope,
}

impl<'a> EvalAssertions<'a> {
    pub fn all_items(&self) -> AssertionMap {
        merge_assertions(&self.scoped, &self.unscoped)
    }

    pub fn is_ok(&self) -> bool {
        self.tracker.is_ok(&self.all_items())
    }

    pub fn is_err(&self) -> bool {
        self.tracker.is_err(&self.all_items())
    }

    pub fn unwrap(self) {
        self.assert_all_passed();
    }

    pub fn failed_paths(&self) -> Vec<String> {
        self.tracker.failed_paths(&self.all_items())
    }

    pub fn all_paths(&self) -> Vec<String> {
        self.tracker.all_paths(&self.all_items())
    }

    pub fn passed_paths(&self) -> Vec<String> {
        self.tracker.passed_paths(&self.all_items())
    }

    pub fn assert_all_passed(&self) {
        self.tracker.assert_all_passed(&self.all_items());
    }

    pub fn assert_any_failed_at(&self, expected_path: &str) {
        self.tracker
            .assert_any_failed_at(expected_path, &self.all_items());
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
        self.wire(self.f.zero(), AssertionMap::new())
    }

    fn one(&self) -> Self::Wire {
        self.wire(self.f.one(), AssertionMap::new())
    }

    fn konst(&self, x: &ElementOf<F>) -> Self::Wire {
        self.wire(x.clone(), AssertionMap::new())
    }

    fn precious(&self, x: &Self::Wire) -> Self::Wire {
        x.clone()
    }

    fn sum(&self, xs: &[Self::Wire]) -> Self::Wire {
        let mut val = self.f.zero();
        let mut assertions = AssertionMap::new();
        for x in xs {
            val = self.f.addf(&val, &x.value);
            assertions = merge_assertions(&assertions, &x.assertions);
        }
        self.wire(val, assertions)
    }

    fn neg(&self, x: &Self::Wire) -> Self::Wire {
        self.wire(self.f.neg(&x.value), x.assertions.clone())
    }

    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.combine(x, y, self.f.addf(&x.value, &y.value))
    }

    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.combine(x, y, self.f.subf(&x.value, &y.value))
    }

    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.combine(x, y, self.f.mulf(&x.value, &y.value))
    }

    fn mulk(&self, e: &ElementOf<F>, y: &Self::Wire) -> Self::Wire {
        self.wire(self.f.mulf(e, &y.value), y.assertions.clone())
    }

    fn quadratic(&self, e: &ElementOf<F>, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.combine(x, y, self.f.mulf(e, &self.f.mulf(&x.value, &y.value)))
    }

    fn ok(&self) -> Self::Assertions {
        self.result(AssertionMap::new(), AssertionMap::new())
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let status = if x.value.eq(&self.f.zero()) {
            AssertionStatus::Passed
        } else {
            AssertionStatus::Failed(format!("expected zero, got {:?}", x.value))
        };
        let id = self.tracker.new_leaf(name);
        let mut scoped = AssertionMap::new();
        scoped.insert(id, status);
        self.result(scoped, x.assertions.clone())
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let mut scoped = AssertionMap::new();
        let mut unscoped = AssertionMap::new();
        for a in assertions {
            scoped = merge_assertions(&scoped, &a.scoped);
            unscoped = merge_assertions(&unscoped, &a.unscoped);
        }
        for &id in scoped.keys() {
            self.tracker.prepend_scope(id, name);
        }
        self.result(scoped, unscoped)
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        let attached = merge_assertions(&assertions.scoped, &assertions.unscoped);
        let new_unscoped = merge_assertions(&x.assertions, &attached);
        self.wire(x.value.clone(), new_unscoped)
    }

    fn to_stringw_debug(&self, x: &Self::Wire) -> String {
        format!("{:?}", x.value)
    }
}

fn merge_assertions(left: &AssertionMap, right: &AssertionMap) -> AssertionMap {
    if left.is_empty() {
        return right.clone();
    }
    if right.is_empty() {
        return left.clone();
    }

    let mut merged = left.clone();
    Arc::make_mut(&mut merged.0).extend(right.iter().map(|(&id, status)| (id, status.clone())));
    merged
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
