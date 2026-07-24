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

use std::{cell::RefCell, collections::HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionStatus {
    Passed,
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssertionId(u32);

pub const NIL_ASSERTION_ID: AssertionId = AssertionId(0);

impl AssertionId {
    #[inline]
    pub fn is_nil(self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ScopeId(u32);

enum ScopeNode {
    Empty,
    Cons(String, ScopeId),
}

struct ScopeTree {
    scopes: Vec<ScopeNode>,
    map: HashMap<(String, ScopeId), ScopeId>,
}

impl ScopeTree {
    fn new() -> Self {
        Self {
            scopes: vec![ScopeNode::Empty],
            map: HashMap::new(),
        }
    }

    fn empty_scope() -> ScopeId {
        ScopeId(0)
    }

    fn cons(&mut self, name: &str, parent: ScopeId) -> ScopeId {
        let key = (name.to_string(), parent);
        if let Some(&id) = self.map.get(&key) {
            return id;
        }
        let id = ScopeId(self.scopes.len() as u32);
        self.scopes.push(ScopeNode::Cons(name.to_string(), parent));
        self.map.insert(key, id);
        id
    }

    fn resolve_path(&self, mut scope_id: ScopeId) -> Vec<String> {
        let mut parts = Vec::new();
        while scope_id.0 != 0 {
            match &self.scopes[scope_id.0 as usize] {
                ScopeNode::Empty => break,
                ScopeNode::Cons(name, next) => {
                    parts.push(name.clone());
                    scope_id = *next;
                }
            }
        }
        parts
    }
}

#[derive(Debug)]
struct AssertionRecord {
    scope: ScopeId,
    representative: AssertionId,
    next: AssertionId,
}

pub struct AssertionScope {
    state: RefCell<AssertionState>,
}

struct AssertionState {
    records: Vec<AssertionRecord>,
    tree: ScopeTree,
}

impl std::fmt::Debug for AssertionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssertionScope@{:p}", self)
    }
}

impl AssertionScope {
    // --- Public API ---

    pub fn new() -> Self {
        Self {
            state: RefCell::new(AssertionState {
                records: vec![AssertionRecord {
                    scope: ScopeTree::empty_scope(),
                    representative: NIL_ASSERTION_ID,
                    next: NIL_ASSERTION_ID,
                }],
                tree: ScopeTree::new(),
            }),
        }
    }

    pub fn new_leaf(&self, name: &str) -> AssertionId {
        let mut state = self.state.borrow_mut();
        let id = AssertionId(state.records.len() as u32);
        let scope = state.tree.cons(name, ScopeTree::empty_scope());
        state.records.push(AssertionRecord {
            scope,
            representative: id,
            next: NIL_ASSERTION_ID,
        });
        id
    }

    pub fn get_path(&self, id: AssertionId) -> String {
        if id.is_nil() {
            return String::new();
        }
        let state = self.state.borrow();
        if (id.0 as usize) < state.records.len() {
            state
                .tree
                .resolve_path(state.records[id.0 as usize].scope)
                .join("/")
        } else {
            String::new()
        }
    }

    pub fn prepend_scope(&self, id: AssertionId, name: &str) {
        if id.is_nil() {
            return;
        }
        let mut state = self.state.borrow_mut();
        let rep = find_record(&state.records, id);
        if rep.is_nil() {
            return;
        }
        let mut curr = rep;
        while !curr.is_nil() {
            let parent = state.records[curr.0 as usize].scope;
            state.records[curr.0 as usize].scope = state.tree.cons(name, parent);
            curr = state.records[curr.0 as usize].next;
        }
    }

    pub fn find(&self, id: AssertionId) -> AssertionId {
        if id.is_nil() {
            return NIL_ASSERTION_ID;
        }
        find_record(&self.state.borrow().records, id)
    }

    pub fn union(&self, id1: AssertionId, id2: AssertionId) {
        if id1.is_nil() || id2.is_nil() {
            return;
        }
        let mut state = self.state.borrow_mut();
        let rep1 = find_record(&state.records, id1);
        let rep2 = find_record(&state.records, id2);

        if rep1.is_nil() || rep2.is_nil() || rep1 == rep2 {
            return;
        }

        // 1. Find tail of list 1
        let mut tail1 = rep1;
        while !state.records[tail1.0 as usize].next.is_nil() {
            tail1 = state.records[tail1.0 as usize].next;
        }

        // 2. Link tail of list 1 to rep2
        state.records[tail1.0 as usize].next = rep2;

        // 3. Update all representatives in list 2 to rep1
        let mut curr = rep2;
        while !curr.is_nil() {
            state.records[curr.0 as usize].representative = rep1;
            curr = state.records[curr.0 as usize].next;
        }
    }

    pub fn is_ok(&self, fates: &HashMap<AssertionId, AssertionStatus>) -> bool {
        fates.values().all(|s| matches!(s, AssertionStatus::Passed))
    }

    pub fn is_err(&self, fates: &HashMap<AssertionId, AssertionStatus>) -> bool {
        !self.is_ok(fates)
    }

    pub fn all_paths(&self, fates: &HashMap<AssertionId, AssertionStatus>) -> Vec<String> {
        self.query_fates("", fates)
            .into_iter()
            .map(|(path, _)| path)
            .collect()
    }

    pub fn passed_paths(&self, fates: &HashMap<AssertionId, AssertionStatus>) -> Vec<String> {
        self.query_fates("", fates)
            .into_iter()
            .filter(|(_, status)| matches!(status, AssertionStatus::Passed))
            .map(|(path, _)| path)
            .collect()
    }

    pub fn failed_paths(&self, fates: &HashMap<AssertionId, AssertionStatus>) -> Vec<String> {
        self.query_fates("", fates)
            .into_iter()
            .filter(|(_, status)| matches!(status, AssertionStatus::Failed(_)))
            .map(|(path, _)| path)
            .collect()
    }

    pub fn assert_all_passed(&self, fates: &HashMap<AssertionId, AssertionStatus>) {
        let failed = self.failed_paths(fates);
        assert!(
            self.is_ok(fates) && failed.is_empty(),
            "Expected all assertions to pass, but the following failed: {failed:?}"
        );
    }

    pub fn assert_all_passed_at(
        &self,
        expected_path: &str,
        fates: &HashMap<AssertionId, AssertionStatus>,
    ) {
        let failed_under_path: Vec<_> = self
            .query_fates(expected_path, fates)
            .into_iter()
            .filter(|(_, status)| matches!(status, AssertionStatus::Failed(_)))
            .map(|(p, _)| p)
            .collect();
        assert!(
            failed_under_path.is_empty(),
            "Expected all assertions at '{expected_path}' to pass, but found failures: {failed_under_path:?}"
        );

        let passed_under_path: Vec<_> = self
            .query_fates(expected_path, fates)
            .into_iter()
            .filter(|(_, status)| matches!(status, AssertionStatus::Passed))
            .map(|(p, _)| p)
            .collect();
        assert!(
            !passed_under_path.is_empty(),
            "Expected passing assertions at '{expected_path}', but no assertions matching '{expected_path}' were found!"
        );
    }

    pub fn assert_any_failed_at(
        &self,
        expected_path: &str,
        fates: &HashMap<AssertionId, AssertionStatus>,
    ) {
        assert!(
            self.is_err(fates),
            "Expected assertion failure at '{expected_path}', but evaluation passed successfully!"
        );
        let fates_res = self.query_fates(expected_path, fates);
        let matches = fates_res.iter().any(|(p, _)| p == expected_path);
        assert!(
            matches,
            "Expected assertion failure at '{expected_path}', but actual failed assertion paths were: {fates_res:?}"
        );
    }

    // --- Private Helpers ---

    fn query_fates(
        &self,
        path_prefix: &str,
        fates: &HashMap<AssertionId, AssertionStatus>,
    ) -> Vec<(String, AssertionStatus)> {
        let mut results = Vec::new();
        let state = self.state.borrow();
        let mut sorted_fates: Vec<_> = fates.iter().collect();
        sorted_fates.sort_by_key(|(id, _)| id.0);

        // A unioned assertion group has one logical outcome.  Aggregate all
        // aliases before rendering paths so a later failure cannot be hidden
        // by an earlier passing alias.
        let mut group_fates = HashMap::new();
        let mut reps = Vec::new();
        for (id, fate) in sorted_fates {
            let rep = find_record(&state.records, *id);
            if rep.is_nil() {
                continue;
            }
            if !group_fates.contains_key(&rep) {
                reps.push(rep);
                group_fates.insert(rep, fate.clone());
            } else if matches!(fate, AssertionStatus::Failed(_)) {
                group_fates.insert(rep, fate.clone());
            }
        }

        for rep in reps {
            let fate = &group_fates[&rep];
            let mut curr = rep;
            while !curr.is_nil() {
                let rec = &state.records[curr.0 as usize];
                let full_path = state.tree.resolve_path(rec.scope).join("/");
                if path_matches(&full_path, path_prefix) {
                    results.push((full_path, fate.clone()));
                }
                curr = rec.next;
            }
        }
        results
    }
}

impl Default for AssertionScope {
    fn default() -> Self {
        Self::new()
    }
}

fn find_record(records: &[AssertionRecord], id: AssertionId) -> AssertionId {
    if id.is_nil() || (id.0 as usize) >= records.len() {
        NIL_ASSERTION_ID
    } else {
        records[id.0 as usize].representative
    }
}

fn path_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || prefix.is_empty()
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
