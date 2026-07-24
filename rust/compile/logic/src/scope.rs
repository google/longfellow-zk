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
    children: HashMap<ScopeId, HashMap<String, ScopeId>>,
}

impl ScopeTree {
    fn new() -> Self {
        Self {
            scopes: vec![ScopeNode::Empty],
            children: HashMap::new(),
        }
    }

    fn empty_scope() -> ScopeId {
        ScopeId(0)
    }

    fn cons(&mut self, name: &str, parent: ScopeId) -> ScopeId {
        if let Some(child_map) = self.children.get(&parent) {
            if let Some(&id) = child_map.get(name) {
                return id;
            }
        }
        let id = ScopeId(self.scopes.len() as u32);
        self.scopes.push(ScopeNode::Cons(name.to_string(), parent));
        self.children
            .entry(parent)
            .or_default()
            .insert(name.to_string(), id);
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

#[derive(Debug, Clone)]
struct AssertionRecord {
    scope: ScopeId,
    parent: AssertionId,
}

pub struct AssertionScope {
    state: RefCell<AssertionState>,
}

struct AssertionState {
    records: Vec<AssertionRecord>,
    members: HashMap<AssertionId, Vec<AssertionId>>,
    tree: ScopeTree,
}

impl std::fmt::Debug for AssertionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssertionScope@{:p}", self)
    }
}

impl AssertionScope {
    pub fn new() -> Self {
        Self {
            state: RefCell::new(AssertionState {
                records: vec![AssertionRecord {
                    scope: ScopeTree::empty_scope(),
                    parent: NIL_ASSERTION_ID,
                }],
                members: HashMap::new(),
                tree: ScopeTree::new(),
            }),
        }
    }

    pub fn new_leaf(&self, name: &str) -> AssertionId {
        let mut state = self.state.borrow_mut();
        let id = AssertionId(state.records.len() as u32);
        let scope = state.tree.cons(name, ScopeTree::empty_scope());
        state.records.push(AssertionRecord { scope, parent: id });
        state.members.insert(id, vec![id]);
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
        let rep = find_rep(&mut state.records, id);
        if rep.is_nil() {
            return;
        }
        if let Some(members) = state.members.get(&rep).cloned() {
            for member_id in members {
                let parent = state.records[member_id.0 as usize].scope;
                state.records[member_id.0 as usize].scope = state.tree.cons(name, parent);
            }
        }
    }

    pub fn find(&self, id: AssertionId) -> AssertionId {
        if id.is_nil() {
            return NIL_ASSERTION_ID;
        }
        find_rep(&mut self.state.borrow_mut().records, id)
    }

    pub fn union(&self, id1: AssertionId, id2: AssertionId) {
        if id1.is_nil() || id2.is_nil() {
            return;
        }
        let mut state = self.state.borrow_mut();
        let rep1 = find_rep(&mut state.records, id1);
        let rep2 = find_rep(&mut state.records, id2);

        if rep1.is_nil() || rep2.is_nil() || rep1 == rep2 {
            return;
        }

        // DSU Union: point rep2's parent to rep1
        state.records[rep2.0 as usize].parent = rep1;

        // Transfer members of rep2 to rep1
        if let Some(mut m2) = state.members.remove(&rep2) {
            state.members.entry(rep1).or_default().append(&mut m2);
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

    fn query_fates(
        &self,
        path_prefix: &str,
        fates: &HashMap<AssertionId, AssertionStatus>,
    ) -> Vec<(String, AssertionStatus)> {
        let mut results = Vec::new();
        let mut state = self.state.borrow_mut();
        let mut sorted_fates: Vec<_> = fates.iter().collect();
        sorted_fates.sort_by_key(|(id, _)| id.0);

        let mut group_fates = HashMap::new();
        let mut reps = Vec::new();
        for (id, fate) in sorted_fates {
            let rep = find_rep(&mut state.records, *id);
            if rep.is_nil() {
                continue;
            }
            match group_fates.entry(rep) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    reps.push(rep);
                    e.insert(fate.clone());
                }
                std::collections::hash_map::Entry::Occupied(mut e) => if matches!(fate, AssertionStatus::Failed(_)) {
                    e.insert(fate.clone());
                }
            }
        }

        for rep in reps {
            let fate = &group_fates[&rep];
            if let Some(members) = state.members.get(&rep).cloned() {
                for member_id in members {
                    let rec = &state.records[member_id.0 as usize];
                    let full_path = state.tree.resolve_path(rec.scope).join("/");
                    if path_matches(&full_path, path_prefix) {
                        results.push((full_path, fate.clone()));
                    }
                }
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

fn find_rep(records: &mut [AssertionRecord], id: AssertionId) -> AssertionId {
    if id.is_nil() || (id.0 as usize) >= records.len() {
        return NIL_ASSERTION_ID;
    }
    let mut root = id;
    while records[root.0 as usize].parent != root && !records[root.0 as usize].parent.is_nil() {
        root = records[root.0 as usize].parent;
    }
    let mut curr = id;
    while curr != root && !curr.is_nil() {
        let nxt = records[curr.0 as usize].parent;
        records[curr.0 as usize].parent = root;
        curr = nxt;
    }
    root
}

fn path_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || prefix.is_empty()
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
