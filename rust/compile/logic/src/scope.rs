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

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

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
    scopes: RefCell<Vec<ScopeNode>>,
    map: RefCell<HashMap<(String, ScopeId), ScopeId>>,
}

impl ScopeTree {
    fn new() -> Self {
        Self {
            scopes: RefCell::new(vec![ScopeNode::Empty]),
            map: RefCell::new(HashMap::new()),
        }
    }

    fn empty_scope() -> ScopeId {
        ScopeId(0)
    }

    fn cons(&self, name: &str, parent: ScopeId) -> ScopeId {
        let mut map = self.map.borrow_mut();
        let key = (name.to_string(), parent);
        if let Some(&id) = map.get(&key) {
            return id;
        }
        let mut scopes = self.scopes.borrow_mut();
        let id = ScopeId(scopes.len() as u32);
        scopes.push(ScopeNode::Cons(name.to_string(), parent));
        map.insert(key, id);
        id
    }

    fn resolve_path(&self, mut scope_id: ScopeId) -> Vec<String> {
        let mut parts = Vec::new();
        let scopes = self.scopes.borrow();
        while scope_id.0 != 0 {
            match &scopes[scope_id.0 as usize] {
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
    representative: AssertionId,
    next: AssertionId,
}

pub struct AssertionScope {
    records: RefCell<Vec<AssertionRecord>>,
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
            records: RefCell::new(vec![AssertionRecord {
                scope: ScopeTree::empty_scope(),
                representative: NIL_ASSERTION_ID,
                next: NIL_ASSERTION_ID,
            }]),
            tree: ScopeTree::new(),
        }
    }

    pub fn new_leaf(&self, name: &str) -> AssertionId {
        let mut records = self.records.borrow_mut();
        let id = AssertionId(records.len() as u32);
        let scope = self.tree.cons(name, ScopeTree::empty_scope());
        records.push(AssertionRecord {
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
        let records = self.records.borrow();
        if (id.0 as usize) < records.len() {
            self.tree
                .resolve_path(records[id.0 as usize].scope)
                .join("/")
        } else {
            String::new()
        }
    }

    pub fn prepend_scope(&self, id: AssertionId, name: &str) {
        if id.is_nil() {
            return;
        }
        let rep = self.find(id);
        if rep.is_nil() {
            return;
        }
        let mut records = self.records.borrow_mut();
        let mut curr = rep;
        while !curr.is_nil() {
            let rec = &mut records[curr.0 as usize];
            rec.scope = self.tree.cons(name, rec.scope);
            curr = rec.next;
        }
    }

    pub fn find(&self, id: AssertionId) -> AssertionId {
        if id.is_nil() {
            return NIL_ASSERTION_ID;
        }
        let records = self.records.borrow();
        if (id.0 as usize) < records.len() {
            records[id.0 as usize].representative
        } else {
            NIL_ASSERTION_ID
        }
    }

    pub fn union(&self, id1: AssertionId, id2: AssertionId) {
        if id1.is_nil() || id2.is_nil() {
            return;
        }
        let rep1 = self.find(id1);
        let rep2 = self.find(id2);

        if rep1.is_nil() || rep2.is_nil() || rep1 == rep2 {
            return;
        }

        let mut records = self.records.borrow_mut();

        // 1. Find tail of list 1
        let mut tail1 = rep1;
        while !records[tail1.0 as usize].next.is_nil() {
            tail1 = records[tail1.0 as usize].next;
        }

        // 2. Link tail of list 1 to rep2
        records[tail1.0 as usize].next = rep2;

        // 3. Update all representatives in list 2 to rep1
        let mut curr = rep2;
        while !curr.is_nil() {
            records[curr.0 as usize].representative = rep1;
            curr = records[curr.0 as usize].next;
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
        let records = self.records.borrow();
        let mut visited_reps = HashSet::new();

        let mut sorted_fates: Vec<_> = fates.iter().collect();
        sorted_fates.sort_by_key(|(id, _)| id.0);

        for (id, fate) in sorted_fates {
            let rep = if (id.0 as usize) < records.len() {
                records[id.0 as usize].representative
            } else {
                NIL_ASSERTION_ID
            };

            if rep.is_nil() || !visited_reps.insert(rep) {
                continue;
            }

            let mut curr = rep;
            while !curr.is_nil() {
                let rec = &records[curr.0 as usize];
                let full_path = self.tree.resolve_path(rec.scope).join("/");
                if path_prefix.is_empty()
                    || full_path == path_prefix
                    || full_path.starts_with(&format!("{}/", path_prefix))
                {
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
