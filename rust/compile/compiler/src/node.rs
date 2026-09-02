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
    fmt,
    hash::{Hash, Hasher},
};

pub struct Node<'a, T> {
    pub id: usize,
    pub v: T,
    pub depth: usize,
    _marker: std::marker::PhantomData<&'a T>,
}

impl<T> fmt::Debug for Node<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node#{}@{:p}", self.id, self)
    }
}

impl<T> Node<'_, T> {
    pub fn new(id: usize, v: T, depth: usize) -> Self {
        Node {
            id,
            v,
            depth,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Eq for Node<'_, T> {}

impl<T> PartialEq for Node<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        let eq = self.id == other.id;
        assert_eq!(
            eq,
            std::ptr::eq(self, other),
            "ID equality and pointer equality must match"
        );
        eq
    }
}

impl<T> Hash for Node<'_, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<T> Ord for Node<'_, T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let ord = self.id.cmp(&other.id);
        assert_eq!(
            ord == std::cmp::Ordering::Equal,
            std::ptr::eq(self, other),
            "Ordering equality and pointer equality must match"
        );
        ord
    }
}

impl<T> PartialOrd for Node<'_, T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
