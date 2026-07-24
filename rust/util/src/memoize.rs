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

use std::{cell::RefCell, hash::Hash};

use rustc_hash::FxHashMap;

pub struct Memoizer<K, V> {
    cache: RefCell<FxHashMap<K, V>>,
}

impl<K, V> Memoizer<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    #[must_use]
    pub fn new() -> Self {
        Memoizer {
            cache: RefCell::new(FxHashMap::default()),
        }
    }

    pub fn get(&self, k: &K) -> Option<V> {
        self.cache.borrow().get(k).cloned()
    }

    pub fn insert(&self, k: K, v: V) {
        self.cache.borrow_mut().insert(k, v);
    }

    pub fn call<F>(&self, k: K, f: F) -> V
    where
        F: FnOnce(&K) -> V,
    {
        let cached = self.get(&k);
        if let Some(val) = cached {
            val
        } else {
            let val = f(&k);
            self.insert(k, val.clone());
            val
        }
    }
}

impl<K, V> Default for Memoizer<K, V>
where
    K: Hash + Eq,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}
