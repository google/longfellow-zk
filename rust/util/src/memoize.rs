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
    where F: FnOnce(&K) -> V {
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
