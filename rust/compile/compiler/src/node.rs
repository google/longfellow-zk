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
