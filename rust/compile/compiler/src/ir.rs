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

use std::{fmt, hash::Hash};

use compile_algebra::field::CompileField;

use crate::node::Node;

#[derive(Debug)]
pub enum IrError {
    NotAnInput,
}

pub type ExprNode<'a, F> = &'a Node<'a, Expr<'a, F>>;
pub type RawAssertions<'a, F> = &'a [ExprNode<'a, F>];

/// Scope tree node stored in the compiler's bump arena as a first-class Node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope<'a> {
    Empty,
    Cons(&'a str, ScopeRef<'a>),
}

pub type ScopeRef<'a> = &'a Node<'a, Scope<'a>>;

impl<'a> Node<'a, Scope<'a>> {
    pub fn to_path(&self) -> Vec<String> {
        let mut path = Vec::new();
        let mut current = self;
        while let Scope::Cons(name, parent) = &current.v {
            if !name.is_empty() {
                path.push(name.to_string());
            }
            current = parent;
        }
        path
    }
}

/// Lightweight assertion item reference used during circuit construction before path resolution.
#[derive(Debug)]
pub struct AssertionItemRef<'a, F: CompileField> {
    pub expr: ExprNode<'a, F>,
    pub scope: ScopeRef<'a>,
}

impl<'a, F: CompileField> Clone for AssertionItemRef<'a, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, F: CompileField> Copy for AssertionItemRef<'a, F> {}

impl<'a, F: CompileField> PartialEq for AssertionItemRef<'a, F> {
    fn eq(&self, other: &Self) -> bool {
        self.expr == other.expr
    }
}

impl<'a, F: CompileField> Eq for AssertionItemRef<'a, F> {}

impl<'a, F: CompileField> AssertionItemRef<'a, F> {
    pub fn to_item(&self) -> AssertionItem<'a, F> {
        AssertionItem {
            expr: self.expr,
            path: self.scope.to_path(),
        }
    }
}

/// Assertion item coupling a root assertion expression with its scope path.
#[derive(Debug)]
pub struct AssertionItem<'a, F: CompileField> {
    pub expr: ExprNode<'a, F>,
    pub path: Vec<String>,
}

impl<'a, F: CompileField> Clone for AssertionItem<'a, F> {
    fn clone(&self) -> Self {
        Self {
            expr: self.expr,
            path: self.path.clone(),
        }
    }
}

impl<'a, F: CompileField> PartialEq for AssertionItem<'a, F> {
    fn eq(&self, other: &Self) -> bool {
        self.expr == other.expr
    }
}

impl<'a, F: CompileField> Eq for AssertionItem<'a, F> {}

pub type Assertions<'a, F> = &'a [AssertionItem<'a, F>];

pub enum Expr<'a, F: CompileField> {
    Input(usize),
    // Slices are allocated directly in the compiler's arena (`bumpalo::Bump`)
    // instead of heap-allocated `Vec` to avoid massive
    // allocation/deallocation overhead.
    Sum(&'a [ExprNode<'a, F>], bool),
    One,
    // Representation of terms. In theory this is all redundant, and
    // One and Quadratic would be sufficient. In practice it is
    // easier to pattern match on Constant and Linear to extract
    // constants, so we accept the redundancy.
    Constant(&'a F::E),
    Linear(&'a F::E, ExprNode<'a, F>),
    Quadratic(&'a F::E, ExprNode<'a, F>, ExprNode<'a, F>),
    // Slices are allocated directly in the compiler's arena (`bumpalo::Bump`)
    // instead of heap-allocated `BTreeSet` to avoid allocation/deallocation
    // overhead.
    WithAssertions(RawAssertions<'a, F>, ExprNode<'a, F>),
}

impl<F: CompileField> Copy for Expr<'_, F> {}

impl<F: CompileField> Clone for Expr<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: CompileField> PartialEq for Expr<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Expr::Input(a), Expr::Input(b)) => a == b,
            (Expr::Sum(a, da), Expr::Sum(b, db)) => a == b && da == db,
            (Expr::One, Expr::One) => true,
            (Expr::Constant(a), Expr::Constant(b)) => std::ptr::eq(*a, *b) || *a == *b,
            (Expr::Linear(ea, xa), Expr::Linear(eb, xb)) => {
                (std::ptr::eq(*ea, *eb) || *ea == *eb) && xa == xb
            }
            (Expr::Quadratic(ea, xa, ya), Expr::Quadratic(eb, xb, yb)) => {
                (std::ptr::eq(*ea, *eb) || *ea == *eb) && xa == xb && ya == yb
            }
            (Expr::WithAssertions(aa, xa), Expr::WithAssertions(ab, xb)) => aa == ab && xa == xb,
            _ => false,
        }
    }
}

impl<F: CompileField> Eq for Expr<'_, F> {}

impl<F: CompileField> Hash for Expr<'_, F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Expr::Input(w) => w.hash(state),
            Expr::Sum(l, precious) => {
                l.hash(state);
                precious.hash(state);
            }
            Expr::One => {}
            Expr::Constant(e) => (*e).hash(state),
            Expr::Linear(e, x) => {
                (*e).hash(state);
                x.hash(state);
            }
            Expr::Quadratic(e, x, y) => {
                (*e).hash(state);
                x.hash(state);
                y.hash(state);
            }
            Expr::WithAssertions(a, x) => {
                a.hash(state);
                x.hash(state);
            }
        }
    }
}

impl<F: CompileField> fmt::Display for Expr<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Input(a) => write!(f, "In({a})"),
            Expr::Sum(l, precious) => {
                let p_str = if *precious { "p:" } else { "" };
                write!(f, "{p_str}Sum([")?;
                for (i, x) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", x.id)?;
                }
                write!(f, "])")
            }
            Expr::One => write!(f, "1"),
            Expr::Constant(e) => write!(f, "C({e:?})"),
            Expr::Linear(e, x) => write!(f, "L({e:?} * {})", x.id),
            Expr::Quadratic(e, x, y) => write!(f, "Q({e:?} * {} * {})", x.id, y.id),
            Expr::WithAssertions(a, x) => write!(f, "WithAssertions({a:?}, {})", x.id),
        }
    }
}

/// Note: This general version of `depth_term` is used before and
/// during compiler passes, allowing non-termified nodes (like
/// `Constant`, `Linear`, and `Delay`) by falling back to
/// `node.depth`. For post-termification passes (like copy
/// propagation), a stricter version is used in `copy.rs` to assert
/// compiler invariants.
pub fn depth_term<F: CompileField>(node: &ExprNode<'_, F>) -> usize {
    match &node.v {
        Expr::Input(_) | Expr::One | Expr::Constant(_) => 1,
        _ => node.depth,
    }
}

pub fn depth_expr<F: CompileField>(expr: &Expr<'_, F>) -> usize {
    match expr {
        Expr::Input(_) | Expr::One | Expr::Constant(_) => 0,
        Expr::Linear(_, x) => 1 + x.depth,
        Expr::Quadratic(_, x, y) => 1 + std::cmp::max(x.depth, y.depth),
        Expr::WithAssertions(a, x) => {
            let a_depth = a.iter().map(|item| item.depth).max().unwrap_or(0);
            std::cmp::max(a_depth, x.depth)
        }
        Expr::Sum(elements, _) => elements.iter().map(depth_term).max().unwrap_or(0),
    }
}

pub fn extract_assertions<'a, F: CompileField>(
    x: &ExprNode<'a, F>,
) -> (Vec<RawAssertions<'a, F>>, ExprNode<'a, F>) {
    let mut current = *x;
    let assertions = std::iter::from_fn(|| {
        if let Expr::WithAssertions(a, y) = &current.v {
            let res = *a;
            current = *y;
            Some(res)
        } else {
            None
        }
    })
    .collect();
    (assertions, current)
}

pub fn position_in_input_array<F: CompileField>(x: &ExprNode<'_, F>) -> Result<usize, IrError> {
    let (_, xx) = extract_assertions(x);
    match &xx.v {
        Expr::Input(n) => Ok(*n),
        _ => Err(IrError::NotAnInput),
    }
}

// Type of IR rewriters.
pub trait RewriteT<'a, F: CompileField> {
    fn ok(&self) -> RawAssertions<'a, F>;
    fn assert0(&self, x: &ExprNode<'a, F>) -> RawAssertions<'a, F>;
    fn assertions(&self, assertions: &[RawAssertions<'a, F>]) -> RawAssertions<'a, F>;
    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F>;
    fn sum(&self, elements: &[ExprNode<'a, F>], precious: bool) -> ExprNode<'a, F>;
    fn one(&self) -> ExprNode<'a, F>;
    fn constant(&self, elt: &F::E) -> ExprNode<'a, F>;
    fn linear(&self, elt: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F>;
    fn quadratic(&self, elt: &F::E, x: &ExprNode<'a, F>, y: &ExprNode<'a, F>) -> ExprNode<'a, F>;
    fn with_assertions(
        &self,
        assertions: &RawAssertions<'a, F>,
        x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F>;
    fn empty_scope(&self) -> ScopeRef<'a>;
    fn push(&self, name: &'a str, parent: ScopeRef<'a>) -> ScopeRef<'a>;
}

impl<'a, F: CompileField, T: RewriteT<'a, F>> RewriteT<'a, F> for &T {
    fn ok(&self) -> RawAssertions<'a, F> {
        (*self).ok()
    }
    fn assert0(&self, x: &ExprNode<'a, F>) -> RawAssertions<'a, F> {
        (*self).assert0(x)
    }
    fn assertions(&self, assertions: &[RawAssertions<'a, F>]) -> RawAssertions<'a, F> {
        (*self).assertions(assertions)
    }
    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F> {
        (*self).input(position_in_input_array)
    }
    fn sum(&self, elements: &[ExprNode<'a, F>], precious: bool) -> ExprNode<'a, F> {
        (*self).sum(elements, precious)
    }
    fn one(&self) -> ExprNode<'a, F> {
        (*self).one()
    }
    fn constant(&self, elt: &F::E) -> ExprNode<'a, F> {
        (*self).constant(elt)
    }
    fn linear(&self, elt: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        (*self).linear(elt, x)
    }
    fn quadratic(&self, elt: &F::E, x: &ExprNode<'a, F>, y: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        (*self).quadratic(elt, x, y)
    }
    fn with_assertions(
        &self,
        assertions: &RawAssertions<'a, F>,
        x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        (*self).with_assertions(assertions, x)
    }
    fn empty_scope(&self) -> ScopeRef<'a> {
        (*self).empty_scope()
    }
    fn push(&self, name: &'a str, parent: ScopeRef<'a>) -> ScopeRef<'a> {
        (*self).push(name, parent)
    }
}

/// Recursively walks the expression/assertion tree from input arena ('a) to target arena ('b).
pub fn walk<'a, 'b, F: CompileField, NEXT: RewriteT<'b, F>>(
    arena: &'b crate::CompilerArena<'b, F>,
    assertions: Assertions<'a, F>,
    rewriter: &NEXT,
) -> Assertions<'b, F> {
    fn children<F: CompileField>(node: ExprNode<'_, F>) -> Vec<ExprNode<'_, F>> {
        match &node.v {
            Expr::Input(_) | Expr::One | Expr::Constant(_) => Vec::new(),
            Expr::Sum(list, _) => list.to_vec(),
            Expr::Linear(_, x) => vec![*x],
            Expr::Quadratic(_, x, y) => vec![*x, *y],
            Expr::WithAssertions(a, x) => {
                let mut children = vec![*x];
                children.extend(a.iter().copied());
                children
            }
        }
    }

    // Single-pass post-order DFS walk using a heap-allocated stack
    let mut visited = Vec::new();
    let mut cache: Vec<Option<ExprNode<'b, F>>> = Vec::new();
    let mut stack = Vec::new();

    // Push root assertion expressions
    for item in assertions.iter() {
        stack.push((item.expr, false));
    }

    while let Some((node, children_visited)) = stack.pop() {
        let id = node.id;
        if id < visited.len() && visited[id] {
            continue;
        }
        if children_visited {
            if id >= visited.len() {
                visited.resize(id + 1, false);
            }
            visited[id] = true;
            let rewritten = match &node.v {
                Expr::Input(a) => rewriter.input(*a),
                Expr::One => rewriter.one(),
                Expr::Constant(ref e) => rewriter.constant(e),
                Expr::Sum(list, precious) => {
                    let walked_list: Vec<ExprNode<'b, F>> =
                        list.iter().map(|child| cache[child.id].unwrap()).collect();
                    rewriter.sum(&walked_list, *precious)
                }
                Expr::Linear(ref e, x) => {
                    let walked_x = cache[x.id].unwrap();
                    rewriter.linear(e, &walked_x)
                }
                Expr::Quadratic(ref e, x, y) => {
                    let walked_x = cache[x.id].unwrap();
                    let walked_y = cache[y.id].unwrap();
                    rewriter.quadratic(e, &walked_x, &walked_y)
                }
                Expr::WithAssertions(a, x) => {
                    let walked_assertions_list: Vec<RawAssertions<'b, F>> = a
                        .iter()
                        .map(|child| {
                            let walked_assertion = cache[child.id].unwrap();
                            rewriter.assert0(&walked_assertion)
                        })
                        .collect();
                    let walked_a = rewriter.assertions(&walked_assertions_list);
                    let walked_x = cache[x.id].unwrap();
                    rewriter.with_assertions(&walked_a, &walked_x)
                }
            };
            if id >= cache.len() {
                cache.resize(id + 1, None);
            }
            cache[id] = Some(rewritten);
        } else {
            stack.push((node, true));
            for child in children(node) {
                stack.push((child, false));
            }
        }
    }

    // Construct walked root assertions carrying paths
    let walked_list: Vec<AssertionItem<'b, F>> = assertions
        .iter()
        .map(|item| AssertionItem {
            expr: cache[item.expr.id].unwrap(),
            path: item.path.clone(),
        })
        .collect();

    arena.alloc_slice(&walked_list)
}

pub fn promote_sum_to_precious<'a, F: CompileField, R: RewriteT<'a, F>>(
    x: &ExprNode<'a, F>,
    rewriter: &R,
) -> ExprNode<'a, F> {
    let (assertions, inner) = extract_assertions(x);
    match &inner.v {
        Expr::Sum(elements, _) => {
            let promoted = rewriter.sum(elements, true);
            assertions
                .into_iter()
                .rev()
                .fold(promoted, |acc, a| rewriter.with_assertions(&a, &acc))
        }
        _ => x,
    }
}

// =============================================================================
// Debug formatting implementations
// =============================================================================

impl<F: CompileField> fmt::Debug for Expr<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Input(w) => write!(f, "Input({w:?})"),
            Expr::Sum(list, precious) => {
                write!(f, "Sum({list:?}, precious={precious})")
            }
            Expr::One => write!(f, "One"),
            Expr::Constant(e) => write!(f, "Constant({e:?})"),
            Expr::Linear(e, x) => write!(f, "Linear({e:?}, {x:?})"),
            Expr::Quadratic(e, x, y) => {
                write!(f, "Quadratic({e:?}, {x:?}, {y:?})")
            }
            Expr::WithAssertions(a, x) => {
                write!(f, "WithAssertions({a:?}, {x:?})")
            }
        }
    }
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrError::NotAnInput => write!(f, "Unknown input node type in IR"),
        }
    }
}

impl std::error::Error for IrError {}

// =============================================================================
// HashedExpr Optimization
// =============================================================================

/// `HashedExpr` wraps an `Expr` and precomputes its hash at creation time.
/// This optimizes Common Subexpression Elimination (CSE) memoization:
///
/// 1. **Avoids redundant hashing:** Hashing an expression tree can be slow. Since expression
///    lookups in CSE are done once in `get` and then again in `insert` on cache misses,
///    precomputing the hash avoids hashing the tree twice.
/// 2. **O(1) Map Hashing:** `FxHashMap`'s internal hashing becomes a single u64 load.
/// 3. **Fast inequality check:** Map key comparison `Equivalent::equivalent` is accelerated by
///    comparing the precomputed hash values before comparing elements.
pub struct HashedExpr<'a, F: CompileField> {
    pub(crate) expr: Expr<'a, F>,
    pub(crate) hash: u64,
}

impl<'a, F: CompileField> HashedExpr<'a, F> {
    pub fn new(expr: Expr<'a, F>) -> Self {
        use std::hash::Hasher;
        let mut hasher = rustc_hash::FxHasher::default();
        expr.hash(&mut hasher);
        let hash = hasher.finish();
        Self { expr, hash }
    }
}

impl<F: CompileField> Clone for HashedExpr<'_, F> {
    fn clone(&self) -> Self {
        Self {
            expr: self.expr.clone(),
            hash: self.hash,
        }
    }
}

impl<F: CompileField> std::hash::Hash for HashedExpr<'_, F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl<F: CompileField> PartialEq for HashedExpr<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.expr == other.expr
    }
}

impl<F: CompileField> Eq for HashedExpr<'_, F> {}
