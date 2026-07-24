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

use std::cell::RefCell;

use compile_algebra::field::CompileField;
use rustc_hash::FxHashMap;

use crate::{
    ir::{depth_expr, Expr, ExprNode, HashedExpr, RewriteT},
    node::Node,
    arena::CompilerArena,
};

fn canonical2<'a, T>(x: &'a Node<'a, T>, y: &'a Node<'a, T>) -> (&'a Node<'a, T>, &'a Node<'a, T>) {
    // sort node lists in all commutative operators
    if x < y {
        (x, y)
    } else {
        (y, x)
    }
}

// common-subexpression elimination
pub struct Cse<'a, F: CompileField> {
    arena: &'a CompilerArena<'a, F>,
    memo: RefCell<FxHashMap<HashedExpr<'a, F>, ExprNode<'a, F>>>,
    elt_memo: RefCell<FxHashMap<F::E, &'a F::E>>,
}

impl<F: CompileField> std::fmt::Debug for Cse<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cse@{:p}", self)
    }
}

impl<F: CompileField> PartialEq for Cse<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl<F: CompileField> Eq for Cse<'_, F> {}

impl<'a, F: CompileField> Cse<'a, F> {
    pub fn new(arena: &'a CompilerArena<'a, F>) -> Self {
        Self {
            arena,
            memo: RefCell::new(FxHashMap::default()),
            elt_memo: RefCell::new(FxHashMap::default()),
        }
    }

    pub fn alloc_elt(&self, elt: &F::E) -> &'a F::E {
        if let Some(&cached) = self.elt_memo.borrow().get(elt) {
            return cached;
        }
        let allocated = self.arena.bump.alloc(elt.clone());
        self.elt_memo.borrow_mut().insert(elt.clone(), allocated);
        allocated
    }

    fn memo_expr(&self, v: Expr<'a, F>) -> ExprNode<'a, F> {
        let hashed = HashedExpr::new(v);
        if let Some(node) = self.memo.borrow().get(&hashed) {
            return node;
        }
        let depth = depth_expr(&hashed.expr);
        let node = self.arena.alloc_node(hashed.expr, depth);
        self.memo.borrow_mut().insert(hashed, node);
        node
    }
}

use crate::ir::RawAssertions;

impl<'a, F: CompileField> RewriteT<'a, F> for Cse<'a, F> {
    fn ok(&self) -> RawAssertions<'a, F> {
        self.arena.alloc_slice(&[])
    }

    fn assert0(&self, x: &ExprNode<'a, F>) -> RawAssertions<'a, F> {
        self.arena.alloc_slice(&[*x])
    }

    fn assertions(&self, assertions: &[RawAssertions<'a, F>]) -> RawAssertions<'a, F> {
        let mut result = Vec::new();
        for a in assertions {
            result.extend(a.iter().copied());
        }
        result.sort_by_key(|n| n.id);
        result.dedup_by_key(|n| n.id);
        self.arena.alloc_slice(&result)
    }

    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F> {
        self.memo_expr(Expr::Input(position_in_input_array))
    }

    fn sum(&self, elements: &[ExprNode<'a, F>], precious: bool) -> ExprNode<'a, F> {
        let mut sorted = elements.to_vec();
        sorted.sort_by_key(|n| n.id);
        let slice = self.arena.alloc_slice(&sorted);
        self.memo_expr(Expr::Sum(slice, precious))
    }

    fn one(&self) -> ExprNode<'a, F> {
        self.memo_expr(Expr::One)
    }

    fn constant(&self, elt: &F::E) -> ExprNode<'a, F> {
        let elt_ref = self.alloc_elt(elt);
        self.memo_expr(Expr::Constant(elt_ref))
    }

    fn linear(&self, elt: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let elt_ref = self.alloc_elt(elt);
        self.memo_expr(Expr::Linear(elt_ref, *x))
    }

    fn quadratic(&self, elt: &F::E, x: &ExprNode<'a, F>, y: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let (cx, cy) = canonical2(*x, *y);
        let elt_ref = self.alloc_elt(elt);
        self.memo_expr(Expr::Quadratic(elt_ref, cx, cy))
    }

    fn with_assertions(
        &self,
        assertions: &crate::ir::Assertions<'a, F>,
        x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        self.memo_expr(Expr::WithAssertions(assertions, *x))
    }
}
