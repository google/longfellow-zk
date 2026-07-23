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

use compile_algebra::field::CompileField;

use crate::{
    algsimp::AlgebraicRewriter,
    cse::Cse,
    ir::{AssertionItem, Assertions, ExprNode, RawAssertions, RewriteT},
    CompilerArena,
};

/// A rewriter that strips all nested `WithAssertions` nodes from an expression
/// tree, collecting them into a side channel (`collected`) while delegating all
/// other node constructions to a generic `NEXT` rewriter (typically `Cse`).
struct StripRewriter<'a, 'b, F: CompileField, NEXT> {
    next: &'b NEXT,
    collected: std::cell::RefCell<Vec<ExprNode<'a, F>>>,
}

impl<'a, F: CompileField, NEXT: RewriteT<'a, F>> RewriteT<'a, F>
    for StripRewriter<'a, '_, F, NEXT>
{
    fn ok(&self) -> RawAssertions<'a, F> {
        self.next.ok()
    }

    fn assert0(&self, x: &ExprNode<'a, F>) -> RawAssertions<'a, F> {
        self.next.assert0(x)
    }

    fn assertions(&self, assertions: &[RawAssertions<'a, F>]) -> RawAssertions<'a, F> {
        self.next.assertions(assertions)
    }

    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F> {
        self.next.input(position_in_input_array)
    }

    fn sum(&self, elements: &[ExprNode<'a, F>], precious: bool) -> ExprNode<'a, F> {
        self.next.sum(elements, precious)
    }

    fn one(&self) -> ExprNode<'a, F> {
        self.next.one()
    }

    fn constant(&self, elt: &F::E) -> ExprNode<'a, F> {
        self.next.constant(elt)
    }

    fn linear(&self, elt: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        self.next.linear(elt, x)
    }

    fn quadratic(&self, elt: &F::E, x: &ExprNode<'a, F>, y: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        self.next.quadratic(elt, x, y)
    }

    fn with_assertions(
        &self,
        assertions: &RawAssertions<'a, F>,
        x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        self.collected
            .borrow_mut()
            .extend(assertions.iter().copied());
        // Strip the assertions by returning the inner expression directly
        x
    }

    fn empty_scope(&self) -> crate::ir::ScopeRef<'a> {
        self.next.empty_scope()
    }

    fn push(&self, name: &'a str, parent: crate::ir::ScopeRef<'a>) -> crate::ir::ScopeRef<'a> {
        self.next.push(name, parent)
    }
}

/// Recursively walks the expression DAG and strips all `WithAssertions` nodes
/// using a `Cse` rewriter, returning a single flattened assertion set in target arena ('b).
pub fn strip_all<'a, 'b, F: CompileField>(
    arena: &'b CompilerArena<'b, F>,
    assertions: Assertions<'a, F>,
) -> Assertions<'b, F> {
    let cse = Cse::new(arena);
    let rewriter = StripRewriter {
        next: &cse,
        collected: std::cell::RefCell::new(Vec::new()),
    };

    // Perform initial walk from 'a to 'b
    let stripped_slice = crate::ir::walk(arena, assertions, &rewriter);
    let new_sub_exprs = rewriter.collected.replace(Vec::new());

    if new_sub_exprs.is_empty() {
        return stripped_slice;
    }

    let mut current_items = stripped_slice.to_vec();
    for sub_expr in new_sub_exprs {
        current_items.push(AssertionItem {
            expr: sub_expr,
            path: Vec::new(),
        });
    }

    loop {
        current_items.sort_by_key(|item| item.expr.id);
        current_items.dedup_by_key(|item| item.expr.id);

        let stripped_slice = crate::ir::walk(arena, arena.alloc_slice(&current_items), &rewriter);
        let new_sub_exprs = rewriter.collected.replace(Vec::new());

        if new_sub_exprs.is_empty() {
            current_items = stripped_slice.to_vec();
            break;
        }

        let mut next_items = stripped_slice.to_vec();
        for sub_expr in new_sub_exprs {
            next_items.push(AssertionItem {
                expr: sub_expr,
                path: Vec::new(),
            });
        }
        current_items = next_items;
    }

    current_items.sort_by_key(|item| item.expr.id);
    current_items.dedup_by_key(|item| item.expr.id);
    arena.alloc_slice(&current_items)
}

/// Rewrite function performing algebraic simplification with CSE after
/// stripping all assertions from the DAG, rewriting into target arena ('b).
pub fn rewrite<'a, 'b, F: CompileField>(
    arena: &'b CompilerArena<'b, F>,
    f: &'b F,
    x: Assertions<'a, F>,
) -> Assertions<'b, F> {
    let stripped = strip_all(arena, x);
    let cse = Cse::new(arena);
    let algebraic = AlgebraicRewriter::new(f, cse);
    crate::ir::walk(arena, stripped, &algebraic)
}
