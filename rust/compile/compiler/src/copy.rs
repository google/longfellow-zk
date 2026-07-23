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
use util::memoize::Memoizer;

use crate::{
    cse::Cse,
    ir::{Assertions, Expr, ExprNode, RewriteT},
    CompilerArena,
};

/// Introduce copy wires. Note that algsimp will remove
/// the copy wires, so this pass must be run after algsimp.
pub struct CopyRewriter<'a, F: CompileField, NEXT> {
    f: &'a F,
    next: NEXT,
    // Memoizer for the one_at_depth function
    memo_one_at_depth: Memoizer<usize, ExprNode<'a, F>>,
}

/// Note: This copy-pass specific version of `depth_term` ensures that
/// all terms of a summation are fully termified (i.e. only `Input`,
/// `One`, or `Quadratic` nodes remain). Any other node variant
/// indicates a compiler bug and triggers a panic, acting as an
/// invariant assertion.
fn depth_term<F: CompileField>(node: &ExprNode<'_, F>) -> usize {
    match &node.v {
        Expr::Input(_) | Expr::One => 1,
        Expr::Quadratic(_, _, _) => node.depth,
        _ => panic!("depth_term: unexpected node variant: {node:?}"),
    }
}

impl<'a, F: CompileField, NEXT> CopyRewriter<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    pub fn new(f: &'a F, next: NEXT) -> Self {
        CopyRewriter {
            next,
            memo_one_at_depth: Memoizer::new(),
            f,
        }
    }

    fn ground_quadratic(
        &self,
        e: &F::E,
        x: &ExprNode<'a, F>,
        y: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        assert_eq!(x.depth, y.depth);
        self.next.quadratic(e, x, y)
    }

    fn one_at_depth(&self, d: usize) -> ExprNode<'a, F> {
        self.memo_one_at_depth.call(d, |d_val| {
            if *d_val == 0 {
                self.one()
            } else {
                let oo = self.one_at_depth(*d_val - 1);
                self.ground_quadratic(&self.f.one(), &oo, &oo)
            }
        })
    }

    fn copy(&self, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let oo = self.one_at_depth(x.depth);
        match &x.v {
            // When creating a copy, take the opportunity to lift any
            // constants in the underlying term, in the hope of
            // creating common subexpressions in the lower layers
            Expr::Quadratic(ref e1, ref x1, ref y1) => {
                let sub_quad = self.ground_quadratic(&self.f.one(), x1, y1);
                self.ground_quadratic(e1, &oo, &sub_quad)
            }
            Expr::Linear(..) => panic!("linear can't happen"),
            Expr::Constant(_) => panic!("constant can't happen"),
            _ => self.ground_quadratic(&self.f.one(), &oo, x),
        }
    }

    fn lift(&self, d: usize, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let mut current = *x;
        loop {
            let cx = depth_term(&current);
            if cx == d {
                return current;
            } else if cx > d {
                panic!("lift: depth too high");
            } else {
                current = self.copy(&current);
            }
        }
    }

    fn sum_no_nested_sums(&self, elements: &[ExprNode<'a, F>]) -> ExprNode<'a, F> {
        match elements {
            [] => panic!("sum: empty elements"),
            [x] => x,
            _ => {
                let d = elements.iter().map(|item| depth_term(item)).max().unwrap();
                let (yes, no): (Vec<ExprNode<'a, F>>, Vec<ExprNode<'a, F>>) =
                    elements.iter().copied().partition(|n| depth_term(n) == d);

                let mut yes_lifted: Vec<ExprNode<'a, F>> =
                    yes.iter().map(|item| self.lift(d, item)).collect();

                match (yes_lifted.as_slice(), no.as_slice()) {
                    (slice_yes, []) => self.next.sum(slice_yes, false),
                    ([], _) => panic!("sum: can't happen 2"),
                    (_, slice_no) => {
                        let folded_no = self.sum_no_nested_sums(slice_no);
                        let copied_no = self.copy(&folded_no);
                        let lifted_no = self.lift(d, &copied_no);
                        yes_lifted.push(lifted_no);
                        self.sum_no_nested_sums(&yes_lifted)
                    }
                }
            }
        }
    }
}

impl<'a, F: CompileField, NEXT> RewriteT<'a, F> for CopyRewriter<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    fn ok(&self) -> crate::ir::RawAssertions<'a, F> {
        self.next.ok()
    }
    fn assert0(&self, x: &ExprNode<'a, F>) -> crate::ir::RawAssertions<'a, F> {
        self.next.assert0(x)
    }
    fn assertions(
        &self,
        assertions: &[crate::ir::RawAssertions<'a, F>],
    ) -> crate::ir::RawAssertions<'a, F> {
        self.next.assertions(assertions)
    }
    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F> {
        self.next.input(position_in_input_array)
    }
    fn sum(&self, elements: &[ExprNode<'a, F>], _precious: bool) -> ExprNode<'a, F> {
        let no_nested_sums: Vec<ExprNode<'a, F>> = elements
            .iter()
            .map(|x| match &x.v {
                Expr::Sum(_, _) => self.quadratic(&self.f.one(), &self.next.one(), x),
                _ => *x,
            })
            .collect();
        self.sum_no_nested_sums(&no_nested_sums)
    }
    fn one(&self) -> ExprNode<'a, F> {
        self.next.one()
    }
    fn constant(&self, elt: &F::E) -> ExprNode<'a, F> {
        if elt == &self.f.one() {
            self.next.one()
        } else {
            assert!(!self.f.is_zero(elt));
            self.quadratic(elt, &self.next.one(), &self.next.one())
        }
    }
    fn linear(&self, elt: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        self.quadratic(elt, &self.next.one(), x)
    }
    fn quadratic(&self, elt: &F::E, x: &ExprNode<'a, F>, y: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let dx = x.depth;
        let dy = y.depth;
        if dx < dy {
            self.quadratic(elt, &self.copy(x), y)
        } else if dx > dy {
            self.quadratic(elt, &self.copy(y), x)
        } else {
            self.ground_quadratic(elt, x, y)
        }
    }
    fn with_assertions(
        &self,
        _assertions: &crate::ir::RawAssertions<'a, F>,
        _x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        panic!("UnexpectedWithAssertion")
    }

    fn empty_scope(&self) -> crate::ir::ScopeRef<'a> {
        self.next.empty_scope()
    }

    fn push(&self, name: &'a str, parent: crate::ir::ScopeRef<'a>) -> crate::ir::ScopeRef<'a> {
        self.next.push(name, parent)
    }
}

/// Rewrite function performing copy rewriter and termification to
/// eliminate Constants and Linears, rewriting from arena ('a) to target arena ('b).
pub fn rewrite<'a, 'b, F: CompileField>(
    arena: &'b CompilerArena<'b, F>,
    f: &'b F,
    x: Assertions<'a, F>,
) -> Assertions<'b, F> {
    let cse = Cse::new(arena);
    let copy_rewriter = CopyRewriter::new(f, cse);
    crate::ir::walk(arena, x, &copy_rewriter)
}
