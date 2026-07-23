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

use crate::ir::{Expr, ExprNode, RewriteT};

/// Algebraic simplification rewriter
pub struct AlgebraicRewriter<'a, F: CompileField, NEXT> {
    f: &'a F,
    next: NEXT,
}

impl<'a, F: CompileField, NEXT> AlgebraicRewriter<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    pub fn new(f: &'a F, next: NEXT) -> Self {
        AlgebraicRewriter { f, next }
    }

    fn flatten_sum(&self, l: &[ExprNode<'a, F>]) -> Vec<ExprNode<'a, F>> {
        let mut result = Vec::new();
        for x in l {
            match &x.v {
                Expr::Sum(inner_list, false) => result.extend(inner_list.iter().copied()),
                _ => result.push(*x),
            }
        }
        result
    }

    fn low_degree(&self, x: &ExprNode<'a, F>) -> bool {
        !matches!(&x.v, Expr::Quadratic(..) | Expr::Sum(_, true))
    }

    fn ground_linear(&self, e: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        assert!(!self.f.is_zero(e));
        self.next.linear(e, x)
    }

    fn ground_quadratic(
        &self,
        e: &F::E,
        a: &ExprNode<'a, F>,
        b: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        assert!(!self.f.is_zero(e));
        self.next.quadratic(e, a, b)
    }

    fn unquadratic(&self, n: &ExprNode<'a, F>) -> (F::E, ExprNode<'a, F>, ExprNode<'a, F>) {
        let f = &self.f;
        let canonical = |e: F::E, x: ExprNode<'a, F>, y: ExprNode<'a, F>| {
            if x < y {
                (e, x, y)
            } else {
                (e, y, x)
            }
        };
        match &n.v {
            Expr::Quadratic(e, x, y) => canonical((*e).clone(), x, y),
            Expr::Linear(e, x) => canonical((*e).clone(), self.one(), x),
            Expr::Constant(e) => ((*e).clone(), self.one(), self.one()),
            _ => canonical(f.one(), self.one(), *n),
        }
    }

    fn compare_triples(
        &self,
        (ref e, ref x, ref y): &(F::E, ExprNode<'a, F>, ExprNode<'a, F>),
        (ref e1, ref x1, ref y1): &(F::E, ExprNode<'a, F>, ExprNode<'a, F>),
    ) -> std::cmp::Ordering {
        let f = &self.f;
        (x, y).cmp(&(x1, y1)).then_with(|| f.compare(e, e1))
    }

    fn linear0(&self, e: &F::E, a: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let f = &self.f;
        match &a.v {
            _ if f.is_zero(e) => self.constant(e),
            _ if e == &f.one() => a,
            Expr::Constant(ref e1) => self.constant(&f.mulf(e, e1)),
            Expr::Linear(ref e1, ref x) => self.linear0(&f.mulf(e, e1), x),
            Expr::Quadratic(ref e1, ref x, ref y) => self.ground_quadratic(&f.mulf(e, e1), x, y),
            _ => self.ground_linear(e, a),
        }
    }

    fn one(&self) -> ExprNode<'a, F> {
        self.constant(&self.f.one())
    }
}

impl<'a, F: CompileField, NEXT> RewriteT<'a, F> for AlgebraicRewriter<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    fn ok(&self) -> crate::ir::RawAssertions<'a, F> {
        self.next.ok()
    }

    fn assert0(&self, x: &ExprNode<'a, F>) -> crate::ir::RawAssertions<'a, F> {
        let f = &self.f;
        match &x.v {
            Expr::Constant(ref e) if f.is_zero(e) => self.ok(),
            Expr::Constant(_) => panic!("AssertionFailure"),
            Expr::Linear(ref e, ref inner_node) => {
                assert!(!f.is_zero(e));
                self.assert0(inner_node)
            }

            _ => self.next.assert0(x),
        }
    }

    fn assertions(
        &self,
        assertions: &[crate::ir::RawAssertions<'a, F>],
    ) -> crate::ir::RawAssertions<'a, F> {
        self.next.assertions(assertions)
    }

    fn with_assertions(
        &self,
        assertions: &crate::ir::RawAssertions<'a, F>,
        x: &ExprNode<'a, F>,
    ) -> ExprNode<'a, F> {
        if assertions.is_empty() {
            *x
        } else {
            self.next.with_assertions(assertions, x)
        }
    }

    fn input(&self, position_in_input_array: usize) -> ExprNode<'a, F> {
        self.next.input(position_in_input_array)
    }

    fn one(&self) -> ExprNode<'a, F> {
        self.constant(&self.f.one())
    }

    fn sum(&self, l: &[ExprNode<'a, F>], precious: bool) -> ExprNode<'a, F> {
        let f = &self.f;
        let flat_l = self.flatten_sum(l);
        let triples = {
            let mut triples: Vec<(F::E, ExprNode<'a, F>, ExprNode<'a, F>)> =
                flat_l.iter().map(|x| self.unquadratic(x)).collect();
            triples.sort_by(|a, b| self.compare_triples(a, b));
            triples
        };

        let folded = triples.into_iter().fold(
            Vec::<(F::E, ExprNode<'a, F>, ExprNode<'a, F>)>::new(),
            |mut acc, (e, x, y)| {
                match acc.last_mut() {
                    Some((last_e, last_x, last_y)) if *last_x == x && *last_y == y => {
                        *last_e = f.addf(last_e, &e);
                    }
                    _ => acc.push((e, x, y)),
                }
                acc
            },
        );

        let term_nodes: Vec<ExprNode<'a, F>> = folded
            .into_iter()
            .map(|(e, x, y)| self.quadratic(&e, &x, &y))
            .collect();

        let (constants, non_constants): (Vec<ExprNode<'a, F>>, Vec<ExprNode<'a, F>>) = term_nodes
            .into_iter()
            .partition(|x| matches!(&x.v, Expr::Constant(_)));

        let const_sum = constants.iter().fold(f.zero(), |acc, x| {
            if let Expr::Constant(ref e) = &x.v {
                f.addf(&acc, e)
            } else {
                acc
            }
        });

        let final_list = if f.is_zero(&const_sum) {
            non_constants
        } else {
            let c = self.constant(&const_sum);
            non_constants
                .into_iter()
                .chain(std::iter::once(c))
                .collect()
        };

        match final_list.len() {
            0 => self.constant(&f.zero()),
            1 => final_list[0],
            _ => self.next.sum(&final_list, precious),
        }
    }

    fn constant(&self, elt: &F::E) -> ExprNode<'a, F> {
        self.next.constant(elt)
    }

    fn linear(&self, e: &F::E, x: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        match &x.v {
            Expr::Sum(l, false) => {
                let mapped: Vec<ExprNode<'a, F>> =
                    l.iter().map(|item| self.linear0(e, item)).collect();
                self.sum(&mapped, false)
            }
            _ => self.linear0(e, x),
        }
    }

    fn quadratic(&self, e: &F::E, a: &ExprNode<'a, F>, b: &ExprNode<'a, F>) -> ExprNode<'a, F> {
        let f = &self.f;
        match (&a.v, &b.v) {
            _ if f.is_zero(e) => self.constant(e),
            (Expr::Constant(ref e1), _) => self.linear(&f.mulf(e, e1), b),
            (_, Expr::Constant(ref e1)) => self.linear(&f.mulf(e, e1), a),
            (Expr::Linear(ref e1, ref x1), _) => self.quadratic(&f.mulf(e, e1), x1, b),
            (_, Expr::Linear(ref e1, ref x1)) => self.quadratic(&f.mulf(e, e1), x1, a),
            (Expr::Sum(_, _), Expr::Sum(_, _)) => self.ground_quadratic(e, a, b),
            (_, Expr::Sum(l, false)) if l.iter().all(|x| self.low_degree(x)) => {
                let mapped: Vec<ExprNode<'a, F>> =
                    l.iter().map(|x| self.quadratic(e, x, a)).collect();
                self.sum(&mapped, false)
            }
            (Expr::Sum(l, false), _) if l.iter().all(|x| self.low_degree(x)) => {
                let mapped: Vec<ExprNode<'a, F>> =
                    l.iter().map(|x| self.quadratic(e, x, b)).collect();
                self.sum(&mapped, false)
            }
            _ => self.ground_quadratic(e, a, b),
        }
    }

    fn empty_scope(&self) -> crate::ir::ScopeRef<'a> {
        self.next.empty_scope()
    }

    fn push(&self, name: &'a str, parent: crate::ir::ScopeRef<'a>) -> crate::ir::ScopeRef<'a> {
        self.next.push(name, parent)
    }
}
