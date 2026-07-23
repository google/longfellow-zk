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
use compile_logic::{Logic, LogicIO};

use crate::{
    algsimp::AlgebraicRewriter,
    cse::Cse,
    ir::{position_in_input_array, AssertionItemRef, Expr, ExprNode, RewriteT},
    CompilerArena,
};

#[derive(Debug, PartialEq, Eq)]
pub struct CompilerAssertions<'a, F: CompileField> {
    pub item_refs: &'a [AssertionItemRef<'a, F>],
    pub raw: crate::ir::RawAssertions<'a, F>,
}

impl<'a, F: CompileField> Clone for CompilerAssertions<'a, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, F: CompileField> Copy for CompilerAssertions<'a, F> {}

impl<'a, F: CompileField> std::ops::Deref for CompilerAssertions<'a, F> {
    type Target = crate::ir::RawAssertions<'a, F>;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

pub struct CompilerLogic<
    'a,
    F: CompileField,
    NEXT: RewriteT<'a, F> = AlgebraicRewriter<'a, F, Cse<'a, F>>,
> {
    arena: &'a CompilerArena<'a, F>,
    f: &'a F,
    next: NEXT,
}

impl<'a, F: CompileField> CompilerLogic<'a, F> {
    pub fn new(arena: &'a CompilerArena<'a, F>, f: &'a F) -> Self {
        let cse = Cse::new(arena);
        let next = AlgebraicRewriter::new(f, cse);
        Self { arena, f, next }
    }
}

impl<'a, F: CompileField, NEXT> Logic for CompilerLogic<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    type F = F;
    type Wire = ExprNode<'a, F>;
    type Assertions = CompilerAssertions<'a, F>;

    fn field(&self) -> &Self::F {
        self.f
    }

    fn zero(&self) -> Self::Wire {
        self.next.constant(&self.f.zero())
    }

    fn one(&self) -> Self::Wire {
        self.next.one()
    }

    fn konst(&self, x: &F::E) -> Self::Wire {
        self.next.constant(x)
    }

    fn precious(&self, x: &Self::Wire) -> Self::Wire {
        crate::ir::promote_sum_to_precious(x, &self.next)
    }

    fn sum(&self, xs: &[Self::Wire]) -> Self::Wire {
        self.next.sum(xs, false)
    }

    fn neg(&self, x: &Self::Wire) -> Self::Wire {
        self.next.linear(&self.f.mone(), x)
    }

    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.next.sum(&[*x, *y], false)
    }

    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.next.sum(&[*x, self.neg(y)], false)
    }

    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.next.quadratic(&self.f.one(), x, y)
    }

    fn mulk(&self, e: &F::E, y: &Self::Wire) -> Self::Wire {
        self.next.linear(e, y)
    }

    fn quadratic(&self, e: &F::E, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.next.quadratic(e, x, y)
    }

    fn ok(&self) -> Self::Assertions {
        CompilerAssertions {
            item_refs: self.arena.alloc_slice(&[]),
            raw: self.arena.alloc_slice(&[]),
        }
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let own_raw = self.next.assert0(x);
        let root_scope = self.next.empty_scope();
        let name_str = self.arena.alloc_str(name);
        let own_scope = self.next.push(name_str, root_scope);

        // Assertions attached to a wire are logically siblings of the
        // assertion consuming that wire.  Collect them here, before an outer
        // assert_all adds its scope, so they receive the same enclosing path
        // without being incorrectly nested under `name`.
        let mut items = Vec::new();
        let mut seen_assertions = rustc_hash::FxHashSet::default();
        let mut seen_nodes = rustc_hash::FxHashSet::default();
        let mut stack = vec![*x];
        while let Some(node) = stack.pop() {
            if !seen_nodes.insert(node.id) {
                continue;
            }
            match &node.v {
                Expr::Input(_) | Expr::One | Expr::Constant(_) => {}
                Expr::Sum(children, _) => stack.extend(children.iter().rev().copied()),
                Expr::Linear(_, child) => stack.push(*child),
                Expr::Quadratic(_, left, right) => {
                    stack.push(*right);
                    stack.push(*left);
                }
                Expr::WithAssertions(attached, inner) => {
                    for item in attached.iter() {
                        if seen_assertions.insert(item.expr.id) {
                            let mut scope = self.next.empty_scope();
                            for component in item.path.iter().rev() {
                                let component = self.arena.alloc_str(component);
                                scope = self.next.push(component, scope);
                            }
                            items.push(AssertionItemRef {
                                expr: item.expr,
                                scope,
                            });
                        }
                    }
                    stack.push(*inner);
                    stack.extend(attached.iter().rev().map(|item| item.expr));
                }
            }
        }

        for &expr in own_raw {
            if seen_assertions.insert(expr.id) {
                items.push(AssertionItemRef {
                    expr,
                    scope: own_scope,
                });
            }
        }

        let item_exprs: Vec<_> = items.iter().map(|item| item.expr).collect();
        let item_exprs = self.arena.alloc_slice(&item_exprs);
        let raw = self.next.assertions(&[item_exprs]);
        assert_eq!(items.len(), raw.len());
        CompilerAssertions {
            item_refs: self.arena.alloc_slice(&items),
            raw,
        }
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let raw_list: Vec<crate::ir::RawAssertions<'a, F>> =
            assertions.iter().map(|a| a.raw).collect();
        let raw = self.next.assertions(&raw_list);

        let name_str = self.arena.alloc_str(name);

        let mut items = Vec::new();
        let mut seen = rustc_hash::FxHashSet::default();
        for child_group in assertions {
            for item in child_group.item_refs {
                if seen.insert(item.expr.id) {
                    let scope = self.next.push(name_str, item.scope);
                    items.push(AssertionItemRef {
                        expr: item.expr,
                        scope,
                    });
                }
            }
        }
        assert_eq!(items.len(), raw.len());
        CompilerAssertions {
            item_refs: self.arena.alloc_slice(&items),
            raw,
        }
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        let items: Vec<_> = assertions
            .item_refs
            .iter()
            .map(AssertionItemRef::to_item)
            .collect();
        let items = self.arena.alloc_slice(&items);
        self.next.with_assertions(&items, x)
    }

    fn to_stringw_debug(&self, _x: &Self::Wire) -> String {
        "<ir>".to_string()
    }
}

impl<'a, F: CompileField, NEXT> LogicIO for CompilerLogic<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    fn input(&self, position_in_input_array: usize) -> Self::Wire {
        assert!(
            position_in_input_array > 0,
            "position_in_input_array = 0 is reserved for the constant One"
        );
        self.next.input(position_in_input_array)
    }

    fn position_in_input_array(&self, x: &Self::Wire) -> usize {
        position_in_input_array(x).expect("position_in_input_array: not an input")
    }
}

impl<'a, F: CompileField, NEXT> std::fmt::Debug for CompilerLogic<'a, F, NEXT>
where NEXT: RewriteT<'a, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompilerLogic").finish()
    }
}
