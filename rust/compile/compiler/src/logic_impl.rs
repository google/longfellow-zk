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
use compile_logic::{scope::AssertionScope, Logic, LogicIO};

use crate::{
    algsimp::AlgebraicRewriter,
    arena::CompilerArena,
    cse::Cse,
    ir::{position_in_input_array, AssertionItem, ExprNode, RewriteT},
};

#[derive(Debug, PartialEq, Eq)]
pub struct CompilerAssertions<'a, F: CompileField> {
    pub items: &'a [AssertionItem<'a, F>],
}

impl<'a, F: CompileField> Clone for CompilerAssertions<'a, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, F: CompileField> Copy for CompilerAssertions<'a, F> {}

pub struct CompilerLogic<
    'a,
    F: CompileField,
    NEXT: RewriteT<'a, F> = AlgebraicRewriter<'a, F, Cse<'a, F>>,
> {
    arena: &'a CompilerArena<'a, F>,
    f: &'a F,
    tracker: &'a AssertionScope,
    next: NEXT,
}

impl<'a, F: CompileField> CompilerLogic<'a, F> {
    pub fn new(arena: &'a CompilerArena<'a, F>, f: &'a F, tracker: &'a AssertionScope) -> Self {
        let cse = Cse::new(arena);
        let next = AlgebraicRewriter::new(f, cse);
        Self {
            arena,
            f,
            tracker,
            next,
        }
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
            items: self.arena.alloc_slice(&[]),
        }
    }

    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions {
        assert!(!name.is_empty(), "assert0 requires a non-empty name");
        let id = self.tracker.new_leaf(name);
        let own_raw = self.next.assert0(x);

        let mut items = Vec::with_capacity(own_raw.len());
        for &expr in own_raw {
            items.push(AssertionItem { expr, id });
        }

        CompilerAssertions {
            items: self.arena.alloc_slice(&items),
        }
    }

    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions {
        assert!(!name.is_empty(), "assert_all requires a non-empty name");
        let mut items = Vec::new();
        let mut seen = rustc_hash::FxHashSet::default();
        let mut seen_roots = rustc_hash::FxHashSet::default();
        for child_group in assertions {
            for item in child_group.items {
                if seen.insert((item.expr.id, item.id)) {
                    let root = self.tracker.find(item.id);
                    if seen_roots.insert(root) {
                        self.tracker.prepend_scope(item.id, name);
                    }
                    items.push(*item);
                }
            }
        }
        CompilerAssertions {
            items: self.arena.alloc_slice(&items),
        }
    }

    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire {
        self.next.with_assertions(&assertions.items, x)
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
