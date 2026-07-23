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
    ir::{Assertions, Expr, ExprNode},
    quad::{QuadCircuit, Term, WExpr, Wire},
};

const ONE_WIRE: Wire = 0;

struct WireMemoizer {
    cache: std::cell::RefCell<Vec<Option<Wire>>>,
}

impl WireMemoizer {
    fn new() -> Self {
        WireMemoizer {
            cache: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn call<'a, F: CompileField, FUNC>(&self, node: ExprNode<'a, F>, f: FUNC) -> Wire
    where FUNC: FnOnce(&ExprNode<'a, F>) -> Wire {
        let id = node.id;
        {
            let cache = self.cache.borrow();
            if id < cache.len() {
                if let Some(w) = cache[id] {
                    return w;
                }
            }
        }
        let val = f(&node);
        let mut cache = self.cache.borrow_mut();
        if id >= cache.len() {
            cache.resize(id + 1, None);
        }
        cache[id] = Some(val);
        val
    }
}

fn push_node<F: CompileField>(nodes: &mut Vec<WExpr<F>>, n: WExpr<F>) -> Wire {
    let c = nodes.len();
    nodes.push(n);
    c
}

fn walk_eltw<F: CompileField>(
    f: &F,
    ememo: &WireMemoizer,
    nodes: &mut Vec<WExpr<F>>,
    node: ExprNode<'_, F>,
) -> Wire {
    ememo.call(node, |n| match &n.v {
        Expr::Input(position_in_input_array) => {
            let wexpr = WExpr::Input {
                position_in_input_array: *position_in_input_array,
            };
            push_node(nodes, wexpr)
        }
        Expr::Sum(list, _) => {
            assert!(!list.is_empty(), "ir_to_quad: empty list in sum");
            let terms: Vec<Term<F>> = list
                .iter()
                .map(|item| compile_term(f, ememo, nodes, item))
                .collect();
            push_node(nodes, WExpr::Sum(terms))
        }
        Expr::One => ONE_WIRE,
        Expr::Quadratic(..) => {
            let term = compile_term(f, ememo, nodes, n);
            push_node(nodes, WExpr::Sum(vec![term]))
        }
        Expr::Constant(_) | Expr::Linear(..) | Expr::WithAssertions(..) => {
            panic!("ir_to_quad: unexpected expression variant: {n:?}")
        }
    })
}

fn compile_term<F: CompileField>(
    f: &F,
    ememo: &WireMemoizer,
    nodes: &mut Vec<WExpr<F>>,
    node: &ExprNode<'_, F>,
) -> Term<F> {
    match &node.v {
        Expr::Quadratic(e, x, y) => {
            assert!(!f.is_zero(e));
            let wx = walk_eltw(f, ememo, nodes, *x);
            let wy = walk_eltw(f, ememo, nodes, *y);
            ((*e).clone(), wx, wy)
        }
        Expr::Input(_) => {
            let w = walk_eltw(f, ememo, nodes, *node);
            (f.one(), ONE_WIRE, w)
        }
        Expr::One => (f.one(), ONE_WIRE, ONE_WIRE),
        _ => panic!("ir_to_quad: expected term node, got {node:?}"),
    }
}

/// Rewrite into a stylized Quad circuit with debug info mapping quad node index to assertion path.
pub fn rewrite<'a, F: CompileField>(
    _arena: &'a crate::CompilerArena<'a, F>,
    f: &F,
    x: Assertions<'a, F>,
) -> (QuadCircuit<F>, Vec<(usize, Vec<String>)>) {
    let one_wexpr = WExpr::Input {
        position_in_input_array: 0,
    };
    let mut nodes = vec![one_wexpr];
    let mut quad_asserts = Vec::new();
    let ememo = WireMemoizer::new();
    for item in x.iter() {
        let wx = walk_eltw(f, &ememo, &mut nodes, item.expr);
        let quad_node_idx = push_node(&mut nodes, WExpr::Assert0(wx));
        quad_asserts.push((quad_node_idx, item.path.clone()));
    }
    (QuadCircuit { nodes }, quad_asserts)
}
