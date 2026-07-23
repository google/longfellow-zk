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
use core_algebra::ElementOf;

pub type Wire = usize;
pub type Term<F> = (ElementOf<F>, Wire, Wire);

pub enum WExpr<F: CompileField> {
    Unspecified,
    Input { position_in_input_array: usize },
    Sum(Vec<Term<F>>),
    Assert0(Wire),
}

impl<F: CompileField> Clone for WExpr<F> {
    fn clone(&self) -> Self {
        match self {
            WExpr::Unspecified => WExpr::Unspecified,
            WExpr::Input {
                position_in_input_array,
            } => WExpr::Input {
                position_in_input_array: *position_in_input_array,
            },
            WExpr::Sum(terms) => WExpr::Sum(terms.clone()),
            WExpr::Assert0(w) => WExpr::Assert0(*w),
        }
    }
}

pub struct QuadCircuit<F: CompileField> {
    pub nodes: Vec<WExpr<F>>,
}

impl<F: CompileField> Clone for QuadCircuit<F> {
    fn clone(&self) -> Self {
        QuadCircuit {
            nodes: self.nodes.clone(),
        }
    }
}
