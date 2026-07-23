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

pub const K_FIRST_WIRE_POSITION: usize = 1;

pub trait Logic {
    type F: CompileField;
    type Wire: Clone + PartialEq;
    type Assertions: Clone;

    fn field(&self) -> &Self::F;

    fn zero(&self) -> Self::Wire;
    fn one(&self) -> Self::Wire;
    fn konst(&self, x: &ElementOf<Self::F>) -> Self::Wire;
    fn precious(&self, x: &Self::Wire) -> Self::Wire;
    fn sum(&self, xs: &[Self::Wire]) -> Self::Wire;
    fn neg(&self, x: &Self::Wire) -> Self::Wire;
    fn add(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;
    fn sub(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;
    fn mul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;
    fn mulk(&self, e: &ElementOf<Self::F>, y: &Self::Wire) -> Self::Wire;
    fn quadratic(&self, e: &ElementOf<Self::F>, x: &Self::Wire, y: &Self::Wire) -> Self::Wire;
    fn ok(&self) -> Self::Assertions;
    /// Assert that `x == 0`. Requires a non-empty name string for path identification.
    fn assert0(&self, name: &str, x: &Self::Wire) -> Self::Assertions;

    /// Groups assertions under scope `name`. Requires a non-empty name string.
    fn assert_all(&self, name: &str, assertions: &[Self::Assertions]) -> Self::Assertions;

    /// Evaluates `body(i)` for each index `i` in `range` (`mapi` functional generator),
    /// automatically naming each generated assertion tag `"{name}.{i}"` and grouping under
    /// `"{name}"`.
    fn assert_mapi<I, F>(&self, name: &str, range: I, mut body: F) -> Self::Assertions
    where
        I: IntoIterator<Item = usize>,
        F: FnMut(usize) -> Self::Assertions,
        Self: Sized,
    {
        let indexed: Vec<_> = range
            .into_iter()
            .enumerate()
            .map(|(i, idx)| self.assert_all(&format!("{name}.{i}"), &[body(idx)]))
            .collect();
        self.assert_all(name, &indexed)
    }
    fn with_assertions(&self, assertions: Self::Assertions, x: &Self::Wire) -> Self::Wire;
    fn mone(&self) -> Self::Wire {
        self.neg(&self.one())
    }

    fn negmul(&self, x: &Self::Wire, y: &Self::Wire) -> Self::Wire {
        self.neg(&self.mul(x, y))
    }

    fn assert_eq(&self, name: &str, x: &Self::Wire, y: &Self::Wire) -> Self::Assertions {
        self.assert0(name, &self.sub(x, y))
    }

    fn slicing(&self, name: &str, witness: &Self::Wire, computed: &Self::Wire) -> Self::Wire {
        self.with_assertions(self.assert_eq(name, witness, computed), witness)
    }

    fn assert_inverse(&self, name: &str, x: &Self::Wire, y: &Self::Wire) -> Self::Assertions {
        let one = self.one();
        let prod = self.mul(x, y);
        self.assert_eq(name, &prod, &one)
    }

    fn dot(&self, a: &[Self::Wire], b: &[Self::Wire]) -> Self::Wire {
        assert_eq!(a.len(), b.len());
        let products: Vec<Self::Wire> = a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| self.mul(x, y))
            .collect();
        self.sum(&products)
    }

    fn prod(&self, elements: &[Self::Wire]) -> Self::Wire {
        if elements.is_empty() {
            self.one()
        } else {
            util::array::tree_fold(elements, &|x, y| self.mul(&x, &y), &|x| x.clone())
        }
    }

    fn to_stringw_debug(&self, x: &Self::Wire) -> String;
}

pub type Eltw<L> = <L as Logic>::Wire;

pub trait LogicIO: Logic {
    fn input(&self, position_in_input_array: usize) -> Self::Wire;
    fn position_in_input_array(&self, x: &Self::Wire) -> usize;

    fn next(&self, pos: &mut usize) -> Self::Wire {
        let wire = self.input(*pos);
        *pos += 1;
        wire
    }
}
