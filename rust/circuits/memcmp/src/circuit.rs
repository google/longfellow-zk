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

use circuits_bitvec::V8;
use circuits_boolean::Bitw;
use compile_logic::Logic;

pub struct Memcmp<'a, L: Logic> {
    arithmetic: circuits_arithmetic::Arithmetic<'a, L>,
}

impl<'a, L: Logic> Memcmp<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            arithmetic: circuits_arithmetic::Arithmetic::new(logic),
        }
    }

    fn arrange(&self, bytes: &[V8<L>]) -> Vec<Bitw<L>> {
        let n = bytes.len();
        let mut bits = Vec::with_capacity(8 * n);
        for i in (0..n).rev() {
            bits.extend(bytes[i].iter().cloned());
        }
        bits
    }

    pub fn leq(&self, a: &[V8<L>], b: &[V8<L>]) -> Bitw<L> {
        let a_bits = self.arrange(a);
        let b_bits = self.arrange(b);
        self.arithmetic.leq(&a_bits, &b_bits)
    }
}
