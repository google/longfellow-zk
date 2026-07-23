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

use circuits_boolean::{Bitw, Boolean};
use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::Logic;
use util::array::init;

pub struct Bignum<'a, L: Logic> {
    boolean: Boolean<'a, L>,
}

impl<'a, L: Logic> Bignum<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            boolean: Boolean::new(logic),
        }
    }

    pub fn of_nat<const W: usize, F: CompileField + SupportsNatConversions<W>>(
        &self,
        n: usize,
        z: &F::N,
    ) -> Vec<Bitw<L>>
    where
        L: Logic<F = F>,
    {
        use core_algebra::Nat;
        assert!(W * 64 <= n, "of_nat: Nat does not fit");
        init(n, |i| {
            let bit_val = z.bit(i);
            self.boolean.konst(bit_val)
        })
    }
}
