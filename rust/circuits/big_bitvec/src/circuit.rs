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

use circuits_bignum::Bignum;
use circuits_bitvec::Bitvec;
use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::Logic;

pub struct BigBitvec<'a, L: Logic> {
    bignum: Bignum<'a, L>,
}

impl<'a, L: Logic> BigBitvec<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            bignum: Bignum::new(logic),
        }
    }

    pub fn of_nat<const W: usize, const N: usize, Fld: CompileField + SupportsNatConversions<W>>(
        &self,
        z: &Fld::N,
    ) -> Bitvec<L, N>
    where
        L: Logic<F = Fld>,
    {
        Bitvec::new(self.bignum.of_nat(N, z))
    }
}
