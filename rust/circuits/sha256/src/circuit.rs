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

use circuits_analog_adder::{AnalogAdder, FieldWrappingSum};
use circuits_bitvec::{BitvecLogic, V32};
use compile_logic::Logic;

use super::constants::K;

#[derive(Clone)]
pub struct Given<L: Logic> {
    pub input_block: [V32<L>; 16],
    pub h0: [V32<L>; 8],
}

pub struct Derived<L: Logic> {
    pub outw: [V32<L>; 48],
    pub oute: [V32<L>; 64],
    pub outa: [V32<L>; 64],
    pub h1: [V32<L>; 8],
}

pub struct Sha256<'a, L: Logic> {
    logic: &'a L,
    pub(crate) bv: BitvecLogic<'a, L>,
}

impl<'a, L: Logic> Sha256<'a, L>
where L::F: FieldWrappingSum
{
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            bv: BitvecLogic::new(logic),
        }
    }

    #[inline]
    fn ch(&self, x: &V32<L>, y: &V32<L>, z: &V32<L>) -> V32<L> {
        self.bv.muxb(x, y, z)
    }

    #[inline]
    fn bigsigma0(&self, x: &V32<L>) -> V32<L> {
        self.bv.xor3(
            &self.bv.rotr(2, x),
            &self.bv.rotr(13, x),
            &self.bv.rotr(22, x),
        )
    }

    #[inline]
    fn bigsigma1(&self, x: &V32<L>) -> V32<L> {
        self.bv.xor3(
            &self.bv.rotr(6, x),
            &self.bv.rotr(11, x),
            &self.bv.rotr(25, x),
        )
    }

    #[inline]
    fn sigma0(&self, x: &V32<L>) -> V32<L> {
        self.bv.xor3(
            &self.bv.rotr(7, x),
            &self.bv.rotr(18, x),
            &self.bv.shr(3, x),
        )
    }

    #[inline]
    fn sigma1(&self, x: &V32<L>) -> V32<L> {
        self.bv.xor3(
            &self.bv.rotr(17, x),
            &self.bv.rotr(19, x),
            &self.bv.shr(10, x),
        )
    }

    pub fn assert_transform_block(&self, given: &Given<L>, derived: &Derived<L>) -> L::Assertions {
        let mut w = Vec::with_capacity(64);
        w.extend(given.input_block.iter().cloned());
        w.extend(derived.outw.iter().cloned());

        let adder = AnalogAdder::new(self.logic);
        // Key schedule assertions
        let schedule_assertions = self.logic.assert_mapi("schedule", 16..64, |i| {
            adder.assert_wrapping_sum(
                &w[i],
                &[&[
                    self.sigma1(&w[i - 2]),
                    w[i - 7].clone(),
                    self.sigma0(&w[i - 15]),
                    w[i - 16].clone(),
                ]],
            )
        });

        // Round assertions
        let mut state = std::array::from_fn(|i| given.h0[i].clone());
        let round_assertions = self.logic.assert_mapi("rounds", 0..64, |t| {
            let [a, b, c, d, e, f, g, h] = state.clone();

            let t1 = [
                h,
                self.bigsigma1(&e),
                self.bv.of_u32(K[t]),
                self.ch(&e, &f, &g),
                w[t].clone(),
            ];
            let t2 = [self.bigsigma0(&a), self.bv.maj(&a, &b, &c)];

            // Assert oute[t] is sum of d and t1 using grouping
            let oute_assertion = adder.assert_wrapping_sum(
                &derived.oute[t],
                &[std::slice::from_ref(&d) as &[V32<L>], &t1 as &[V32<L>]],
            );

            // Assert outa[t] is sum of t2 and t1 using grouping
            let outa_assertion =
                adder.assert_wrapping_sum(&derived.outa[t], &[&t2 as &[V32<L>], &t1 as &[V32<L>]]);

            state = [
                derived.outa[t].clone(),
                a,
                b,
                c,
                derived.oute[t].clone(),
                e,
                f,
                g,
            ];

            self.logic
                .assert_all("round_step", &[oute_assertion, outa_assertion])
        });

        // Final state addition assertions
        let final_assertions = self.logic.assert_mapi("final", 0..8, |i| {
            adder.assert_wrapping_sum(&derived.h1[i], &[&[given.h0[i].clone(), state[i].clone()]])
        });

        self.logic.assert_all(
            "sha256",
            &[schedule_assertions, final_assertions, round_assertions],
        )
    }
}
