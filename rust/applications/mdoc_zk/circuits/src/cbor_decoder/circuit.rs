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

use circuits_bitvec::{Bitvec, BitvecLogic, V8};
use circuits_boolean::{Bitw, Boolean};
use compile_logic::Logic;

pub struct Given<L: Logic> {
    pub v: V8<L>,
}

pub struct CborDecodeResult<L: Logic, const N: usize> {
    pub atomp: Bitw<L>,
    pub itemsp: Bitw<L>,
    pub stringp: Bitw<L>,
    pub arrayp: Bitw<L>,
    pub mapp: Bitw<L>,
    pub tagp: Bitw<L>,
    pub specialp: Bitw<L>,
    pub simple_specialp: Bitw<L>,
    pub count0_23: Bitw<L>,
    pub count24_27: Bitw<L>,
    pub count24: Bitw<L>,
    pub count25: Bitw<L>,
    pub count26: Bitw<L>,
    pub count27: Bitw<L>,
    pub length_plus_next_v8: Bitw<L>,
    pub count_is_next_v8: Bitw<L>,
    pub invalid: Bitw<L>,
    pub length: Bitvec<L, N>,
    pub as_bits: V8<L>,
}

pub struct CborByteDecoder<'a, L: Logic> {
    boolean: Boolean<'a, L>,
    pub(crate) bv: BitvecLogic<'a, L>,
}

impl<'a, L: Logic> CborByteDecoder<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            boolean: Boolean::new(logic),
            bv: BitvecLogic::new(logic),
        }
    }

    pub fn decode_one_v8<const N: usize>(
        &self,
        v: &V8<L>,
    ) -> (CborDecodeResult<L, N>, L::Assertions) {
        let (count, tag): (Bitvec<L, 5>, Bitvec<L, 3>) = self.bv.split(v);

        let atomp = self.bv.eqmask(&tag, 0b000, 0b110);
        let stringp = self.bv.eqmask(&tag, 0b010, 0b110);
        let itemsp = self.bv.eqmask(&tag, 0b100, 0b110);
        let specialp = self.bv.eqmask(&tag, 0b111, 0b111);
        let tagp = self.bv.eqmask(&tag, 0b110, 0b111);

        let arrayp = self.bv.eqmask(&tag, 0b100, 0b111);
        let mapp = self.bv.eqmask(&tag, 0b101, 0b111);

        let count_24_31 = self.bv.eqmask(&count, 0b11000, 0b11000);
        let count0_23 = self.boolean.notb(&count_24_31);
        let count24_27 = self.bv.eqmask(&count, 0b11000, 0b11100);

        let count24 = self.bv.eqmask(&count, 0b11000, 0b11111);
        let count25 = self.bv.eqmask(&count, 0b11001, 0b11111);
        let count26 = self.bv.eqmask(&count, 0b11010, 0b11111);
        let count27 = self.bv.eqmask(&count, 0b11011, 0b11111);

        let count_20_23 = self.bv.eqmask(&count, 0b10100, 0b11100);
        let simple_specialp = self.boolean.andb(&specialp, &count_20_23);

        let length_plus_next_v8 = self.boolean.andb(&count24, &stringp);
        let count_is_next_v8 = self.boolean.andb(&count24, &itemsp);

        let count0_24 = self.boolean.orb(&count24, &count0_23);
        let atom_or_tag = self.boolean.orb(&atomp, &tagp);
        let good_count = self
            .boolean
            .orb(&count0_24, &self.boolean.andb(&atom_or_tag, &count24_27));

        let count_w = self.bv.zext::<5, N>(&count);

        let one = self.bv.of_u64::<N>(1);
        let two = self.bv.of_u64::<N>(2);
        let three = self.bv.of_u64::<N>(3);
        let five = self.bv.of_u64::<N>(5);
        let nine = self.bv.of_u64::<N>(9);

        let l24_25 = self.bv.select(&count[0], &three, &two);
        let l26_27 = self.bv.select(&count[0], &nine, &five);
        let l24_27 = self.bv.select(&count[1], &l26_27, &l24_25);

        let base_length = self.bv.select(&count0_23, &one, &l24_27);

        let str_23 = self.boolean.andb(&stringp, &count0_23);
        let adjust_if_string = self.bv.select(&str_23, &count_w, &self.bv.of_u64::<N>(0));
        let (length, assert) = self.bv.checked_add(&base_length, &adjust_if_string);

        let invalid_special = self
            .boolean
            .andb(&specialp, &self.boolean.notb(&simple_specialp));
        let invalid = self
            .boolean
            .orb(&invalid_special, &self.boolean.notb(&good_count));

        (
            CborDecodeResult {
                atomp,
                itemsp,
                stringp,
                arrayp,
                mapp,
                tagp,
                specialp,
                simple_specialp,
                count0_23,
                count24_27,
                count24,
                count25,
                count26,
                count27,
                length_plus_next_v8,
                count_is_next_v8,
                invalid,
                length,
                as_bits: v.clone(),
            },
            assert,
        )
    }
}
