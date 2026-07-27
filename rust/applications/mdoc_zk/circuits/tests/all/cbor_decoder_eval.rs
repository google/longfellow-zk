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

use circuits_bitvec::BitvecLogic;
use circuits_boolean::Boolean;
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;

fn compare_bool<L: compile_logic::Logic>(
    boolean: &Boolean<L>,
    want: bool,
    got: &circuits_boolean::Bitw<L>,
) where
    compile_logic::Eltw<L>: PartialEq + std::fmt::Debug,
{
    let got_val = boolean.as_eltw(got);
    let want_val = boolean.as_eltw(&boolean.konst(want));
    assert_eq!(got_val, want_val);
}

fn compare_bitvec<L: compile_logic::Logic, const N: usize>(
    boolean: &Boolean<L>,
    want: u64,
    got: &circuits_bitvec::Bitvec<L, N>,
) where
    compile_logic::Eltw<L>: PartialEq + std::fmt::Debug,
{
    for i in 0..N {
        let want_bit = ((want >> i) & 1) == 1;
        compare_bool(boolean, want_bit, got.bit(i));
    }
}

use mdoc_zk_circuits::cbor_decoder::{
    decode_one_v8, evaluate_given, CborByteDecoder, ConcreteGiven,
};

#[test]
fn test_cbor_decoder_exhaustive() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    let bv = BitvecLogic::new(&l);
    let boolean = Boolean::new(&l);
    let decoder = CborByteDecoder::new(&l);

    for v in 0..=255 {
        // Run simulator
        let expected = decode_one_v8(v);

        let concrete_given = ConcreteGiven { v };
        let wire_given = evaluate_given(&concrete_given, &bv);
        let (decoded, assert) = decoder.decode_one_v8::<8>(&wire_given.v);
        assert!(assert.is_ok());

        // Check outputs
        compare_bool(&boolean, expected.atomp, &decoded.atomp);
        compare_bool(&boolean, expected.itemsp, &decoded.itemsp);
        compare_bool(&boolean, expected.stringp, &decoded.stringp);
        compare_bool(&boolean, expected.arrayp, &decoded.arrayp);
        compare_bool(&boolean, expected.mapp, &decoded.mapp);
        compare_bool(&boolean, expected.tagp, &decoded.tagp);
        compare_bool(&boolean, expected.specialp, &decoded.specialp);
        compare_bool(&boolean, expected.simple_specialp, &decoded.simple_specialp);
        compare_bool(&boolean, expected.count0_23, &decoded.count0_23);
        compare_bool(&boolean, expected.count24_27, &decoded.count24_27);
        compare_bool(&boolean, expected.count24, &decoded.count24);
        compare_bool(&boolean, expected.count25, &decoded.count25);
        compare_bool(&boolean, expected.count26, &decoded.count26);
        compare_bool(&boolean, expected.count27, &decoded.count27);
        compare_bool(
            &boolean,
            expected.length_plus_next_v8,
            &decoded.length_plus_next_v8,
        );
        compare_bool(
            &boolean,
            expected.count_is_next_v8,
            &decoded.count_is_next_v8,
        );
        compare_bool(&boolean, expected.invalid, &decoded.invalid);

        // Check length
        compare_bitvec(&boolean, expected.length, &decoded.length);
    }
}
