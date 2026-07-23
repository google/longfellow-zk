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
use circuits_sha256::{derived, evaluate_derived, evaluate_given, ConcreteGiven, Sha256};
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;

use super::test_support;

#[test]
fn test_eval_sha256() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);

    let input = [
        0, 0xdeadbeef, 0xbd5b7dde, 0x9c093ccd, 0x7ab6fbbc, 0x5964baab, 0x3812799a, 0x16c03889,
        0xf56df778, 0xd41bb667, 0xb2c97556, 0x91773445, 0x7024f334, 0x4ed2b223, 0x2d807112,
        0xc2e3001,
    ];
    let h0 = [
        0, 0xabadcafe, 0x575b95fc, 0x30960fa, 0xaeb72bf8, 0x5a64f6f6, 0x612c1f4, 0xb1c08cf2,
    ];
    let want = [
        0x656f967b, 0x508cb605, 0x109902c5, 0xbe9909c, 0x30ed1bc6, 0x8d3bb28c, 0x836c99a8,
        0x30731a12,
    ];

    // Run simulator and verify simulator outputs
    let given = ConcreteGiven {
        input_block: input,
        h0,
    };
    let derived = derived(&given);
    assert_eq!(derived.h1, want);

    // Build the EvalLogic inputs
    let given_wires = evaluate_given(&given, &bv);
    let derived_wires = evaluate_derived(&derived, &bv);

    // Run the round checker directly under EvalLogic.
    let sha256 = Sha256::new(&l);
    let assertion = sha256.assert_transform_block(&given_wires, &derived_wires);
    assertion.unwrap();
}

#[test]
fn test_eval_sha256_tampering() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);

    let input = [
        0, 0xdeadbeef, 0xbd5b7dde, 0x9c093ccd, 0x7ab6fbbc, 0x5964baab, 0x3812799a, 0x16c03889,
        0xf56df778, 0xd41bb667, 0xb2c97556, 0x91773445, 0x7024f334, 0x4ed2b223, 0x2d807112,
        0xc2e3001,
    ];
    let h0 = [
        0, 0xabadcafe, 0x575b95fc, 0x30960fa, 0xaeb72bf8, 0x5a64f6f6, 0x612c1f4, 0xb1c08cf2,
    ];

    let given = ConcreteGiven {
        input_block: input,
        h0,
    };
    let derived_val = derived(&given);
    let sha256 = Sha256::new(&l);

    let corruptors = test_support::all_sha256_corruptors();

    for c in corruptors {
        let mut g = given.clone();
        let mut d = derived_val.clone();
        (c.corrupt)(&mut g, &mut d);

        let given_wires = evaluate_given(&g, &bv);
        let derived_wires = evaluate_derived(&d, &bv);
        let res = sha256.assert_transform_block(&given_wires, &derived_wires);

        assert!(
            res.is_err(),
            "Corruptor '{}' failed to cause assertion error",
            c.name
        );
        let failed = res.failed_paths();
        assert!(
            failed.iter().any(|path| path == &c.expected_path),
            "Corruptor '{}' expected exact failure path '{}', actual failures: {failed:?}",
            c.name,
            c.expected_path
        );
    }
}
