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
use circuits_mac::{circuit::MAC, concrete::given, evaluate::evaluate_given};
use compile_algebra::{field::CompileField, p256::P256Field};
use compile_logic::eval::EvalLogic;

use super::test_support;

fn test_mac_direct_eval_generic<F: CompileField>(fc: &F) {
    let test_msg = [0x5au8; 32];
    let av_val: u128 = 0x112233445566778899aabbccddeeff00;
    let ap0_val: u128 = 0xabcdef0123456789abcdef0123456789;
    let ap1_val: u128 = 0xfedcba9876543210fedcba9876543210;

    let concrete_given = given(test_msg, av_val, [ap0_val, ap1_val]);

    type L<'a, FC> = EvalLogic<'a, FC>;
    let lp = L::new(fc);
    let bv = BitvecLogic::new(&lp);
    let mac_circuit = MAC::new(&lp);

    let wire_given = evaluate_given(&lp, &bv, &concrete_given);

    let assertion = mac_circuit.assert_mac(&wire_given);
    assertion.unwrap();

    // Run shared corruptors test
    let corruptors = test_support::all_mac_corruptors();
    for c in corruptors {
        let mut g = concrete_given.clone();
        (c.corrupt)(&mut g);

        let wire_given_tampered = evaluate_given(&lp, &bv, &g);
        let res = mac_circuit.assert_mac(&wire_given_tampered);

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

#[test]
fn test_mac_direct_eval() {
    let fc = P256Field::new();
    test_mac_direct_eval_generic(&fc);
}
