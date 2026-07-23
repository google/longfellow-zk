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

use compile_algebra::{p256::P256Field, secp256r1::Secp256r1};
use compile_logic::eval::EvalLogic;
use mdoc_zk_circuits::{
    parse_test_data,
    signature::{derived, given, signature_input_of_parsed_mdoc, MdocSignature, SignatureMac},
};

use super::mdoc_signature_corruptors;

fn test_signature_circuit_independent_eval_generic(f: &P256Field) {
    let curve = Secp256r1::new(f);

    let (issuer_pk, parsed, _) = parse_test_data::<4, compile_algebra::CompileNat<4>>(
        &mdoc_zk_testcases::vectors::TEST_DATA,
    );

    let av_u128 = 0x112233445566778899aabbccddeeff00u128;
    let ap0_u128 = 0xabcdef0123456789abcdef0123456789u128;
    let ap1_u128 = 0xfedcba9876543210fedcba9876543210u128;
    let ap_keys = [[ap0_u128, ap1_u128]; 3];

    type L<'a, FC> = EvalLogic<'a, FC>;
    let lp256 = L::new(f);
    let sig_circuit = MdocSignature::new(&lp256, &curve);

    let sig_input = signature_input_of_parsed_mdoc(&parsed, issuer_pk);
    let mac_input = SignatureMac {
        mac_av: av_u128,
        mac_ap: ap_keys,
    };
    let fn_field = compile_algebra::q256::Q256Field::new();
    let given = given::<4, P256Field, _, _>(sig_input, mac_input, f, &fn_field, &curve);
    let derived = derived::<4, _, _, _>(f, &fn_field, &curve, &given).unwrap();

    let wire_given = mdoc_zk_circuits::signature::evaluate::evaluate_given::<Secp256r1<_>, _, _>(
        &lp256,
        &circuits_bitvec::BitvecLogic::new(&lp256),
        &given,
        f,
    );
    let wire_derived = mdoc_zk_circuits::signature::evaluate::evaluate_derived::<Secp256r1<_>, _, _>(
        &lp256,
        &circuits_bitvec::BitvecLogic::new(&lp256),
        &derived,
    );

    let assertion = sig_circuit.assert_signatures_and_macs(&wire_given, &wire_derived);
    assertion.unwrap();
}

#[test]
fn test_signature_circuit_independent_eval() {
    let f = P256Field::new();
    test_signature_circuit_independent_eval_generic(&f);
}

#[test]
fn test_eval_mdoc_signature_shared_corruptors() {
    let f = P256Field::new();
    let curve = Secp256r1::new(&f);
    let fn_field = compile_algebra::q256::Q256Field::new();

    let (issuer_pk, parsed, _) = parse_test_data::<4, compile_algebra::CompileNat<4>>(
        &mdoc_zk_testcases::vectors::TEST_DATA,
    );

    let base_sig_input = signature_input_of_parsed_mdoc(&parsed, issuer_pk);
    let base_mac_input = SignatureMac {
        mac_av: 0x112233445566778899aabbccddeeff00u128,
        mac_ap: [
            [
                0xabcdef0123456789abcdef0123456789u128,
                0xfedcba9876543210fedcba9876543210u128,
            ],
            [
                0xabcdef0123456789abcdef0123456789u128,
                0xfedcba9876543210fedcba9876543210u128,
            ],
            [
                0xabcdef0123456789abcdef0123456789u128,
                0xfedcba9876543210fedcba9876543210u128,
            ],
        ],
    };

    type L<'a, FC> = EvalLogic<'a, FC>;
    let lp256 = L::new(&f);
    let sig_circuit = MdocSignature::new(&lp256, &curve);

    let corruptors = mdoc_signature_corruptors::all_mdoc_signature_corruptors::<P256Field>();
    for c in corruptors {
        let mut sig_input = base_sig_input.clone();
        if let Some(ref f_input) = c.corrupt_input {
            f_input(&mut sig_input);
        }

        let mut given_val =
            given::<4, P256Field, _, _>(sig_input, base_mac_input.clone(), &f, &fn_field, &curve);
        let derived_val = derived::<4, _, _, _>(&f, &fn_field, &curve, &given_val).unwrap();

        if let Some(ref f_given) = c.corrupt_given {
            f_given(&mut given_val, &f);
        }

        let wire_given = mdoc_zk_circuits::signature::evaluate::evaluate_given::<Secp256r1<_>, _, _>(
            &lp256,
            &circuits_bitvec::BitvecLogic::new(&lp256),
            &given_val,
            &f,
        );
        let wire_derived =
            mdoc_zk_circuits::signature::evaluate::evaluate_derived::<Secp256r1<_>, _, _>(
                &lp256,
                &circuits_bitvec::BitvecLogic::new(&lp256),
                &derived_val,
            );

        let res = sig_circuit.assert_signatures_and_macs(&wire_given, &wire_derived);
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
