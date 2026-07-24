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

use compile_algebra::{
    gf2_128::Gf2_128Field, p256::P256Field, q256::Q256Field, secp256r1::Secp256r1, CompileNat,
};
use compile_logic::eval::EvalLogic;
use mdoc_zk_circuits::{
    hash::{
        derived as hash_gen_derived, given as hash_given, hash_input_of_parsed_mdoc, HashInput,
        HashMac, MdocHash,
    },
    parse_test_data,
    signature::{
        derived as sig_gen_derived, given as sig_given, signature_input_of_parsed_mdoc,
        MdocSignature, SignatureInput, SignatureMac,
    },
};

#[allow(clippy::too_many_arguments)]
fn run_two_circuit_setup_generic<'a>(
    f: &P256Field,
    fn_field: &Q256Field,
    curve: &Secp256r1<P256Field>,
    lp256: &EvalLogic<'a, P256Field>,
    l128: &EvalLogic<'a, Gf2_128Field>,
    mdoc_sig_circuit: &MdocSignature<'a, 4, Secp256r1<P256Field>, EvalLogic<'a, P256Field>>,
    mdoc_hashes: &[MdocHash<'a, EvalLogic<'a, Gf2_128Field>>; 4],
    test_data: (HashInput, SignatureInput),
) {
    let (hash_input_data, sig_input_data) = super::test_support::prepare_mock_signatures::<
        4,
        _,
        _,
        _,
    >(curve, f, fn_field, test_data.0, test_data.1);
    let av_u128 = 0x112233445566778899aabbccddeeff00u128;
    let ap0_u128 = 0xabcdef0123456789abcdef0123456789u128;
    let ap1_u128 = 0xfedcba9876543210fedcba9876543210u128;
    let ap_keys = [[ap0_u128, ap1_u128]; 3];

    // EVALUATE HASH CIRCUIT (over GF(2^128))
    let mac_input_hash = HashMac {
        mac_av: av_u128,
        mac_ap: ap_keys,
    };
    let hash_given = hash_given::<4, _>(hash_input_data, mac_input_hash);
    let hash_derived = hash_gen_derived::<4, _>(&hash_given);
    let nattrs = hash_given.hash_input.attrs.len();
    let mdoc_hash = &mdoc_hashes[nattrs.saturating_sub(1).min(3)];
    let wire_hash_given = mdoc_zk_circuits::hash::evaluate::evaluate_given(
        l128,
        &circuits_bitvec::BitvecLogic::new(l128),
        &hash_given,
    );
    let wire_hash_derived = mdoc_zk_circuits::hash::evaluate::evaluate_derived(
        l128,
        &circuits_bitvec::BitvecLogic::new(l128),
        &hash_derived,
    );

    let assertion =
        mdoc_hash.assert_valid_presentation_and_macs(&wire_hash_given, &wire_hash_derived);
    assertion.unwrap();

    // EVALUATE SIGNATURE CIRCUIT (over P-256 prime field)
    let sig_mac_input = SignatureMac {
        mac_av: av_u128,
        mac_ap: ap_keys,
    };
    let sig_given =
        sig_given::<4, P256Field, _, _>(sig_input_data, sig_mac_input, f, fn_field, curve);
    let sig_derived = sig_gen_derived::<4, _, _, _>(f, fn_field, curve, &sig_given).unwrap();

    let wire_sig_given = mdoc_zk_circuits::signature::evaluate::evaluate_given::<Secp256r1<_>, _, _>(
        lp256,
        &circuits_bitvec::BitvecLogic::new(lp256),
        &sig_given,
        f,
    );
    let wire_sig_derived =
        mdoc_zk_circuits::signature::evaluate::evaluate_derived::<Secp256r1<_>, _, _>(
            lp256,
            &circuits_bitvec::BitvecLogic::new(lp256),
            &sig_derived,
        );

    let sig_assertion =
        mdoc_sig_circuit.assert_signatures_and_macs(&wire_sig_given, &wire_sig_derived);
    sig_assertion.unwrap();
}

#[test]
fn test_all_two_circuit_setups() {
    let p256 = P256Field::new();
    let fn_field = Q256Field::new();
    let f128_compile = Gf2_128Field::new();
    let curve = Secp256r1::new(&p256);
    let p256_tracker = compile_logic::tracker::AssertionTracker::new();
    let lp256 = EvalLogic::new_with_tracker(&p256, &p256_tracker);
    let f128_tracker = compile_logic::tracker::AssertionTracker::new();
    let l128 = EvalLogic::new_with_tracker(&f128_compile, &f128_tracker);
    let mdoc_sig_circuit = MdocSignature::new(&lp256, &curve);
    let mdoc_hashes = [
        MdocHash::new(&l128, 1),
        MdocHash::new(&l128, 2),
        MdocHash::new(&l128, 3),
        MdocHash::new(&l128, 4),
    ];

    for case in mdoc_zk_testcases::vectors::ALL_TEST_CASES {
        let filename = case.name;
        if filename.starts_with("fail-") {
            continue;
        }
        let (issuer_pk, parsed, now) = parse_test_data::<4, CompileNat<4>>(case.data);
        let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
        let sig_input = signature_input_of_parsed_mdoc(&parsed, issuer_pk);
        run_two_circuit_setup_generic(
            &p256,
            &fn_field,
            &curve,
            &lp256,
            &l128,
            &mdoc_sig_circuit,
            &mdoc_hashes,
            (hash_input, sig_input),
        );
    }
}
