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

use circuits_bitvec::{Bitvec, BitvecLogic};
use circuits_boolean::Boolean;
use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field, p256::P256Field, CompileNat};
use compile_logic::{eval::EvalLogic, Logic};
use core_algebra::Nat;
use mdoc_zk_circuits::{
    hash::{
        derived, evaluate_derived, evaluate_given, given, hash_input_of_parsed_mdoc, HashMac,
        MdocHash,
    },
    mso_attribute::{constants::K_ATTR_INDEX_BITS, DisclosedAttribute},
    parse_test_data,
};

use super::mdoc_hash_corruptors;

#[test]
fn test_eval_mdoc_hash_independent() {
    let fc = P256Field::new();
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&fc, &tracker);

    let mac_input = HashMac {
        mac_av: 0,
        mac_ap: [[0, 0]; 3],
    };
    let given = given::<4, _>(hash_input, mac_input);
    let derived = derived::<4, _>(&given);
    let mdoc = MdocHash::new(&l, given.hash_input.attrs.len());
    let bv = BitvecLogic::new(&l);
    let wire_given = evaluate_given(&l, &bv, &given);
    let wire_derived = evaluate_derived(&l, &bv, &derived);

    let assertion = mdoc.assert_valid_presentation_and_macs(&wire_given, &wire_derived);
    assertion.unwrap();
}

fn test_eval_mdoc_hash_generic<'a, const W: usize, FC>(l: &'a EvalLogic<'a, FC>)
where
    FC: CompileField + circuits_analog_adder::FieldWrappingSum,
{
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let mac_input = HashMac {
        mac_av: 0,
        mac_ap: [[0, 0]; 3],
    };
    let given = given::<4, _>(hash_input, mac_input);
    let derived = derived::<4, _>(&given);
    let bv = BitvecLogic::new(l);
    let wire_given = evaluate_given(l, &bv, &given);
    let wire_derived = evaluate_derived(l, &bv, &derived);

    let mdoc = MdocHash::new(l, given.hash_input.attrs.len());
    let assertion = mdoc.assert_valid_presentation(&wire_given, &wire_derived);

    assertion.unwrap();
}

fn test_eval_mdoc_hash_with_mac_generic<'a, const W: usize, FC>(l: &'a EvalLogic<'a, FC>)
where
    FC: CompileField + circuits_analog_adder::FieldWrappingSum,
{
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let av_u128 = 0x112233445566778899aabbccddeeff00u128;
    let ap0_u128 = 0xabcdef0123456789abcdef0123456789u128;
    let ap1_u128 = 0xfedcba9876543210fedcba9876543210u128;
    let ap_keys = [[ap0_u128, ap1_u128]; 3];

    let mac_input = HashMac {
        mac_av: av_u128,
        mac_ap: ap_keys,
    };
    let given = given::<4, _>(hash_input, mac_input);
    let derived = derived::<4, _>(&given);
    let bv = BitvecLogic::new(l);
    let wire_given = evaluate_given(l, &bv, &given);
    let wire_derived = evaluate_derived(l, &bv, &derived);

    let mdoc = MdocHash::new(l, given.hash_input.attrs.len());
    let assertion = mdoc.assert_valid_presentation_and_macs(&wire_given, &wire_derived);

    assertion.unwrap();
}

#[test]
fn test_eval_mdoc_hash() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    test_eval_mdoc_hash_generic::<2, _>(&l);
}

#[test]
fn test_eval_mdoc_hash_with_mac() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    test_eval_mdoc_hash_with_mac_generic::<2, _>(&l);
}

fn apply_negative_test_modifications<'a, FC: CompileField>(
    filename: &str,
    disclosed_attrs: &mut [DisclosedAttribute<EvalLogic<'a, FC>>],
    logic: &EvalLogic<'a, FC>,
    bitvec_logic: &BitvecLogic<EvalLogic<'a, FC>>,
) {
    let boolean = Boolean::new(logic);

    let eval_bitvec_u8 = |bv: &Bitvec<EvalLogic<'a, FC>, 8>| -> u8 {
        let mut val = 0u8;
        for i in 0..8 {
            let bit_eltw = bv.bit(i);
            let eltw = boolean.as_eltw(bit_eltw);
            if eltw.value != logic.field().zero() {
                val |= 1 << i;
            }
        }
        val
    };

    if filename.contains("fail-not_over_18") {
        let target_key = b"age_over_18";
        let mut target_cbor_key = vec![0x60 + target_key.len() as u8];
        target_cbor_key.extend_from_slice(target_key);

        for da in disclosed_attrs.iter_mut() {
            let mut key_bytes = [0u8; 32];
            for (byte, val) in key_bytes.iter_mut().zip(da.expected_name.data.iter()) {
                *byte = eval_bitvec_u8(val);
            }
            if key_bytes.starts_with(&target_cbor_key) {
                da.expected_cbor_value.data[0] = bitvec_logic.of_u8(0xf4);
                for j in 1..64 {
                    da.expected_cbor_value.data[j] = bitvec_logic.of_u8(0);
                }
                da.expected_cbor_value.len = bitvec_logic.of_u64::<K_ATTR_INDEX_BITS>(1);
            }
        }
    } else if filename.contains("fail-birthdate_0971_09_01") {
        let target_key = b"birth_date";
        let mut target_cbor_key = vec![0x60 + target_key.len() as u8];
        target_cbor_key.extend_from_slice(target_key);

        for da in disclosed_attrs.iter_mut() {
            let mut key_bytes = [0u8; 32];
            for (byte, val) in key_bytes.iter_mut().zip(da.expected_name.data.iter()) {
                *byte = eval_bitvec_u8(val);
            }
            if key_bytes.starts_with(&target_cbor_key) {
                let mut val = vec![0xD9, 0x03, 0xEC, 0x6A];
                val.extend_from_slice(b"0971-09-01");
                for (dst, &src) in da.expected_cbor_value.data.iter_mut().zip(val.iter()) {
                    *dst = bitvec_logic.of_u8(src);
                }
                for i in val.len()..64 {
                    da.expected_cbor_value.data[i] = bitvec_logic.of_u8(0);
                }
                da.expected_cbor_value.len =
                    bitvec_logic.of_u64::<K_ATTR_INDEX_BITS>(val.len() as u64);
            }
        }
    } else if filename.contains("fail-birthdate_1871_09_01") {
        let target_key = b"birth_date";
        let mut target_cbor_key = vec![0x60 + target_key.len() as u8];
        target_cbor_key.extend_from_slice(target_key);

        for da in disclosed_attrs.iter_mut() {
            let mut key_bytes = [0u8; 32];
            for (byte, val) in key_bytes.iter_mut().zip(da.expected_name.data.iter()) {
                *byte = eval_bitvec_u8(val);
            }
            if key_bytes.starts_with(&target_cbor_key) {
                let mut val = vec![0xD9, 0x03, 0xEC, 0x6A];
                val.extend_from_slice(b"1871-09-01");
                for (dst, &src) in da.expected_cbor_value.data.iter_mut().zip(val.iter()) {
                    *dst = bitvec_logic.of_u8(src);
                }
                for i in val.len()..64 {
                    da.expected_cbor_value.data[i] = bitvec_logic.of_u8(0);
                }
                da.expected_cbor_value.len =
                    bitvec_logic.of_u64::<K_ATTR_INDEX_BITS>(val.len() as u64);
            }
        }
    } else if filename.contains("fail-birthdate_1971_09_01_extra_0") {
        let target_key = b"birth_date";
        let mut target_cbor_key = vec![0x60 + target_key.len() as u8];
        target_cbor_key.extend_from_slice(target_key);

        for da in disclosed_attrs.iter_mut() {
            let mut key_bytes = [0u8; 32];
            for (byte, val) in key_bytes.iter_mut().zip(da.expected_name.data.iter()) {
                *byte = eval_bitvec_u8(val);
            }
            if key_bytes.starts_with(&target_cbor_key) {
                let mut val = vec![0xD9, 0x03, 0xEC, 0x6A];
                val.extend_from_slice(b"1971-09-010");
                for (dst, &src) in da.expected_cbor_value.data.iter_mut().zip(val.iter()) {
                    *dst = bitvec_logic.of_u8(src);
                }
                for i in val.len()..64 {
                    da.expected_cbor_value.data[i] = bitvec_logic.of_u8(0);
                }
                da.expected_cbor_value.len =
                    bitvec_logic.of_u64::<K_ATTR_INDEX_BITS>(val.len() as u64);
            }
        }
    }
}

fn test_all_mdoc_cases_generic<'a, const W: usize, FC>(l: &'a EvalLogic<'a, FC>)
where
    FC: CompileField + circuits_analog_adder::FieldWrappingSum,
{
    let mut count = 0;

    for case in mdoc_zk_testcases::vectors::ALL_TEST_CASES {
        let filename = case.name;
        println!("Running test case: {filename}");
        let is_negative = filename.starts_with("fail-");

        let (_, parsed, now) = parse_test_data::<4, CompileNat<4>>(case.data);
        let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

        let mac_input = HashMac {
            mac_av: 0,
            mac_ap: [[0, 0]; 3],
        };
        let given = given::<4, _>(hash_input, mac_input);
        let derived = derived::<4, _>(&given);
        let bitvec_logic = BitvecLogic::new(l);
        let mut wire_given = evaluate_given(l, &bitvec_logic, &given);
        let wire_derived = evaluate_derived(l, &bitvec_logic, &derived);

        apply_negative_test_modifications(
            filename,
            &mut wire_given.disclosed_attributes,
            l,
            &bitvec_logic,
        );

        let mdoc = MdocHash::new(l, given.hash_input.attrs.len());
        let assertion = mdoc.assert_valid_presentation(&wire_given, &wire_derived);
        if is_negative {
            assert!(
                assertion.is_err(),
                "Expected negative test to fail: {filename}"
            );
        } else {
            assertion.unwrap();
        }
        count += 1;
    }
    assert!(count > 0, "No test cases found/executed!");
    println!("Successfully verified {count} test cases.");
}

#[test]
fn test_all_mdoc_cases() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    test_all_mdoc_cases_generic::<2, _>(&l);
}

#[test]
fn test_namespace_mixup_exploit() {
    let f = Gf2_128Field::new();

    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let mut hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let doc_type_off = 23 + parsed.doc_type_offset_in_mso;
    hash_input.cbor_mso[doc_type_off] ^= 1;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&hash_input.cbor_mso);
    let sha_result = hasher.finalize();

    hash_input.issuer_sig_e = CompileNat::<4>::from_bytes_be(&sha_result);

    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);

    let mac_input = HashMac {
        mac_av: 0,
        mac_ap: [[0, 0]; 3],
    };
    let given = given::<4, _>(hash_input, mac_input);
    let derived = derived::<4, _>(&given);
    let bv = BitvecLogic::new(&l);
    let mut tampered_given = given.clone();
    tampered_given.doc_type_offset_in_preimage += 1;

    let wire_given = evaluate_given(&l, &bv, &tampered_given);
    let wire_derived = evaluate_derived(&l, &bv, &derived);

    let mdoc = MdocHash::new(&l, tampered_given.hash_input.attrs.len());
    let res = mdoc.assert_valid_presentation(&wire_given, &wire_derived);

    assert!(
        res.is_err(),
        "Expected tampered namespace/docType to fail circuit evaluation"
    );
    res.assert_any_failed_at(
        "assert_valid_presentation/assert_mso_doc_type/cbor_header/cbor_header.0/header_byte",
    );
}

#[test]
fn test_eval_mdoc_hash_shared_corruptors() {
    let f = Gf2_128Field::new();

    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let base_hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
    let base_mac_input = HashMac {
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

    let corruptors = mdoc_hash_corruptors::all_mdoc_hash_corruptors();
    for c in corruptors {
        let tracker = compile_logic::tracker::AssertionTracker::new();
        let l = EvalLogic::new_with_tracker(&f, &tracker);
        let bv = BitvecLogic::new(&l);
        let base_given = given::<4, _>(base_hash_input.clone(), base_mac_input.clone());
        let derived_val = derived::<4, _>(&base_given);

        let mut tampered_given = base_given.clone();
        (c.corrupt)(&mut tampered_given);

        let wire_given = evaluate_given(&l, &bv, &tampered_given);
        let wire_derived = evaluate_derived(&l, &bv, &derived_val);

        let mdoc = MdocHash::new(&l, tampered_given.hash_input.attrs.len());
        let res = mdoc.assert_valid_presentation_and_macs(&wire_given, &wire_derived);
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
        res.assert_any_failed_at(&c.expected_path);
    }
}

#[test]
fn test_check_doc_type_suppression() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    let bv = BitvecLogic::new(&l);

    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);

    // 1. When suppress_doc_type_check is false and expected_doc_type matches, evaluation succeeds.
    let mut hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
    hash_input.suppress_doc_type_check = false;
    hash_input.expected_doc_type = b"org.iso.18013.5.1.mDL".to_vec();

    let mac_input = HashMac {
        mac_av: 0,
        mac_ap: [[0, 0]; 3],
    };
    let given_val = given::<4, _>(hash_input.clone(), mac_input.clone());
    let derived_val = derived::<4, _>(&given_val);
    let wire_given = evaluate_given(&l, &bv, &given_val);
    let wire_derived = evaluate_derived(&l, &bv, &derived_val);
    let mdoc = MdocHash::new(&l, given_val.hash_input.attrs.len());
    let res = mdoc.assert_valid_presentation(&wire_given, &wire_derived);
    res.unwrap();

    // 2. When suppress_doc_type_check is false and expected_doc_type is wrong, evaluation fails.
    let mut wrong_hash_input = hash_input.clone();
    wrong_hash_input.expected_doc_type = b"wrong.doc.type.foo.bar".to_vec();
    let given_wrong = given::<4, _>(wrong_hash_input, mac_input.clone());

    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    let bv = BitvecLogic::new(&l);

    let wire_given_wrong = evaluate_given(&l, &bv, &given_wrong);
    let wire_derived_wrong = evaluate_derived(&l, &bv, &derived_val);

    let mdoc = MdocHash::new(&l, given_wrong.hash_input.attrs.len());
    let res_wrong = mdoc.assert_valid_presentation_and_macs(&wire_given_wrong, &wire_derived_wrong);
    assert!(res_wrong.is_err());
    let failed_all = res_wrong.failed_paths();
    println!("ALL FAILED PATHS: {:?}", failed_all);
    res_wrong.assert_any_failed_at(
        "assert_valid_presentation_and_macs/assert_valid_presentation/assert_mso_doc_type/value_bytes/value_bytes.0/doc_type_byte"
    );

    // 3. When suppress_doc_type_check is true, even with wrong expected_doc_type, evaluation
    //    succeeds (check suppressed).
    let mut suppressed_hash_input = hash_input.clone();
    suppressed_hash_input.suppress_doc_type_check = true;
    suppressed_hash_input.expected_doc_type = b"wrong.doc.type.foo.bar".to_vec();
    let given_suppressed = given::<4, _>(suppressed_hash_input, mac_input);
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);
    let bv = BitvecLogic::new(&l);

    let wire_given_suppressed = evaluate_given(&l, &bv, &given_suppressed);
    let wire_derived_suppressed = evaluate_derived(&l, &bv, &derived_val);
    let mdoc = MdocHash::new(&l, given_suppressed.hash_input.attrs.len());
    let res_suppressed =
        mdoc.assert_valid_presentation(&wire_given_suppressed, &wire_derived_suppressed);
    res_suppressed.unwrap();
}
