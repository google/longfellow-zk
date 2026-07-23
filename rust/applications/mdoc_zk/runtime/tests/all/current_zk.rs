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

use compile_algebra::CompileNat;
use core_algebra::Nat;
use mdoc_zk_circuits::parse_test_data;
use mdoc_zk_runtime::{
    provider, req_attr, run_mdoc_prover_inner, run_mdoc_verifier_inner, RequestedAttribute,
};

struct TestCircuits {
    circuits: std::collections::HashMap<usize, provider::ProvidedCircuit>,
}

impl TestCircuits {
    fn compile_all() -> Self {
        let results = mdoc_zk_compile::compile_all_circuits();
        let mut circuits = std::collections::HashMap::new();
        for (idx, res) in results.into_iter().enumerate() {
            let nattrs = idx + 1;
            let (lfa_bytes, _, _) = res.expect("Failed to compile circuit");
            let spec = &mdoc_zk_runtime::CURRENT_ZK_SPECS[nattrs - 1];
            let archive = core_proto::archive::CircuitArchive::from_bytes(&lfa_bytes).unwrap();
            let compressed =
                zstd::encode_all(&lfa_bytes[..], mdoc_zk_circuits::config::K_ZSTD_LEVEL).unwrap();
            circuits.insert(
                nattrs,
                provider::ProvidedCircuit {
                    name: spec.combined_hash_hex(),
                    spec: *spec,
                    archive,
                    compressed,
                },
            );
        }
        Self { circuits }
    }

    fn get(&self, nattrs: usize) -> Option<&provider::ProvidedCircuit> {
        self.circuits.get(&nattrs)
    }
}

fn run_current_mdoc_flow(test_circuits: &TestCircuits) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";

    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(req_attrs.len()).unwrap();

    let mut rng = runtime_random::DeterministicRng::new(42);
    let zkproof = run_mdoc_prover_inner(
        &provided.spec,
        &provided.compressed,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng,
    )
    .unwrap();

    assert!(!zkproof.is_empty());

    let verify_res = run_mdoc_verifier_inner(
        &provided.spec,
        &provided.compressed,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &zkproof,
    );
    assert!(
        verify_res.is_ok(),
        "Verification failed: {:?}",
        verify_res.err()
    );
}

fn run_current_mdoc_subset_flow(test_circuits: &TestCircuits) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .step_by(2)
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";

    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(req_attrs.len()).unwrap();

    let mut rng = runtime_random::DeterministicRng::new(42);
    let zkproof = run_mdoc_prover_inner(
        &provided.spec,
        &provided.compressed,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng,
    )
    .unwrap();

    assert!(!zkproof.is_empty());

    let verify_res = run_mdoc_verifier_inner(
        &provided.spec,
        &provided.compressed,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &zkproof,
    );
    assert!(
        verify_res.is_ok(),
        "Verification failed: {:?}",
        verify_res.err()
    );
}

fn run_current_mdoc_all_positive_cases(test_circuits: &TestCircuits) {
    for case in mdoc_zk_testcases::vectors::ALL_TEST_CASES {
        if case.name.starts_with("fail-") {
            continue;
        }
        let (_, parsed, now) = parse_test_data::<4, CompileNat<4>>(case.data);
        let nattrs = parsed.attrs.len();
        if nattrs == 0 || nattrs > 4 {
            continue;
        }
        let ns = if case.data.doc_type.starts_with("org.iso.18013.5.1") {
            "org.iso.18013.5.1"
        } else {
            case.data.doc_type
        };
        let req_attrs: Vec<RequestedAttribute> = parsed
            .attrs
            .iter()
            .take(nattrs)
            .map(|a| req_attr(ns, &a.name, &a.cbor_value))
            .collect();

        if !mdoc_zk_runtime::same_namespace(&req_attrs) {
            continue;
        }
        if req_attrs
            .iter()
            .any(|a| !mdoc_zk_runtime::circuit_supports(&a.cbor_value))
        {
            continue;
        }

        let Some(provided) = test_circuits.get(nattrs) else {
            continue;
        };

        let mut rng = runtime_random::DeterministicRng::new(42);

        let zkproof = run_mdoc_prover_inner(
            &provided.spec,
            &provided.compressed,
            case.data.mdoc,
            case.data.pkx,
            case.data.pky,
            case.data.transcript,
            &req_attrs,
            now,
            case.data.doc_type,
            &mut rng,
        )
        .unwrap_or_else(|_| panic!("Prover failed for positive case: {}", case.name));

        assert!(!zkproof.is_empty(), "Proof empty for {}", case.name);

        let verify_res = run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            case.data.pkx,
            case.data.pky,
            case.data.transcript,
            &req_attrs,
            now,
            case.data.doc_type,
            &zkproof,
        );
        assert!(
            verify_res.is_ok(),
            "Verifier failed for positive case {}: {:?}",
            case.name,
            verify_res.err()
        );
    }
}

fn run_current_mdoc_all_negative_cases(test_circuits: &TestCircuits) {
    for case in mdoc_zk_testcases::vectors::ALL_TEST_CASES {
        if !case.name.starts_with("fail-") {
            continue;
        }
        let (_, parsed, now) = parse_test_data::<4, CompileNat<4>>(case.data);
        let nattrs = parsed.attrs.len();
        if nattrs == 0 || nattrs > 4 {
            continue;
        }
        let ns = if case.data.doc_type.starts_with("org.iso.18013.5.1") {
            "org.iso.18013.5.1"
        } else {
            case.data.doc_type
        };
        let mut req_attrs: Vec<RequestedAttribute> = parsed
            .attrs
            .iter()
            .take(nattrs)
            .map(|a| req_attr(ns, &a.name, &a.cbor_value))
            .collect();

        if case.name.contains("not_over_18") {
            for a in &mut req_attrs {
                if a.id == b"age_over_18" {
                    a.cbor_value = vec![0xf4]; // boolean false
                }
            }
        } else if case.name.contains("0971_09_01") {
            for a in &mut req_attrs {
                if a.id == b"birth_date" {
                    a.cbor_value = vec![
                        0xD9, 0x03, 0xEC, 0x6A, b'0', b'9', b'7', b'1', b'-', b'0', b'9', b'-',
                        b'0', b'1',
                    ];
                }
            }
        } else if case.name.contains("1871_09_01") {
            for a in &mut req_attrs {
                if a.id == b"birth_date" {
                    a.cbor_value = vec![
                        0xD9, 0x03, 0xEC, 0x6A, b'1', b'8', b'7', b'1', b'-', b'0', b'9', b'-',
                        b'0', b'1',
                    ];
                }
            }
        } else if case.name.contains("extra_0") {
            for a in &mut req_attrs {
                if a.id == b"birth_date" {
                    a.cbor_value = vec![
                        0xD9, 0x03, 0xEC, 0x6A, b'1', b'9', b'7', b'1', b'-', b'0', b'9', b'-',
                        b'0', b'1', b'0',
                    ];
                }
            }
        }

        let Some(provided) = test_circuits.get(nattrs) else {
            continue;
        };

        let mut rng = runtime_random::DeterministicRng::new(42);

        let zkproof_res = run_mdoc_prover_inner(
            &provided.spec,
            &provided.compressed,
            case.data.mdoc,
            case.data.pkx,
            case.data.pky,
            case.data.transcript,
            &req_attrs,
            now,
            case.data.doc_type,
            &mut rng,
        );
        assert!(
            zkproof_res.is_err(),
            "Prover unexpectedly succeeded for fail case: {}",
            case.name
        );
    }
}

fn run_current_verifier_negative_cases(test_circuits: &TestCircuits) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";

    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(req_attrs.len()).unwrap();
    let mut rng = runtime_random::DeterministicRng::new(42);
    let zkproof = run_mdoc_prover_inner(
        &provided.spec,
        &provided.compressed,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng,
    )
    .unwrap();

    // 1. Wrong PKX
    let invalid_key_x_string = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            invalid_key_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong PKX"
    );

    // 2. Wrong PKY
    let invalid_key_y_formatted =
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            invalid_key_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong PKY"
    );

    // 3. Wrong Transcript
    let mut bad_transcript = transcript.to_vec();
    if bad_transcript.is_empty() {
        bad_transcript.push(0xff);
    } else {
        bad_transcript[0] ^= 0xff;
    }
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            &bad_transcript,
            &req_attrs,
            now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong transcript"
    );

    // 4. Wrong Timestamp
    let bad_now = "2099-01-01T00:00:00Z";
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            bad_now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong timestamp"
    );

    // 5. Wrong Doc Type
    let bad_doc_type = "org.iso.18013.5.1.fake";
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            bad_doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong doc_type"
    );

    // 6. Empty Doc Type
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            "",
            &zkproof
        )
        .is_err(),
        "Verifier should reject empty doc_type"
    );

    // 7. Attribute Mismatch - Wrong Value
    let mut bad_attrs_val = req_attrs.clone();
    bad_attrs_val[0].cbor_value = vec![0x63, b'f', b'o', b'o']; // Text "foo"
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &bad_attrs_val,
            now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong attribute value"
    );

    // 8. Attribute Mismatch - Wrong ID
    let mut bad_attrs_id = req_attrs.clone();
    bad_attrs_id[0].id = vec![b'x'];
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &bad_attrs_id,
            now,
            doc_type,
            &zkproof
        )
        .is_err(),
        "Verifier should reject wrong attribute id"
    );

    // 9. Attribute Number Mismatch - Too Few
    assert_eq!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &[],
            now,
            doc_type,
            &zkproof
        ),
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::AttributeNumberMismatch),
        "Verifier should reject empty attributes slice"
    );

    // 10. Attribute Number Mismatch - Too Many
    let mut two_attrs = req_attrs.clone();
    two_attrs.push(req_attrs[0].clone());
    assert_eq!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &two_attrs,
            now,
            doc_type,
            &zkproof
        ),
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::AttributeNumberMismatch),
        "Verifier should reject too many attributes"
    );

    // 11. Unsupported ZkSpec Version (version 0 and version 99)
    let mut bad_spec_0 = provided.spec;
    bad_spec_0.version = 0;
    assert_eq!(
        run_mdoc_verifier_inner(
            &bad_spec_0,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &zkproof
        ),
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::InvalidZkSpecVersion),
        "Verifier should reject version 0"
    );

    let mut bad_spec_99 = provided.spec;
    bad_spec_99.version = 99;
    assert_eq!(
        run_mdoc_verifier_inner(
            &bad_spec_99,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &zkproof
        ),
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::InvalidZkSpecVersion),
        "Verifier should reject version 99"
    );
}

fn run_current_verifier_attribute_reordering_and_duplicates(test_circuits: &TestCircuits) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let all_req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let two_attrs = if all_req_attrs.len() >= 2 {
        vec![all_req_attrs[0].clone(), all_req_attrs[1].clone()]
    } else {
        let mut second = all_req_attrs[0].clone();
        second.id = b"fake_attr".to_vec();
        vec![all_req_attrs[0].clone(), second]
    };

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";
    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(2).unwrap();
    let mut rng = runtime_random::DeterministicRng::new(42);
    let zkproof_res = run_mdoc_prover_inner(
        &provided.spec,
        &provided.compressed,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &two_attrs,
        now,
        doc_type,
        &mut rng,
    );
    if let Ok(zkproof) = zkproof_res {
        let reordered = vec![two_attrs[1].clone(), two_attrs[0].clone()];
        assert!(
            run_mdoc_verifier_inner(
                &provided.spec,
                &provided.compressed,
                &pubkey_x_string,
                &pubkey_y_formatted,
                transcript,
                &reordered,
                now,
                doc_type,
                &zkproof
            )
            .is_err(),
            "Verifier should reject reordered attributes"
        );

        let duplicates = vec![two_attrs[0].clone(), two_attrs[0].clone()];
        assert!(
            run_mdoc_verifier_inner(
                &provided.spec,
                &provided.compressed,
                &pubkey_x_string,
                &pubkey_y_formatted,
                transcript,
                &duplicates,
                now,
                doc_type,
                &zkproof
            )
            .is_err(),
            "Verifier should reject duplicate attributes"
        );
    }
}

fn run_current_verifier_bad_proofs(test_circuits: &TestCircuits) {
    let (issuer_pk, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let req_attrs: Vec<RequestedAttribute> = parsed
        .attrs
        .iter()
        .map(|a| req_attr("org.iso.18013.5.1", &a.name, &a.cbor_value))
        .collect();

    let mdoc_bytes = mdoc_zk_testcases::vectors::TEST_DATA.mdoc;
    let transcript = mdoc_zk_testcases::vectors::TEST_DATA.transcript;
    let doc_type = "org.iso.18013.5.1.mDL";
    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(req_attrs.len()).unwrap();
    let mut rng = runtime_random::DeterministicRng::new(42);
    let zkproof = run_mdoc_prover_inner(
        &provided.spec,
        &provided.compressed,
        mdoc_bytes,
        &pubkey_x_string,
        &pubkey_y_formatted,
        transcript,
        &req_attrs,
        now,
        doc_type,
        &mut rng,
    )
    .unwrap();

    // 1. Empty proof
    assert_eq!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &[]
        ),
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::HashParsingFailure),
        "Verifier should reject empty proof"
    );

    // 2. Random bytes of various lengths
    for len in [10, 100, 1000, 5000, 10000, 20000] {
        let random_bytes: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i * 37 % 256).unwrap())
            .collect();
        assert!(
            run_mdoc_verifier_inner(
                &provided.spec,
                &provided.compressed,
                &pubkey_x_string,
                &pubkey_y_formatted,
                transcript,
                &req_attrs,
                now,
                doc_type,
                &random_bytes
            )
            .is_err(),
            "Verifier should reject random proof of len {len}"
        );
    }

    // 3. Bit/byte flips in valid proof
    for idx in [10, 100, zkproof.len() / 2, zkproof.len().saturating_sub(10)] {
        if idx < zkproof.len() {
            let mut flipped = zkproof.clone();
            flipped[idx] ^= 0x55;
            assert!(
                run_mdoc_verifier_inner(
                    &provided.spec,
                    &provided.compressed,
                    &pubkey_x_string,
                    &pubkey_y_formatted,
                    transcript,
                    &req_attrs,
                    now,
                    doc_type,
                    &flipped
                )
                .is_err(),
                "Verifier should reject proof with byte flip at index {idx}"
            );
        }
    }

    // 4. Truncated proof
    if zkproof.len() > 100 {
        let truncated = &zkproof[..zkproof.len() - 100];
        assert!(
            run_mdoc_verifier_inner(
                &provided.spec,
                &provided.compressed,
                &pubkey_x_string,
                &pubkey_y_formatted,
                transcript,
                &req_attrs,
                now,
                doc_type,
                truncated
            )
            .is_err(),
            "Verifier should reject truncated proof"
        );
    }

    // 5. Extended proof with trailing garbage
    let mut extended = zkproof.clone();
    extended.extend_from_slice(&[0xaa; 100]);
    assert!(
        run_mdoc_verifier_inner(
            &provided.spec,
            &provided.compressed,
            &pubkey_x_string,
            &pubkey_y_formatted,
            transcript,
            &req_attrs,
            now,
            doc_type,
            &extended
        )
        .is_err(),
        "Verifier should reject proof with trailing garbage"
    );
}

fn run_circuit_supports_cbor() {
    use mdoc_zk_runtime::circuit_supports;

    // Valid Inputs (ported from C++ CborValidate.ValidInputs)
    assert!(circuit_supports(&[0x00]), "Integer 0");
    assert!(circuit_supports(&[0x01]), "Integer 1");
    assert!(circuit_supports(&[0x20]), "Integer -1");
    assert!(circuit_supports(&[0xF5]), "Boolean True");
    assert!(circuit_supports(&[0xF4]), "Boolean False");
    assert!(circuit_supports(&[0x60]), "Empty String");
    assert!(circuit_supports(&[0x61, b'a']), "String 'a'");
    assert!(circuit_supports(&[0x40]), "Empty Bytes");
    assert!(circuit_supports(&[0x41, 0x01]), "Bytes 0x01");

    // Fulldate: Tag 1004 (D9 03 EC) + String (6A) + 10 bytes -> 14 bytes
    let mut fulldate = vec![0xD9, 0x03, 0xEC, 0x6A];
    fulldate.extend_from_slice(&[b'0'; 10]);
    assert_eq!(fulldate.len(), 14);
    assert!(circuit_supports(&fulldate), "Fulldate 14 bytes");

    // Tdate: Tag 0 (C0) + String (74, len 20) + 20 bytes -> 22 bytes
    let mut tdate = vec![0xC0, 0x74];
    tdate.extend_from_slice(&[b'0'; 20]);
    assert_eq!(tdate.len(), 22);
    assert!(circuit_supports(&tdate), "Tdate 22 bytes");

    // Invalid Inputs (ported from C++ CborValidate.InvalidInputs)
    assert!(!circuit_supports(&[]), "Empty slice");
    assert!(!circuit_supports(&[0x80]), "Array not allowed");
    assert!(!circuit_supports(&[0xA0]), "Map not allowed");
    assert!(
        !circuit_supports(&[0x61]),
        "Malformed length (missing data)"
    );
    assert!(
        !circuit_supports(&[0xF5, 0xF5]),
        "Boolean with trailing data"
    );
    assert!(!circuit_supports(&[0xC2, 0x40]), "Unsupported Tag 2");

    // Fulldate wrong lengths (expected 14)
    let mut fulldate_wrong = vec![0xD9, 0x03, 0xEC, 0x69]; // String len 9
    fulldate_wrong.extend_from_slice(&[b'0'; 9]);
    assert_eq!(fulldate_wrong.len(), 13);
    assert!(!circuit_supports(&fulldate_wrong), "Fulldate len 13");
    fulldate_wrong.extend_from_slice(&[b'0'; 2]);
    assert!(!circuit_supports(&fulldate_wrong), "Fulldate len 15");
    fulldate_wrong.extend_from_slice(&[b'0'; 7]);
    assert!(!circuit_supports(&fulldate_wrong), "Fulldate len 22");

    // Fulldate inner type mismatch (Tag 1004 + Integer 0)
    assert!(
        !circuit_supports(&[0xD9, 0x03, 0xEC, 0x00]),
        "Fulldate inner integer"
    );

    // Tdate wrong lengths (expected 22)
    let mut tdate_short = vec![0xC0, 0x73]; // String len 19
    tdate_short.extend_from_slice(&[b'0'; 19]);
    assert_eq!(tdate_short.len(), 21);
    assert!(!circuit_supports(&tdate_short), "Tdate len 21");

    // Tdate inner type mismatch (Tag 0 + Integer 0)
    assert!(!circuit_supports(&[0xC0, 0x00]), "Tdate inner integer");

    // Trailing garbage after valid integer
    assert!(
        !circuit_supports(&[0x01, 0x01]),
        "Valid integer followed by garbage"
    );
}

fn run_namespace_mixup(test_circuits: &TestCircuits) {
    use mdoc_zk_runtime::{req_attr, same_namespace};

    let attr1 = req_attr("org.iso.18013.5.1", "family_name", [0x63, b'f', b'o', b'o']);
    let attr2 = req_attr("org.iso.18013.5.1", "birth_date", [0x63, b'b', b'a', b'r']);
    let attr3 = req_attr(
        "aamva.test.namespace",
        "family_name",
        [0x63, b'b', b'a', b'z'],
    );

    assert!(
        same_namespace(&[attr1.clone(), attr2.clone()]),
        "Same namespace should be true"
    );
    assert!(
        !same_namespace(&[attr1.clone(), attr3.clone()]),
        "Mixed namespace should be false"
    );

    let (issuer_pk, _, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let pubkey_x_string = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.0.to_bytes_le()).to_str_radix(16)
    );
    let pubkey_y_formatted = format!(
        "0x{}",
        num_bigint::BigUint::from_bytes_le(&issuer_pk.1.to_bytes_le()).to_str_radix(16)
    );

    let provided = test_circuits.get(2).unwrap();
    let mixed_attrs = vec![attr1, attr3];

    let res = run_mdoc_verifier_inner(
        &provided.spec,
        &provided.compressed,
        &pubkey_x_string,
        &pubkey_y_formatted,
        mdoc_zk_testcases::vectors::TEST_DATA.transcript,
        &mixed_attrs,
        now,
        "org.iso.18013.5.1.mDL",
        &[0u8; 1000],
    );
    assert_eq!(
        res,
        Err(mdoc_zk_runtime::MdocVerifierErrorCode::AttributeNumberMismatch),
        "Verifier should reject mixed namespace"
    );
}

fn run_current_circuit_hashes(test_circuits: &TestCircuits) {
    for nattrs in 1..=4 {
        let p = test_circuits.get(nattrs).expect("circuit missing");
        let expected_spec = &mdoc_zk_runtime::CURRENT_ZK_SPECS[nattrs - 1];
        assert_eq!(
            p.spec, *expected_spec,
            "Current spec mismatch for nattrs={nattrs}"
        );
    }
}

#[test]
fn test_all_current_zk() {
    let test_circuits = TestCircuits::compile_all();
    run_current_circuit_hashes(&test_circuits);
    run_current_mdoc_flow(&test_circuits);
    run_current_mdoc_subset_flow(&test_circuits);
    run_current_mdoc_all_positive_cases(&test_circuits);
    run_current_mdoc_all_negative_cases(&test_circuits);
    run_current_verifier_negative_cases(&test_circuits);
    run_current_verifier_attribute_reordering_and_duplicates(&test_circuits);
    run_current_verifier_bad_proofs(&test_circuits);
    run_circuit_supports_cbor();
    run_namespace_mixup(&test_circuits);
}
