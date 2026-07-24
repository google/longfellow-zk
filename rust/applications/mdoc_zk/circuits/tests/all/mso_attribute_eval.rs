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

use circuits_bitvec::{BitvecLogic, V8};
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;
use mdoc_zk_circuits::mso_attribute::{
    circuit::{AttrSlice, AttributeVerifier, DisclosedAttribute, FieldLocator},
    constants::K_ATTR_INDEX_BITS,
};
use mso_attribute_corruptors::MsoAttributeMockGiven;

use super::mso_attribute_corruptors;

#[test]
fn test_prefix_equal_boundary_bug() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);

    let bv = BitvecLogic::new(&l);
    let verifier = AttributeVerifier::new(&l);

    // Create got and want of size 51
    let mut got = Vec::new();
    let mut want = Vec::new();
    for _ in 0..50 {
        got.push(bv.of_u8(0));
        want.push(bv.of_u8(0));
    }
    // Make them differ at index 50 (the 51st byte)
    got.push(bv.of_u8(1));
    want.push(bv.of_u8(0));

    let len = bv.of_u64::<K_ATTR_INDEX_BITS>(51);

    // Test with max = 50: should succeed (does not compare index 50)
    let assertions_50 = verifier.assert_prefix_equal(50, &got, &want, &len);
    assertions_50.unwrap();

    // Test with max = 51: should fail (compares index 50 and finds mismatch)
    let assertions_51 = verifier.assert_prefix_equal(51, &got, &want, &len);
    assert!(assertions_51.is_err());
}

#[test]
fn test_prefix_equal_vlen_boundary_bug() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    let l = EvalLogic::new_with_tracker(&f, &tracker);

    let bv = BitvecLogic::new(&l);
    let verifier = AttributeVerifier::new(&l);

    // Create got and want of size 78
    let mut got = Vec::new();
    let mut want = Vec::new();
    for _ in 0..77 {
        got.push(bv.of_u8(0));
        want.push(bv.of_u8(0));
    }
    // Make them differ at index 77 (the 78th byte)
    got.push(bv.of_u8(1));
    want.push(bv.of_u8(0));

    let len = bv.of_u64::<K_ATTR_INDEX_BITS>(78);

    // Test with max = 77: should succeed (does not compare index 77)
    let assertions_77 = verifier.assert_prefix_equal(77, &got, &want, &len);
    assertions_77.unwrap();

    // Test with max = 78: should fail (compares index 77 and finds mismatch)
    let assertions_78 = verifier.assert_prefix_equal(78, &got, &want, &len);
    assert!(assertions_78.is_err());
}

fn run_attribute_test_mock<'a, F>(
    f: &'a Gf2_128Field,
    tracker: &'a compile_logic::tracker::AssertionTracker,
    mutate_f: F,
) -> compile_logic::eval::EvalAssertions<'a>
where
    F: FnOnce(&mut MsoAttributeMockGiven),
{
    let mut mock = MsoAttributeMockGiven {
        raw_buf: vec![
            0xd8, 0x18, 0x58, 0x60, 0xa4, // headers
            0x68, b'd', b'i', b'g', b'e', b's', b't', b'I', b'D', 0x00, // digestID
            0x66, b'r', b'a', b'n', b'd', b'o', b'm', // random key
            0x58, 0x20, // byte string 32
            0x22, 0x31, 0x18, 0x3c, 0x7d, 0x9f, 0x4d, 0x2e, 0x2e, 0x14, 0x6d, 0x24, 0x84, 0x58,
            0xb4, 0xcc, 0xe9, 0x48, 0x79, 0x8f, 0xda, 0x82, 0x40, 0xd3, 0x60, 0xa8, 0xf4, 0x0f,
            0x6d, 0x75, 0x48, 0xd3, 0x71, b'e', b'l', b'e', b'm', b'e', b'n', b't', b'I', b'd',
            b'e', b'n', b't', b'i', b'f', b'i', b'e', b'r', // key
            0x6b, b'a', b'g', b'e', b'_', b'o', b'v', b'e', b'r', b'_', b'1',
            b'8', // age_over_18
            0x6c, b'e', b'l', b'e', b'm', b'e', b'n', b't', b'V', b'a', b'l', b'u',
            b'e', // key
            0xf5, // true
        ],
        slot_position: [5, 15, 56, 86],
        length: [10, 41, 30, 14],
        permutation: [0, 1, 2, 3],
        disclosed_name: {
            let mut name = vec![0x60 + 11];
            name.extend_from_slice(b"age_over_18");
            name
        },
        disclosed_name_len: 12,
        disclosed_value: vec![0xf5],
        disclosed_value_len: 1,
        preimage_len: 100,
    };

    mutate_f(&mut mock);

    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = EvalLogic::new_with_tracker(f, tracker);
    let bv = BitvecLogic::new(&l);

    use mdoc_zk_circuits::mso_attribute::constants::K_ATTR_PREIMAGE_LEN;
    let (nblocks, length_bytes, padded_preimage) =
        circuits_sha256msg::concrete::pad_sha256_message(&mock.raw_buf, 2).unwrap();
    let attribute_preimage = padded_preimage
        .iter()
        .map(|&b| bv.of_u8(b))
        .collect::<Vec<_>>();
    let zero_v8 = bv.of_u8(0);

    let mut oa_attr = std::array::from_fn(|_| zero_v8.clone());
    for i in 0..mock.disclosed_name.len().min(32) {
        oa_attr[i] = bv.of_u8(mock.disclosed_name[i]);
    }

    let mut oa_v1 = std::array::from_fn(|_| zero_v8.clone());
    for i in 0..mock.disclosed_value.len().min(64) {
        oa_v1[i] = bv.of_u8(mock.disclosed_value[i]);
    }

    let da = DisclosedAttribute {
        expected_name: AttrSlice {
            data: oa_attr,
            len: bv.of_u64::<K_ATTR_INDEX_BITS>(mock.disclosed_name_len),
        },
        expected_cbor_value: AttrSlice {
            data: oa_v1,
            len: bv.of_u64::<K_ATTR_INDEX_BITS>(mock.disclosed_value_len),
        },
    };

    let field_locator = FieldLocator {
        slot_position: std::array::from_fn(|i| {
            bv.of_u64::<K_ATTR_INDEX_BITS>(mock.slot_position[i])
        }),
        length: std::array::from_fn(|i| bv.of_u64::<K_ATTR_INDEX_BITS>(mock.length[i])),
        permutation: std::array::from_fn(|i| bv.of_u64::<2>(mock.permutation[i])),
    };

    let preimage_array: [V8<L>; K_ATTR_PREIMAGE_LEN] = attribute_preimage.try_into().unwrap();
    let preimage_bytes = AttrSlice {
        data: preimage_array,
        len: bv.of_u64::<K_ATTR_INDEX_BITS>(mock.preimage_len),
    };

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&mock.raw_buf);
    let digest_bytes = hasher.finalize();

    let expected_digest = bv.from_fn::<256, _>(|idx| {
        let byte_idx = 31 - (idx / 8);
        let bit_idx = idx % 8;
        let byte = digest_bytes[byte_idx];
        let bit_val = (byte.checked_shr(bit_idx as u32).unwrap_or(0) & 1) == 1;
        circuits_boolean::Boolean::new(&l).konst(bit_val)
    });

    let concrete_given = circuits_sha256msg::concrete::ConcreteGiven {
        padded_preimage,
        nblocks,
        length_bytes,
        expected_hash: [0; 8],
    };
    let concrete_derived = circuits_sha256msg::concrete::derived(&concrete_given, 2);
    let sha_derived = circuits_sha256msg::evaluate::evaluate_derived(&concrete_derived, &bv);

    let verifier = AttributeVerifier::new(&l);

    let verifier_args = mdoc_zk_circuits::mso_attribute::circuit::Given {
        attribute_preimage: preimage_bytes,
        field_locator,
        disclosed_attribute: da,
        expected_digest,
    };

    verifier.assert_attribute(&verifier_args, &sha_derived)
}

#[test]
fn test_attribute_success() {
    let f = Gf2_128Field::new();
    let tracker = compile_logic::tracker::AssertionTracker::new();
    run_attribute_test_mock(&f, &tracker, |_| {}).unwrap();
}

#[test]
fn test_eval_mso_attribute_shared_corruptors() {
    let f = Gf2_128Field::new();
    let corruptors = mso_attribute_corruptors::all_mso_attribute_corruptors();
    for c in corruptors {
        let tracker = compile_logic::tracker::AssertionTracker::new();
        let res = run_attribute_test_mock(&f, &tracker, |g| {
            (c.corrupt)(g);
        });
        assert!(
            res.is_err(),
            "Corruptor '{}' failed to cause assertion failure",
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
