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
use circuits_sha256msg::{concrete::given, Given, Sha256Msg};
use compile_algebra::gf2_128::Gf2_128Field;
use compile_logic::eval::EvalLogic;

use super::test_support;

fn run_corruptor_test<const MAX_BLOCKS: usize>(
    message: &[u8],
    corrupt: &dyn Fn(
        &mut circuits_sha256msg::concrete::ConcreteGiven,
        &mut circuits_sha256msg::concrete::ConcreteDerived,
    ),
) -> compile_logic::eval::EvalAssertions {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);
    let boolean = Boolean::new(&l);

    let mut given = given(message, &circuits_sha256::constants::INITIAL, MAX_BLOCKS).unwrap();
    let mut derived = circuits_sha256msg::concrete::derived(&given, MAX_BLOCKS);

    corrupt(&mut given, &mut derived);

    let nblocks_wire = bv.of_u8(given.nblocks as u8);
    let length_bytes = bv.of_u64(given.length_bytes);
    let input_bytes: Vec<_> = given.padded_preimage.iter().map(|&x| bv.of_u8(x)).collect();

    let mut expected_hash_wires = vec![boolean.falseb(); 256];
    for j in 0..8 {
        let w = given.expected_hash[7 - j];
        for k in 0..32 {
            let bit_val = ((w >> k) & 1) == 1;
            expected_hash_wires[j * 32 + k] = boolean.konst(bit_val);
        }
    }
    let expected_hash = Bitvec::<_, 256>::new(expected_hash_wires);

    let mut sha_derived = Vec::with_capacity(MAX_BLOCKS);
    for b in 0..MAX_BLOCKS {
        let wit_wires = circuits_sha256::evaluate::evaluate_derived(&derived.sha_derived[b], &bv);
        sha_derived.push(wit_wires);
    }

    let sha256msg = Sha256Msg::<_, MAX_BLOCKS>::new(&l);
    let given_wires = Given {
        padded_preimage: input_bytes,
        nblocks: nblocks_wire,
        length_bytes,
        expected_hash,
    };
    sha256msg.assert_message_hash(&given_wires, &sha_derived)
}

#[test]
fn test_eval_sha256_msg() {
    run_corruptor_test::<1>(&[], &|_g, _d| {}).unwrap();
    run_corruptor_test::<1>(b"hello world", &|_g, _d| {}).unwrap();
    run_corruptor_test::<1>(&[0u8; 55], &|_g, _d| {}).unwrap();
    run_corruptor_test::<2>(&[0u8; 56], &|_g, _d| {}).unwrap();
    run_corruptor_test::<3>(
        b"This is a longer message that definitely spans across multiple SHA-256 blocks to verify correctness.",
        &|_g, _d| {},
    )
    .unwrap();
}

#[test]
fn test_eval_sha256msg_shared_corruptors() {
    let corruptors = test_support::all_sha256msg_corruptors();
    for c in corruptors {
        let res = run_corruptor_test::<2>(b"hello world", &*c.corrupt);
        assert!(
            res.is_err(),
            "Corruptor '{}' failed to cause assertion failure",
            c.name
        );
        res.assert_any_failed_at(c.expected_path);
    }
}

#[test]
fn test_exploit_nblocks_too_large() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);
    let boolean = Boolean::new(&l);

    let nblocks_val = 2; // out of bounds (> max_blocks = 1)

    let given = given(&[0u8; 55], &circuits_sha256::constants::INITIAL, 1).unwrap();
    let derived = circuits_sha256msg::concrete::derived(&given, 1);

    let expected_hash = Bitvec::<_, 256>::new(vec![boolean.falseb(); 256]);

    let wit_wires = circuits_sha256::evaluate::evaluate_derived(&derived.sha_derived[0], &bv);

    let nblocks_wire = bv.of_u8(nblocks_val);
    let input_bytes: Vec<_> = given.padded_preimage.iter().map(|&x| bv.of_u8(x)).collect();

    let length_bytes = bv.of_u64(0);
    let sha256msg = Sha256Msg::<_, 1>::new(&l);
    let given_wires = Given {
        padded_preimage: input_bytes,
        nblocks: nblocks_wire,
        length_bytes,
        expected_hash,
    };
    let assertion = sha256msg.assert_message_hash(&given_wires, &[wit_wires]);
    assertion.assert_any_failed_at("nblocks_max");
}

#[test]
fn test_exploit_nblocks_zero() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);
    let boolean = Boolean::new(&l);

    let nblocks_val = 0; // out of bounds (< 1)

    let given = given(&[0u8; 55], &circuits_sha256::constants::INITIAL, 1).unwrap();
    let derived = circuits_sha256msg::concrete::derived(&given, 1);

    let expected_hash = Bitvec::<_, 256>::new(vec![boolean.falseb(); 256]);

    let wit_wires = circuits_sha256::evaluate::evaluate_derived(&derived.sha_derived[0], &bv);

    let nblocks_wire = bv.of_u8(nblocks_val);
    let input_bytes: Vec<_> = given.padded_preimage.iter().map(|&x| bv.of_u8(x)).collect();

    let length_bytes = bv.of_u64(0);
    let sha256msg = Sha256Msg::<_, 1>::new(&l);
    let given_wires = Given {
        padded_preimage: input_bytes,
        nblocks: nblocks_wire,
        length_bytes,
        expected_hash,
    };
    let assertion = sha256msg.assert_message_hash(&given_wires, &[wit_wires]);
    assertion.assert_any_failed_at("nblocks_nz");
}

#[test]
fn test_eval_nblocks_ok() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);

    let sha256msg = Sha256Msg::<_, 2>::new(&l);

    {
        let nblocks = bv.of_u8(1);
        let length_bytes = bv.of_u64(0);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_all_passed();
    }

    {
        let nblocks = bv.of_u8(1);
        let length_bytes = bv.of_u64(55);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_all_passed();
    }

    {
        let nblocks = bv.of_u8(2);
        let length_bytes = bv.of_u64(56);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_all_passed();
    }
}

#[test]
fn test_eval_nblocks_failures() {
    let f = Gf2_128Field::new();
    type L<'a> = EvalLogic<'a, Gf2_128Field>;
    let l = L::new(&f);
    let bv = BitvecLogic::new(&l);

    let sha256msg = Sha256Msg::<_, 2>::new(&l);

    // nblocks = 0 (violates nblocks_nz)
    {
        let nblocks = bv.of_u8(0);
        let length_bytes = bv.of_u64(10);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_any_failed_at("nblocks_nz");
    }

    // nblocks = 3 (violates nblocks_max for MAX_BLOCKS = 2)
    {
        let nblocks = bv.of_u8(3);
        let length_bytes = bv.of_u64(10);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_any_failed_at("nblocks_max");
    }

    // nblocks = 1, length_bytes = 56 (violates limit_upper because 56 + 9 = 65 > 64)
    {
        let nblocks = bv.of_u8(1);
        let length_bytes = bv.of_u64(56);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_any_failed_at("limit_upper");
    }

    // nblocks = 2, length_bytes = 10 (violates limit_lower because 2 * 64 = 128 > 10 + 72 = 82)
    {
        let nblocks = bv.of_u8(2);
        let length_bytes = bv.of_u64(10);
        let assertion = sha256msg.assert_nblocks(&nblocks, &length_bytes);
        assertion.assert_any_failed_at("limit_lower");
    }
}
