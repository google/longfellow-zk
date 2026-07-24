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

use compile_algebra::gf2_128::Gf2_128Field;
use compile_eval::FieldID;
use mdoc_zk_circuits::mso_attribute::circuit::AttributeVerifier;
use mso_attribute_corruptors::MsoAttributeMockGiven;
use runtime_algebra::field::RuntimeField;

use super::mso_attribute_corruptors;

pub fn compile_attribute_circuit<const W: usize, FC>(
    fc: &FC,
) -> (
    compile_eval::Circuit<FC>,
    compile_eval::CircuitGeometry,
    compile_compiler::debug::CircuitDebugSymbols,
)
where
    FC: mdoc_zk_circuits::MdocHashCompileField,
{
    let (circuit, stats, symbols) = compile_compiler::compile(fc, |iologic| {
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

        let verifier = AttributeVerifier::new(&iologic);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires = mdoc_zk_circuits::mso_attribute::allocate_given(&bv, &mut pos);
        let derived_wires = mdoc_zk_circuits::mso_attribute::allocate_derived(&bv, &mut pos);
        (
            verifier.assert_attribute(&given_wires, &derived_wires),
            1,
            0,
        )
    });

    (circuit, stats, symbols)
}

fn push_bits<const W: usize, FR: RuntimeField<W>>(
    inputs: &mut Vec<FR::E>,
    val: u64,
    nbits: usize,
    fr: &FR,
) {
    for k in 0..nbits {
        let bit = (val >> k) & 1;
        inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
    }
}

fn make_inputs<const W: usize, FR: RuntimeField<W>>(
    mock: &MsoAttributeMockGiven,
    fr: &FR,
) -> Vec<FR::E> {
    let mut inputs = compile_eval::initial_inputs(fr);

    let (_, _, padded_preimage) =
        circuits_sha256msg::concrete::pad_sha256_message(&mock.raw_buf, 2).unwrap();

    // attribute_preimage.data (128 bytes)
    for i in 0..128 {
        let b = if i < padded_preimage.len() {
            padded_preimage[i]
        } else {
            0
        };
        push_bits(&mut inputs, b as u64, 8, fr);
    }
    // attribute_preimage.len (10 bits)
    push_bits(&mut inputs, mock.preimage_len, 10, fr);

    // field_locator.slot_position (4 x 10 bits)
    for i in 0..4 {
        push_bits(&mut inputs, mock.slot_position[i], 10, fr);
    }
    // field_locator.length (4 x 10 bits)
    for i in 0..4 {
        push_bits(&mut inputs, mock.length[i], 10, fr);
    }
    // field_locator.permutation (4 x 2 bits)
    for i in 0..4 {
        push_bits(&mut inputs, mock.permutation[i], 2, fr);
    }

    // disclosed_attribute.expected_name.data (32 bytes)
    for i in 0..32 {
        let b = if i < mock.disclosed_name.len() {
            mock.disclosed_name[i]
        } else {
            0
        };
        push_bits(&mut inputs, b as u64, 8, fr);
    }
    // disclosed_attribute.expected_name.len (10 bits)
    push_bits(&mut inputs, mock.disclosed_name_len, 10, fr);

    // disclosed_attribute.expected_cbor_value.data (64 bytes)
    for i in 0..64 {
        let b = if i < mock.disclosed_value.len() {
            mock.disclosed_value[i]
        } else {
            0
        };
        push_bits(&mut inputs, b as u64, 8, fr);
    }
    // disclosed_attribute.expected_cbor_value.len (10 bits)
    push_bits(&mut inputs, mock.disclosed_value_len, 10, fr);

    // expected_digest (256 bits)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&mock.raw_buf);
    let digest_bytes = hasher.finalize();

    for idx in 0..256 {
        let byte_idx = 31 - (idx / 8);
        let bit_idx = idx % 8;
        let byte = digest_bytes[byte_idx];
        let bit = (byte >> bit_idx) & 1;
        inputs.push(if bit == 1 { fr.one() } else { fr.zero() });
    }

    // allocate_derived: SHA-256 derived for 2 blocks
    let (nblocks, length_bytes, _) =
        circuits_sha256msg::concrete::pad_sha256_message(&mock.raw_buf, 2).unwrap();
    let concrete_given = circuits_sha256msg::concrete::ConcreteGiven {
        padded_preimage,
        nblocks,
        length_bytes,
        expected_hash: [0; 8],
    };
    let concrete_derived = circuits_sha256msg::concrete::derived(&concrete_given, 2);

    for b in 0..2 {
        let d = &concrete_derived.sha_derived[b];
        for i in 0..48 {
            push_bits(&mut inputs, d.outw[i] as u64, 32, fr);
        }
        for i in 0..64 {
            push_bits(&mut inputs, d.oute[i] as u64, 32, fr);
        }
        for i in 0..64 {
            push_bits(&mut inputs, d.outa[i] as u64, 32, fr);
        }
        for i in 0..8 {
            push_bits(&mut inputs, d.h1[i] as u64, 32, fr);
        }
    }

    inputs
}

#[test]
fn test_serialize_attribute_size() {
    let gf2_c = Gf2_128Field::new();

    let (circuit, stats, _) = compile_attribute_circuit::<2, _>(&gf2_c);
    compile_compiler::dump_stats("mso_attribute", &circuit, &stats);
}

#[test]
fn test_compile_mso_attribute_tampering() {
    let gf2_c = Gf2_128Field::new();
    let gf2_r = runtime_algebra::gf2_128::Gf2_128Field::new();

    let (circuit, _, symbols) = compile_attribute_circuit::<2, _>(&gf2_c);

    let base_mock = MsoAttributeMockGiven {
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

    // Verify untampered passes
    let inputs = make_inputs(&base_mock, &gf2_r);
    compile_eval::eval_circuit_fc(
        &gf2_c,
        &gf2_r,
        &circuit,
        &symbols,
        &inputs,
        FieldID::Gf2_128,
    )
    .unwrap()
    .assert_all_passed();

    // Verify all shared corruptors fail compiled circuit evaluation
    let corruptors = mso_attribute_corruptors::all_mso_attribute_corruptors();
    for c in corruptors {
        let mut mock = base_mock.clone();
        (c.corrupt)(&mut mock);

        let inputs_tampered = make_inputs(&mock, &gf2_r);
        let eval_res = compile_eval::eval_circuit_fc(
            &gf2_c,
            &gf2_r,
            &circuit,
            &symbols,
            &inputs_tampered,
            FieldID::Gf2_128,
        )
        .unwrap();
        assert!(
            eval_res.is_err(),
            "Corruptor '{}' failed to cause compiled circuit evaluation error",
            c.name
        );
        let failed = eval_res.failed_paths();
        assert!(
            failed.iter().any(|path| path == &c.expected_path),
            "Corruptor '{}' expected exact compiled failure path '{}', actual failures: {failed:?}",
            c.name,
            c.expected_path
        );
    }
}
