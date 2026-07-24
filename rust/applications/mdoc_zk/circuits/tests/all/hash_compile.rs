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

use compile_algebra::{gf2_128::Gf2_128Field, CompileNat};
use core_algebra::{Nat, SerializableField, SupportsU128Conversions};
use mdoc_zk_circuits::{
    config::K_ZSTD_LEVEL,
    hash::{
        derived, given, hash_input_of_parsed_mdoc, ConcreteDerived, ConcreteGiven, HashMac,
        MdocHash,
    },
    parse_test_data, MdocHashCompileField,
};
use runtime_algebra::field::RuntimeField;

use super::mdoc_hash_corruptors;

pub fn mdoc_zk_circuits_hash_circuit<FC>(
    fc: &FC,
) -> (compile_eval::Circuit<FC>, compile_eval::CircuitGeometry)
where
    FC: MdocHashCompileField,
{
    let (circuit, stats, _) = compile_hash_circuit(fc);
    (circuit, stats)
}

fn compile_hash_circuit<FC>(
    fc: &FC,
) -> (
    compile_eval::Circuit<FC>,
    compile_eval::CircuitGeometry,
    compile_compiler::debug::CircuitDebugSymbols,
)
where
    FC: MdocHashCompileField,
{
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let num_attrs = hash_input.attrs.len();

    compile_compiler::compile(fc, |iologic| {
        let mdoc = MdocHash::new(&iologic, num_attrs);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires =
            mdoc_zk_circuits::hash::allocate_given(&iologic, &bv, num_attrs, &mut pos);
        let derived_wires = mdoc_zk_circuits::hash::allocate_derived::<
            _,
            { mdoc_zk_circuits::hash::constants::K_MAX_SHA_BLOCKS },
        >(&bv, num_attrs, &mut pos);

        (
            mdoc.assert_valid_presentation_and_macs(&given_wires, &derived_wires),
            iologic.tracker,
            1,
            0,
        )
    })
}

fn push_bits<const W: usize, FR: RuntimeField<W>>(
    inputs: &mut Vec<FR::E>,
    value: u128,
    nbits: usize,
    fr: &FR,
) {
    for bit in 0..nbits {
        inputs.push(if (value >> bit) & 1 == 1 {
            fr.one()
        } else {
            fr.zero()
        });
    }
}

fn push_bytes<const W: usize, FR: RuntimeField<W>>(
    inputs: &mut Vec<FR::E>,
    bytes: &[u8],
    size: usize,
    fr: &FR,
) {
    for idx in 0..size {
        push_bits(
            inputs,
            u128::from(bytes.get(idx).copied().unwrap_or(0)),
            8,
            fr,
        );
    }
}

fn push_nat<const W: usize, FR: RuntimeField<W>, N: Nat<4>>(
    inputs: &mut Vec<FR::E>,
    value: &N,
    nbits: usize,
    fr: &FR,
) {
    let bytes = value.to_bytes_le();
    for bit in 0..nbits {
        let value = bytes.get(bit / 8).map_or(0, |byte| (byte >> (bit % 8)) & 1);
        inputs.push(if value == 1 { fr.one() } else { fr.zero() });
    }
}

fn make_hash_inputs<const W: usize, FR>(
    given: &ConcreteGiven,
    derived: &ConcreteDerived,
    fr: &FR,
) -> Vec<FR::E>
where
    FR: RuntimeField<W> + SupportsU128Conversions,
{
    use mdoc_zk_circuits::{
        hash::constants::{K_MSO_PREIMAGE_LEN, K_TIMESTAMP_LEN},
        mso_attribute::constants::K_ATTR_PREIMAGE_LEN,
    };
    const EXPECTED_NAME_LEN: usize = 32;
    const EXPECTED_VALUE_LEN: usize = 64;

    let mut inputs = compile_eval::initial_inputs(fr);

    for attr in &given.hash_input.attrs {
        push_bytes(&mut inputs, &attr.expected_name, EXPECTED_NAME_LEN, fr);
        push_bits(&mut inputs, attr.expected_name.len() as u128, 10, fr);
        push_bytes(
            &mut inputs,
            &attr.expected_cbor_value,
            EXPECTED_VALUE_LEN,
            fr,
        );
        push_bits(&mut inputs, attr.expected_cbor_value.len() as u128, 10, fr);
    }

    push_bytes(&mut inputs, &given.hash_input.now, K_TIMESTAMP_LEN, fr);

    for value in given
        .mac_e
        .iter()
        .chain(&given.mac_device_pkx)
        .chain(&given.mac_device_pky)
    {
        inputs.push(fr.u128_to_element(*value));
    }
    inputs.push(fr.u128_to_element(given.mac_input.mac_av));
    inputs.push(if given.hash_input.suppress_doc_type_check {
        fr.one()
    } else {
        fr.zero()
    });

    push_bytes(
        &mut inputs,
        &given.hash_input.expected_doc_type,
        EXPECTED_NAME_LEN,
        fr,
    );
    push_bits(
        &mut inputs,
        given.hash_input.expected_doc_type.len() as u128,
        10,
        fr,
    );

    push_nat(&mut inputs, &given.hash_input.issuer_sig_e, 256, fr);
    push_bytes(&mut inputs, &given.preimage.value, K_MSO_PREIMAGE_LEN, fr);
    push_bits(&mut inputs, u128::from(given.preimage.len), 16, fr);
    push_bits(&mut inputs, u128::from(given.nblocks), 8, fr);
    push_nat(&mut inputs, &given.hash_input.device_pk.0, 256, fr);
    push_nat(&mut inputs, &given.hash_input.device_pk.1, 256, fr);

    for offset in [
        given.doc_type_offset_in_preimage,
        given.valid_from_offset_in_preimage,
        given.valid_until_offset_in_preimage,
        given.dev_key_info_offset_in_preimage,
        given.value_digests_offset_in_preimage,
    ] {
        push_bits(&mut inputs, u128::from(offset), 16, fr);
    }

    for attr in &given.attribute_given {
        push_bytes(&mut inputs, &attr.padded_preimage, K_ATTR_PREIMAGE_LEN, fr);
        push_bits(&mut inputs, attr.unpadded_preimage_len as u128, 10, fr);
        push_bits(
            &mut inputs,
            attr.mso_digest_offset_in_preimage as u128,
            16,
            fr,
        );
        for value in attr.field_locator.slot_position {
            push_bits(&mut inputs, value as u128, 10, fr);
        }
        for value in attr.field_locator.length {
            push_bits(&mut inputs, value as u128, 10, fr);
        }
        for idx in 0..4 {
            push_bits(
                &mut inputs,
                ((attr.field_locator.permutation >> (2 * idx)) & 3) as u128,
                2,
                fr,
            );
        }
    }

    for pair in given.mac_input.mac_ap {
        inputs.push(fr.u128_to_element(pair[0]));
        inputs.push(fr.u128_to_element(pair[1]));
    }

    derived.push_derived(fr, |value| inputs.push(value));
    inputs
}

fn test_mdoc_zk_circuits_hash_for_field<
    const W_R: usize,
    FC: MdocHashCompileField,
    FR: RuntimeField<W_R> + SerializableField,
>(
    fc: &FC,
    _fr: &FR,
) {
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
    let num_attrs = hash_input.attrs.len();

    let (_circuit, stats, _symbols) = compile_compiler::compile(fc, |iologic| {
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let mdoc = MdocHash::new(&iologic, num_attrs);
        let bv = circuits_bitvec::BitvecLogic::new(&iologic);
        let given_wires =
            mdoc_zk_circuits::hash::allocate_given(&iologic, &bv, num_attrs, &mut pos);
        let derived_wires = mdoc_zk_circuits::hash::allocate_derived::<
            _,
            { mdoc_zk_circuits::hash::constants::K_MAX_SHA_BLOCKS },
        >(&bv, num_attrs, &mut pos);

        (
            mdoc.assert_valid_presentation_and_macs(&given_wires, &derived_wires),
            iologic.tracker,
            1,
            0,
        )
    });

    compile_compiler::dump_stats("mdoc_hash", &_circuit, &stats);
}

#[test]
fn test_mdoc_zk_circuits_hash() {
    let fc = Gf2_128Field::new();
    let fr = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_mdoc_zk_circuits_hash_for_field::<2, _, _>(&fc, &fr);
}

#[test]
fn test_compile_mdoc_hash_corruptors() {
    let fc = Gf2_128Field::new();
    let fr = runtime_algebra::gf2_128::Gf2_128Field::new();
    let (circuit, _, symbols) = compile_hash_circuit(&fc);

    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);
    let mac_input = HashMac {
        mac_av: 0x112233445566778899aabbccddeeff00,
        mac_ap: [[
            0xabcdef0123456789abcdef0123456789,
            0xfedcba9876543210fedcba9876543210,
        ]; 3],
    };
    let base_given = given::<4, _>(hash_input, mac_input);
    let base_derived = derived::<4, _>(&base_given);

    compile_eval::eval_circuit_fc(
        &fc,
        &fr,
        &circuit,
        &symbols,
        &make_hash_inputs(&base_given, &base_derived, &fr),
        compile_eval::FieldID::Gf2_128,
    )
    .unwrap()
    .assert_all_passed();

    for corruptor in mdoc_hash_corruptors::all_mdoc_hash_corruptors() {
        let mut corrupted = base_given.clone();
        (corruptor.corrupt)(&mut corrupted);
        let result = compile_eval::eval_circuit_fc(
            &fc,
            &fr,
            &circuit,
            &symbols,
            &make_hash_inputs(&corrupted, &base_derived, &fr),
            compile_eval::FieldID::Gf2_128,
        )
        .unwrap();
        let failed = result.failed_paths();
        assert!(
            failed.iter().any(|path| path == &corruptor.expected_path),
            "Corruptor '{}' expected exact compiled failure path '{}', actual failures: {failed:?}",
            corruptor.name,
            corruptor.expected_path
        );
    }
}

#[test]
fn test_serialize_and_verify_mdoc_hash_circuit() {
    use core_proto::{writer::CircuitWriter, FieldID};

    let gf2_c = Gf2_128Field::new();
    let (circuit, stats) = mdoc_zk_circuits_hash_circuit(&gf2_c);

    compile_compiler::dump_stats("mdoc_hash_serialized", &circuit, &stats);

    let expected_id: [u8; 32] = [
        0x7f, 0xec, 0x95, 0x56, 0x51, 0x4f, 0x03, 0xfb, 0x2f, 0x83, 0x3c, 0xf2, 0xe5, 0xea, 0x7e,
        0x87, 0x3e, 0x06, 0x2b, 0x4d, 0x83, 0x25, 0x1e, 0x7b, 0x91, 0x4e, 0x36, 0xfc, 0x43, 0xbe,
        0x97, 0x26,
    ];
    assert_eq!(
        circuit.id, expected_id,
        "Circuit hash changed! Expected {:?}, got {:?}",
        expected_id, circuit.id
    );

    let writer = CircuitWriter::new(&gf2_c, FieldID::Gf2_128);
    let serialized = writer.to_bytes(&circuit);
    let orig_size = serialized.len();

    let compressed =
        zstd::bulk::compress(&serialized, K_ZSTD_LEVEL).expect("zstd compression failed");
    let compressed_size = compressed.len();

    println!("MDOC Hash Circuit serialization stats:");
    println!("  Original serialized size:   {orig_size} bytes");
    println!("  Zstd compressed size:       {compressed_size} bytes");
}

#[test]
fn test_paranoid_hash_input_subsets_and_permutations() {
    let (_, parsed, now) = parse_test_data::<4, CompileNat<4>>(
        &mdoc_zk_testcases::vectors::BIRTHDATE_1971_09_01_MDOC_3,
    );
    let all_ids = parsed.all_attr_ids();
    assert!(
        all_ids.len() >= 4,
        "BIRTHDATE_1971_09_01_MDOC_3 should have at least 4 attributes"
    );
    let four_ids = &all_ids[0..4];

    let mut subsets: Vec<Vec<usize>> = Vec::new();
    for mask in 0..(1 << 4) {
        let mut subset = Vec::new();
        for i in 0..4 {
            if (mask & (1 << i)) != 0 {
                subset.push(i);
            }
        }
        subsets.push(subset);
    }

    let mut total_tested = 0;
    for subset in subsets {
        fn permute(arr: &mut Vec<usize>, start: usize, perms: &mut Vec<Vec<usize>>) {
            if start == arr.len() {
                perms.push(arr.clone());
                return;
            }
            for i in start..arr.len() {
                arr.swap(start, i);
                permute(arr, start + 1, perms);
                arr.swap(start, i);
            }
        }
        let mut perms = Vec::new();
        let mut sub = subset.clone();
        permute(&mut sub, 0, &mut perms);

        for p in perms {
            let req_ids: Vec<&[u8]> = p.iter().map(|&idx| four_ids[idx]).collect();
            let input = hash_input_of_parsed_mdoc(&parsed, &req_ids, now);
            assert_eq!(input.attrs.len(), req_ids.len());
            for (i, &req_id) in req_ids.iter().enumerate() {
                let attr_name_bytes = &input.attrs[i].expected_name;
                assert_eq!(
                    attr_name_bytes,
                    &mdoc_zk_circuits::cbor::encode_cbor_string(req_id),
                    "Mismatch at permutation {p:?}, index {i}"
                );
            }
            total_tested += 1;
        }
    }
    assert_eq!(
        total_tested, 65,
        "Should test exactly 65 subsets and permutations"
    );
}
