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
use compile_compiler::{CompilerArena, CompilerLogic};
use core_algebra::SerializableField;
use mdoc_zk_circuits::{
    config::K_ZSTD_LEVEL,
    hash::{hash_input_of_parsed_mdoc, MdocHash},
    parse_test_data, MdocHashCompileField,
};
use runtime_algebra::field::RuntimeField;

pub fn mdoc_zk_circuits_hash_circuit<FC>(
    fc: &FC,
) -> (compile_eval::Circuit<FC>, compile_eval::CircuitGeometry)
where FC: MdocHashCompileField {
    let arena = CompilerArena::new();
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let num_attrs = hash_input.attrs.len();

    let mdoc = MdocHash::new(&iologic, num_attrs);
    let bv = circuits_bitvec::BitvecLogic::new(&iologic);
    let given_wires = mdoc_zk_circuits::hash::allocate_given(&iologic, &bv, num_attrs, &mut pos);
    let derived_wires = mdoc_zk_circuits::hash::allocate_derived::<
        _,
        { mdoc_zk_circuits::hash::constants::K_MAX_SHA_BLOCKS },
    >(&bv, num_attrs, &mut pos);

    let assertion = mdoc.assert_valid_presentation_and_macs(&given_wires, &derived_wires);

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);
    (circuit, stats)
}

fn test_mdoc_zk_circuits_hash_for_field<
    const W_R: usize,
    FC: MdocHashCompileField,
    FR: RuntimeField<W_R> + SerializableField,
>(
    fc: &FC,
    _fr: &FR,
) {
    let arena = CompilerArena::new();
    let (_, parsed, now) =
        parse_test_data::<4, CompileNat<4>>(&mdoc_zk_testcases::vectors::TEST_DATA);
    let hash_input = hash_input_of_parsed_mdoc(&parsed, &parsed.all_attr_ids(), now);

    let iologic = CompilerLogic::new(&arena, fc);
    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;

    let num_attrs = hash_input.attrs.len();

    let mdoc = MdocHash::new(&iologic, num_attrs);
    let bv = circuits_bitvec::BitvecLogic::new(&iologic);
    let given_wires = mdoc_zk_circuits::hash::allocate_given(&iologic, &bv, num_attrs, &mut pos);
    let derived_wires = mdoc_zk_circuits::hash::allocate_derived::<
        _,
        { mdoc_zk_circuits::hash::constants::K_MAX_SHA_BLOCKS },
    >(&bv, num_attrs, &mut pos);

    let assertion = mdoc.assert_valid_presentation_and_macs(&given_wires, &derived_wires);

    let (_circuit, stats, _symbols) = compile_compiler::top::compile(&arena, fc, assertion, 0, 0);

    compile_compiler::top::dump_stats("mdoc_hash", &_circuit, &stats);
}

#[test]
fn test_mdoc_zk_circuits_hash() {
    let fc = Gf2_128Field::new();
    let fr = runtime_algebra::gf2_128::Gf2_128Field::new();
    test_mdoc_zk_circuits_hash_for_field::<2, _, _>(&fc, &fr);
}

#[test]
fn test_serialize_and_verify_mdoc_hash_circuit() {
    use core_proto::{writer::CircuitWriter, FieldID};

    let gf2_c = Gf2_128Field::new();
    let (circuit, stats) = mdoc_zk_circuits_hash_circuit(&gf2_c);

    compile_compiler::top::dump_stats("mdoc_hash_serialized", &circuit, &stats);

    let expected_id: [u8; 32] = [
        0x7c, 0x04, 0x99, 0xe9, 0x93, 0xc5, 0xc9, 0x2e, 0xf6, 0x76, 0xaf, 0xde, 0x4a, 0xb7, 0x9e,
        0x27, 0x3b, 0x7e, 0x45, 0xce, 0xdb, 0x82, 0xed, 0xc0, 0x27, 0xad, 0x50, 0x04, 0x52, 0xd8,
        0xa0, 0x8a,
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
