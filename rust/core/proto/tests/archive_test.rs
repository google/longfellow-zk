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

use core_proto::archive::{CircuitArchive, CircuitArchiveBuilder, LFA2_MAGIC};

#[test]
fn test_circuit_archive_lfa2_roundtrip() {
    let id1 = [1u8; 32];
    let payload1 = vec![0x10, 0x20, 0x30];

    let id2 = [2u8; 32];
    let payload2 = vec![0x40, 0x50, 0x60, 0x70];

    let mut builder = CircuitArchiveBuilder::new();
    builder.set_circuit_version(7);
    builder.set_created_at("2026-07-15T15:13:24Z");
    builder.set_author("Google LLC");
    builder.set_generator_tool("rzkl-compiler v0.1.0");
    builder.set_description("mdoc ZK Circuit Archive");
    builder.add_entry("sig", id1, payload1.clone());
    builder.add_entry("hash", id2, payload2.clone());

    let archive = builder.build();
    let bytes = archive.to_bytes_lfa2();

    assert_eq!(&bytes[..4], LFA2_MAGIC);

    let deserialized = CircuitArchive::from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.circuit_version, 7);
    assert_eq!(deserialized.combined_id, archive.combined_id);
    assert_eq!(deserialized.created_at, "2026-07-15T15:13:24Z");
    assert_eq!(deserialized.author, "Google LLC");
    assert_eq!(deserialized.generator_tool, "rzkl-compiler v0.1.0");
    assert_eq!(deserialized.description, "mdoc ZK Circuit Archive");
    assert_eq!(deserialized.entries.len(), 2);

    let sig_entry = deserialized.get("sig").unwrap();
    assert_eq!(sig_entry.circuit_id, id1);
    assert_eq!(sig_entry.payload, payload1);

    let hash_entry = deserialized.get("hash").unwrap();
    assert_eq!(hash_entry.circuit_id, id2);
    assert_eq!(hash_entry.payload, payload2);
}

#[test]
fn test_circuit_archive_lfa1_roundtrip() {
    use circuits_boolean::Boolean;
    use compile_algebra::{gf2_128::Gf2_128Field, p256::P256Field};
    use compile_compiler::{CompilerArena, CompilerLogic};
    use compile_logic::LogicIO;
    use core_proto::writer::CircuitWriter;

    let f256 = P256Field::new();
    let fgf2 = Gf2_128Field::new();

    let arena256 = CompilerArena::new();
    let iologic256 = CompilerLogic::new(&arena256, &f256);
    let boolean256 = Boolean::new(&iologic256);
    let a = iologic256.input(1);
    let ab = boolean256.of_eltw(a);
    let (assertion256, tracker256) = (boolean256.assert_true("assert_a", &ab), iologic256.tracker);
    let (c_sig, _, _) =
        compile_compiler::top::compile(&arena256, &f256, assertion256, tracker256, 1, 0);

    let arena_gf2 = CompilerArena::new();
    let iologic_gf2 = CompilerLogic::new(&arena_gf2, &fgf2);
    let boolean_gf2 = Boolean::new(&iologic_gf2);
    let b = iologic_gf2.input(1);
    let bb = boolean_gf2.of_eltw(b);
    let (assertion_gf2, tracker_gf2) = (
        boolean_gf2.assert_true("assert_b", &bb),
        iologic_gf2.tracker,
    );
    let (c_hash, _, _) =
        compile_compiler::top::compile(&arena_gf2, &fgf2, assertion_gf2, tracker_gf2, 1, 0);

    let w_sig = CircuitWriter::new(&f256, core_proto::FieldID::P256);
    let sig_bytes = w_sig.to_bytes_lfc1(&c_sig);

    let w_hash = CircuitWriter::new(&fgf2, core_proto::FieldID::Gf2_128);
    let hash_bytes = w_hash.to_bytes_lfc1(&c_hash);

    let mut builder = CircuitArchiveBuilder::new();
    builder.set_created_at("");
    builder.set_author("");
    builder.set_generator_tool("");
    builder.set_description("");
    builder.add_entry("sig", c_sig.id, sig_bytes.clone());
    builder.add_entry("hash", c_hash.id, hash_bytes.clone());

    let archive = builder.build();
    let bytes = archive.to_bytes_lfa1();

    assert_eq!(bytes[0], 1);

    let deserialized = CircuitArchive::from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.combined_id, archive.combined_id);
    assert_eq!(deserialized.created_at, "");
    assert_eq!(deserialized.author, "");
    assert_eq!(deserialized.generator_tool, "");
    assert_eq!(deserialized.description, "");
    assert_eq!(deserialized.entries.len(), 2);

    let sig_entry = deserialized.get("sig").unwrap();
    assert_eq!(sig_entry.circuit_id, c_sig.id);
    assert_eq!(sig_entry.payload, sig_bytes);
}

#[test]
#[should_panic(expected = "Cannot serialize to LFA1 format: created_at field is non-empty")]
fn test_circuit_archive_lfa1_information_loss_assertion() {
    let id1 = [1u8; 32];
    let payload1 = vec![0x10, 0x20, 0x30];

    let mut builder = CircuitArchiveBuilder::new();
    builder.set_created_at("2026-07-15T15:13:24Z"); // Non-empty created_at
    builder.set_author("");
    builder.set_generator_tool("");
    builder.set_description("");
    builder.add_entry("sig", id1, payload1);

    let archive = builder.build();
    let _ = archive.to_bytes_lfa1();
}

#[test]
#[should_panic(expected = "Cannot serialize to LFA1 format: circuit_version is non-zero")]
fn test_circuit_archive_lfa1_circuit_version_assertion() {
    let id1 = [1u8; 32];
    let payload1 = vec![0x10, 0x20, 0x30];

    let mut builder = CircuitArchiveBuilder::new();
    builder.set_circuit_version(7);
    builder.add_entry("sig", id1, payload1);

    let archive = builder.build();
    let _ = archive.to_bytes_lfa1();
}

#[test]
fn test_circuit_archive_legacy_concatenated_stream() {
    use circuits_boolean::Boolean;
    use compile_algebra::{gf2_128::Gf2_128Field, p256::P256Field};
    use compile_compiler::{CompilerArena, CompilerLogic};
    use compile_logic::LogicIO;
    use core_proto::writer::CircuitWriter;

    let f256 = P256Field::new();
    let fgf2 = Gf2_128Field::new();

    let arena256 = CompilerArena::new();
    let iologic256 = CompilerLogic::new(&arena256, &f256);
    let boolean256 = Boolean::new(&iologic256);
    let a = iologic256.input(1);
    let ab = boolean256.of_eltw(a);
    let (assertion256, tracker256) = (boolean256.assert_true("assert_a", &ab), iologic256.tracker);
    let (c_sig, _, _) =
        compile_compiler::top::compile(&arena256, &f256, assertion256, tracker256, 1, 0);

    let arena_gf2 = CompilerArena::new();
    let iologic_gf2 = CompilerLogic::new(&arena_gf2, &fgf2);
    let boolean_gf2 = Boolean::new(&iologic_gf2);
    let b = iologic_gf2.input(1);
    let bb = boolean_gf2.of_eltw(b);
    let (assertion_gf2, tracker_gf2) = (
        boolean_gf2.assert_true("assert_b", &bb),
        iologic_gf2.tracker,
    );
    let (c_hash, _, _) =
        compile_compiler::top::compile(&arena_gf2, &fgf2, assertion_gf2, tracker_gf2, 1, 0);

    let w_sig = CircuitWriter::new(&f256, core_proto::FieldID::P256);
    let sig_bytes = w_sig.to_bytes_lfc1(&c_sig);

    let w_hash = CircuitWriter::new(&fgf2, core_proto::FieldID::Gf2_128);
    let hash_bytes = w_hash.to_bytes_lfc1(&c_hash);

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&sig_bytes);
    concatenated.extend_from_slice(&hash_bytes);

    let archive = CircuitArchive::from_bytes(&concatenated).unwrap();
    assert_eq!(archive.version, 1);
    assert_eq!(archive.entries.len(), 2);

    let sig_entry = archive.get("sig").unwrap();
    assert_eq!(sig_entry.circuit_id, c_sig.id);
    assert_eq!(sig_entry.payload, sig_bytes);

    let hash_entry = archive.get("hash").unwrap();
    assert_eq!(hash_entry.circuit_id, c_hash.id);
    assert_eq!(hash_entry.payload, hash_bytes);
}
