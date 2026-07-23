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

use circuits_boolean::Boolean;
use compile_algebra::p256::P256Field;
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_eval::SerializableField;
use compile_logic::LogicIO;
use core_proto::{reader::CircuitReader, writer::CircuitWriter, FieldID};

#[test]
fn test_circuit_serialization_lfc2_roundtrip() {
    let f = P256Field::new();
    let rf = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let boolean = Boolean::new(&iologic);

    let a = iologic.input(1);
    let b = iologic.input(2);

    let ab = boolean.of_eltw(a);
    let bb = boolean.of_eltw(b);

    let x = boolean.xorb(&ab, &bb);
    let assertion = boolean.assert_true("assert_x", &x);

    let (circuit, _, _) = compile_compiler::top::compile(&arena, &f, assertion, 1, 0);

    let writer = CircuitWriter::new(&f, FieldID::P256);
    let serialized = writer.to_bytes_lfc2(&circuit);
    assert_eq!(&serialized[..4], b"LFC2");

    let reader = CircuitReader::new(&rf, FieldID::P256);
    let deserialized_res = reader.from_bytes(&serialized, false);
    if let Err(e) = &deserialized_res {
        panic!("Deserialization failed: {e}");
    }
    let (deserialized, remaining) = deserialized_res.unwrap();
    assert_eq!(remaining.len(), 0);

    let computed_id = compile_eval::compute_id(&rf, &deserialized.raw);
    assert_eq!(deserialized.raw.ninput, circuit.raw.ninput);
    assert_eq!(deserialized.raw.npublic_input, circuit.raw.npublic_input);
    assert_eq!(deserialized.raw.noutput, circuit.raw.noutput);
    assert_eq!(deserialized.raw.layers.len(), circuit.raw.layers.len());
    assert_eq!(deserialized.raw.logv, circuit.raw.logv);

    for (i, layer) in deserialized.raw.layers.iter().enumerate() {
        let orig_layer = &circuit.raw.layers[i];

        assert_eq!(layer.nw(), orig_layer.nw());
        assert_eq!(layer.logw(), orig_layer.logw());
        assert_eq!(layer.num_terms(), orig_layer.num_terms());

        let layer_terms = layer.terms(&deserialized.raw.constants);
        let orig_terms = orig_layer.terms(&circuit.raw.constants);
        assert_eq!(layer_terms.len(), orig_terms.len());

        for (j, term) in layer_terms.iter().enumerate() {
            let orig_term = &orig_terms[j];
            assert_eq!(rf.to_bytes(&term.k), f.to_bytes(&orig_term.k));
            assert_eq!(term.g, orig_term.g);
            assert_eq!(term.h0, orig_term.h0);
            assert_eq!(term.h1, orig_term.h1);
        }
    }
    assert_eq!(deserialized.id, circuit.id);
    assert_eq!(computed_id, circuit.id);
}

#[test]
fn test_circuit_serialization_lfc1_roundtrip() {
    let f = P256Field::new();
    let rf = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let boolean = Boolean::new(&iologic);

    let a = iologic.input(1);
    let b = iologic.input(2);

    let ab = boolean.of_eltw(a);
    let bb = boolean.of_eltw(b);

    let x = boolean.xorb(&ab, &bb);
    let assertion = boolean.assert_true("assert_x", &x);

    let (circuit, _, _) = compile_compiler::top::compile(&arena, &f, assertion, 1, 0);

    let writer = CircuitWriter::new(&f, FieldID::P256);
    let serialized = writer.to_bytes_lfc1(&circuit);

    let reader = CircuitReader::new(&rf, FieldID::P256);
    let deserialized_res = reader.from_bytes(&serialized, false);
    if let Err(e) = &deserialized_res {
        panic!("Deserialization failed: {e}");
    }
    let (deserialized, remaining) = deserialized_res.unwrap();
    assert_eq!(remaining.len(), 0);

    let computed_id = compile_eval::compute_id(&rf, &deserialized.raw);
    assert_eq!(deserialized.id, circuit.id);
    assert_eq!(computed_id, circuit.id);
}

#[test]
fn test_circuit_serialization_compatibility() {
    let f = P256Field::new();
    let rf = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let boolean = Boolean::new(&iologic);

    let a = iologic.input(1);
    let b = iologic.input(2);

    let ab = boolean.of_eltw(a);
    let bb = boolean.of_eltw(b);

    let x = boolean.xorb(&ab, &bb);
    let assertion = boolean.assert_true("assert_x", &x);

    let (circuit, _, _) = compile_compiler::top::compile(&arena, &f, assertion, 1, 0);

    let writer = CircuitWriter::new(&f, FieldID::P256);
    let serialized_lfc1 = writer.to_bytes_lfc1(&circuit);
    let serialized_lfc2 = writer.to_bytes_lfc2(&circuit);

    let reader = CircuitReader::new(&rf, FieldID::P256);

    let (c1, _) = reader.from_bytes(&serialized_lfc1, false).unwrap();
    let (c2, _) = reader.from_bytes(&serialized_lfc2, false).unwrap();

    assert_eq!(c1.id, c2.id);
    assert_eq!(c1.raw.ninput, c2.raw.ninput);
    assert_eq!(c1.raw.layers.len(), c2.raw.layers.len());
    assert_eq!(c1.raw.constants.len(), c2.raw.constants.len());
}
