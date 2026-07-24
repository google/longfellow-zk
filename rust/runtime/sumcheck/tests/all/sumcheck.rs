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

use compile_algebra::p256::P256Field as CompileP256;
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::{Logic, LogicIO};
use core_proto::{
    circuit::Circuit, reader::CircuitReader, writer::CircuitWriter, FieldID, SerializableField,
};
use runtime_algebra::{
    field::{RuntimeField, SupportsU64Conversions},
    p256::P256Field as RuntimeP256,
    AlgebraicField,
};
use runtime_random::{RandomEngine, Transcript};
use runtime_sumcheck::{
    eval::eval_circuit, prover::prove, verifier::verify, LayerProof, Poly, QuadRoundPoly,
    SumcheckProof,
};

fn zero_proof<const W: usize, F: SerializableField + RuntimeField<W>>(
    circ: &Circuit<F>,
    f: &F,
) -> SumcheckProof<W, F> {
    let mut layers = Vec::new();
    for ly in 0..circ.raw.layers.len() {
        let clr = &circ.raw.layers[ly];
        let hp = [
            vec![Poly::<3, W, F>::zero(f).to_wire(); clr.logw()],
            vec![Poly::<3, W, F>::zero(f).to_wire(); clr.logw()],
        ];
        let claims = [f.zero(), f.zero()];
        layers.push(LayerProof { hp, claims });
    }
    SumcheckProof { layers }
}

fn compile_circuit(
    build_fn: impl for<'a> FnOnce(
        &'a CompilerArena<'a, CompileP256>,
        &'a CompileP256,
    ) -> (
        compile_compiler::CompilerAssertions<'a, CompileP256>,
        compile_logic::scope::AssertionScope,
    ),
) -> (Circuit<RuntimeP256>, RuntimeP256) {
    let fc = CompileP256::new();
    let arena = CompilerArena::new();
    let (assert_expr, tracker) = build_fn(&arena, &fc);

    let (circ_comp, _, _) = compile_compiler::top::compile(&arena, &fc, assert_expr, tracker, 1, 0);

    let f = RuntimeP256::new();
    let writer = CircuitWriter::new(&fc, FieldID::P256);
    let bytes = writer.to_bytes_lfc2(&circ_comp);
    let reader = CircuitReader::new(&f, FieldID::P256);
    let (circ, _) = reader
        .from_bytes_lfc2(&bytes, true)
        .expect("Circuit conversion to runtime field failed");

    (circ, f)
}

#[test]
fn test_sumcheck_prover_verifier_end_to_end() {
    let (circ, f) = compile_circuit(|arena, fc| {
        let logic = CompilerLogic::new(arena, fc);
        let x = logic.input(1);
        let y = logic.input(2);
        let z = logic.mul(&x, &y);
        (logic.assert0("assert_z", &z), logic.tracker)
    });

    // Witness where x = 1, y = 0 => z = 1 * 0 = 0 (satisfies assert0)
    let mut w0 = vec![f.zero(); circ.raw.ninput];
    w0[0] = f.one();
    w0[1] = f.one();
    w0[2] = f.zero();

    let in_layers = eval_circuit(w0.clone(), &circ, &f).unwrap();

    let mut transcript = Transcript::new(b"test_sumcheck");
    let pad = zero_proof(&circ, &f);
    let (proof, _) = prove(in_layers, &pad, &circ, &mut transcript, &f);

    let mut verifier_transcript = Transcript::new(b"test_sumcheck");
    let verify_result = verify(
        w0.clone(),
        &pad,
        &circ,
        &proof,
        &mut verifier_transcript,
        &f,
    );

    assert!(
        verify_result.is_ok(),
        "Verification failed: {:?}",
        verify_result.err()
    );

    let buf_prover = transcript.bytes(256);
    let buf_verifier = verifier_transcript.bytes(256);
    assert_eq!(
        buf_prover, buf_verifier,
        "Prover and verifier transcripts differ!"
    );
}

#[test]
fn test_sumcheck_prover_verifier_with_nonzero_pad() {
    let (circ, f) = compile_circuit(|arena, fc| {
        let logic = CompilerLogic::new(arena, fc);
        let x = logic.input(1);
        let y = logic.input(2);
        let z = logic.mul(&x, &y);
        (logic.assert0("assert_z", &z), logic.tracker)
    });

    let mut w_pad = vec![f.zero(); circ.raw.ninput];
    w_pad[0] = f.one();
    w_pad[2] = f.u64_to_element(5);

    let in_layers_pad = eval_circuit(w_pad, &circ, &f).unwrap();
    let zero_pad = zero_proof(&circ, &f);
    let mut transcript_pad = Transcript::new(b"test_sumcheck");
    let (pad, _) = prove(in_layers_pad, &zero_pad, &circ, &mut transcript_pad, &f);

    // The actual unpadded witness is where x=0, y=0. Position 0 is One.
    let mut w0 = vec![f.zero(); circ.raw.ninput];
    w0[0] = f.one();
    let in_layers = eval_circuit(w0.clone(), &circ, &f).unwrap();

    let mut transcript = Transcript::new(b"test_sumcheck");
    let (proof, _) = prove(in_layers, &pad, &circ, &mut transcript, &f);

    let mut verifier_transcript = Transcript::new(b"test_sumcheck");
    let verify_result = verify(
        w0.clone(),
        &pad,
        &circ,
        &proof,
        &mut verifier_transcript,
        &f,
    );

    assert!(
        verify_result.is_ok(),
        "Verification failed: {:?}",
        verify_result.err()
    );

    let buf_prover = transcript.bytes(256);
    let buf_verifier = verifier_transcript.bytes(256);
    assert_eq!(
        buf_prover, buf_verifier,
        "Prover and verifier transcripts differ!"
    );
}

#[test]
fn test_sumcheck_multi_layer() {
    let (circ, f) = compile_circuit(|arena, fc| {
        let logic = CompilerLogic::new(arena, fc);
        let mut x = logic.input(1);
        let y = logic.input(2);
        for _ in 0..6 {
            let sum = logic.add(&x, &y);
            x = logic.mul(&sum, &x);
        }
        (logic.assert0("assert_x", &x), logic.tracker)
    });
    assert!(
        circ.raw.layers.len() > 1,
        "Circuit must have multiple layers"
    );

    let mut w0 = vec![f.zero(); circ.raw.ninput];
    w0[0] = f.one();
    w0[1] = f.zero();
    w0[2] = f.u64_to_element(12345);

    let in_layers = eval_circuit(w0.clone(), &circ, &f).unwrap();
    let mut transcript_prover = Transcript::new(b"test_multi_layer");
    let pad = zero_proof(&circ, &f);
    let (proof, _) = prove(in_layers, &pad, &circ, &mut transcript_prover, &f);

    let mut transcript_verifier = Transcript::new(b"test_multi_layer");
    let verify_result = verify(
        w0.clone(),
        &pad,
        &circ,
        &proof,
        &mut transcript_verifier,
        &f,
    );

    assert!(
        verify_result.is_ok(),
        "Verification failed: {:?}",
        verify_result.err()
    );
}
