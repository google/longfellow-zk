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

use crate::{
    algebra::{Field, Rng},
    circuit::Circuit,
    ligero::{LigeroCommitResult, LigeroConfig, LigeroProver, LqcTriple},
    sumcheck::{CircuitPad, eval_circuit, sumcheck_prove},
    transcript::Transcript,
    zk::{
        DEFAULT_STATEMENT_HASH, ZkProof, generate_lqc_triples, symbolic_sumcheck_verifier_core,
        write_sumcheck_statement,
    },
};

pub struct ZkProver<F> {
    pub circuit_data: Circuit<F>,
    pub config: LigeroConfig,
}

pub struct ZkCommitResult<F: Field + 'static> {
    pub prover: LigeroProver<F>,
    pub commit: LigeroCommitResult<F>,
    pub pad: CircuitPad<F>,
    pub lqc: Vec<LqcTriple>,
    pub root: [u8; 32],
}

impl<F: Field + 'static> ZkProver<F> {
    pub fn new(circuit_data: Circuit<F>, config: LigeroConfig) -> Self {
        Self {
            circuit_data,
            config,
        }
    }

    pub fn commit<R: Rng>(&self, inputs: &[F], rng: &mut R) -> ZkCommitResult<F> {
        let (pad, pad_witness) = CircuitPad::sample(&self.circuit_data, rng);

        let lqc = generate_lqc_triples(&self.circuit_data);

        // Assemble witness (private inputs + padding)
        let n_public = self.circuit_data.npublic_input;
        let mut witness = inputs[n_public..].to_vec();
        witness.extend_from_slice(&pad_witness);

        // Commit to witness
        let subfield = F::Subfield::default();
        let prover_pcs = LigeroProver::new(self.config.clone(), witness.len(), lqc.len(), subfield);
        let subfield_boundary = self.circuit_data.subfield_boundary.saturating_sub(n_public);

        let commit = prover_pcs.commit(&witness, &lqc, rng, subfield_boundary);

        let mut root = [0u8; 32];
        root.copy_from_slice(&commit.merkle.root);

        ZkCommitResult {
            prover: prover_pcs,
            commit,
            pad,
            lqc,
            root,
        }
    }

    pub fn prove(&self, inputs: &[F], commit_info: &ZkCommitResult<F>, label: &str) -> ZkProof<F> {
        let n_public = self.circuit_data.npublic_input;
        let public_inputs = &inputs[..n_public];

        // Initialize transcript and bind public inputs/commit root
        let mut transcript = Transcript::new(label.as_bytes());
        transcript.write_bytes(&commit_info.root);
        write_sumcheck_statement(&mut transcript, &self.circuit_data, inputs);

        // Run sumcheck prover
        let in_layers =
            eval_circuit(inputs, &self.circuit_data).expect("Circuit evaluation failed");
        let mut sumcheck_transcript = transcript.clone();

        let (sumcheck_proof, _) = sumcheck_prove(
            &mut sumcheck_transcript,
            &in_layers,
            &self.circuit_data,
            &commit_info.pad,
        );

        // Verify symbolically and generate PC proof
        let pad_index_start = inputs.len() - n_public;
        let sym_res = symbolic_sumcheck_verifier_core(
            pad_index_start,
            public_inputs,
            &self.circuit_data,
            &sumcheck_proof,
            &mut transcript,
        );

        // The statement hash passed to Ligero is hardcoded for backward compatibility.
        // This is safe because all statement-specific information (Merkle root, public inputs,
        // and sumcheck transcript state) has already been written to the transcript before this point.
        let stmt_hash = DEFAULT_STATEMENT_HASH;

        let com_proof = commit_info.prover.prove(
            &commit_info.commit,
            &commit_info.lqc,
            &sym_res.a,
            &sym_res.b,
            &stmt_hash,
            &mut transcript,
        );

        ZkProof {
            root: commit_info.root,
            sumcheck_proof,
            ligero_proof: com_proof,
        }
    }
}
