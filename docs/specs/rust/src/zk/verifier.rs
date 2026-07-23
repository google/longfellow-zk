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

use std::fmt;

use crate::{
    algebra::Field,
    circuit::Circuit,
    ligero::{
        LigeroConfig, LigeroVerifier, LqcTriple, VerificationError as LigeroVerificationError,
    },
    transcript::Transcript,
    zk::{
        DEFAULT_STATEMENT_HASH, ZkProof, generate_lqc_triples, symbolic_sumcheck_verifier_core,
        write_sumcheck_statement,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkVerificationError {
    SumcheckProofLayerMismatch {
        expected: usize,
        actual: usize,
    },
    SumcheckProofRoundMismatch {
        layer: usize,
        expected: usize,
        actual: usize,
    },
    SumcheckProofEvaluationMismatch {
        layer: usize,
        round: usize,
    },
    PublicInputLengthMismatch {
        expected: usize,
        actual: usize,
    },
    LigeroVerification(LigeroVerificationError),
}

impl fmt::Display for ZkVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SumcheckProofLayerMismatch { expected, actual } => {
                write!(
                    f,
                    "Sumcheck proof layer count mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::SumcheckProofRoundMismatch {
                layer,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Sumcheck proof round count mismatch in layer {}: expected {}, got {}",
                    layer, expected, actual
                )
            }
            Self::SumcheckProofEvaluationMismatch { layer, round } => {
                write!(
                    f,
                    "Sumcheck proof evaluation mismatch in layer {}, round {}",
                    layer, round
                )
            }
            Self::PublicInputLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "Public input length mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::LigeroVerification(err) => write!(f, "Ligero commitment proof error: {}", err),
        }
    }
}

impl std::error::Error for ZkVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LigeroVerification(err) => Some(err),
            _ => None,
        }
    }
}

impl From<LigeroVerificationError> for ZkVerificationError {
    fn from(err: LigeroVerificationError) -> Self {
        Self::LigeroVerification(err)
    }
}

pub struct ZkVerifier<F> {
    pub circuit_data: Circuit<F>,
    pub config: LigeroConfig,
}

impl<F: Field + 'static> ZkVerifier<F> {
    pub fn new(circuit_data: Circuit<F>, config: LigeroConfig) -> Self {
        Self {
            circuit_data,
            config,
        }
    }

    pub fn lqc_triples(&self) -> Vec<LqcTriple> {
        generate_lqc_triples(&self.circuit_data)
    }

    pub fn verify(
        &self,
        public_inputs: &[F],
        zkp: &ZkProof<F>,
        label: &str,
    ) -> Result<(), ZkVerificationError> {
        // Validate public inputs length
        if public_inputs.len() != self.circuit_data.npublic_input {
            return Err(ZkVerificationError::PublicInputLengthMismatch {
                expected: self.circuit_data.npublic_input,
                actual: public_inputs.len(),
            });
        }

        // 1. Validate sumcheck proof sizes and structures against circuit layout to prevent panics
        if zkp.sumcheck_proof.len() != self.circuit_data.layers.len() {
            return Err(ZkVerificationError::SumcheckProofLayerMismatch {
                expected: self.circuit_data.layers.len(),
                actual: zkp.sumcheck_proof.len(),
            });
        }
        for ly in 0..self.circuit_data.layers.len() {
            let clr = &self.circuit_data.layers[ly];
            let plr = &zkp.sumcheck_proof[ly];
            if plr.hp[0].len() != clr.logw || plr.hp[1].len() != clr.logw {
                return Err(ZkVerificationError::SumcheckProofRoundMismatch {
                    layer: ly,
                    expected: clr.logw,
                    actual: plr.hp[0].len(),
                });
            }
            for round in 0..clr.logw {
                if plr.hp[0][round].evals.len() < 2 || plr.hp[1][round].evals.len() < 2 {
                    return Err(ZkVerificationError::SumcheckProofEvaluationMismatch {
                        layer: ly,
                        round,
                    });
                }
            }
        }

        // 2. Validate requested elements size against expected circuit geometry
        let witness_only_len = self.circuit_data.ninput - self.circuit_data.npublic_input;
        let mut pad_witness_len = 3 * self.circuit_data.layers.len();
        for layer in &self.circuit_data.layers {
            pad_witness_len += 4 * layer.logw;
        }
        let nw = witness_only_len + pad_witness_len;

        let mut ts = Transcript::new(label.as_bytes());
        ts.write_bytes(&zkp.root);
        write_sumcheck_statement(&mut ts, &self.circuit_data, public_inputs);

        let pad_index_start = self.circuit_data.ninput - self.circuit_data.npublic_input;
        let sym_res = symbolic_sumcheck_verifier_core(
            pad_index_start,
            public_inputs,
            &self.circuit_data,
            &zkp.sumcheck_proof,
            &mut ts,
        );

        // The statement hash passed to Ligero is hardcoded.  This is
        // safe because all statement-specific information (Merkle
        // root, public inputs, and sumcheck transcript state) has
        // already been written to the transcript before this point.
        let statement_hash = DEFAULT_STATEMENT_HASH;

        let sf = F::Subfield::default();
        let ligero_verifier = LigeroVerifier::new(self.config.clone(), sf);
        ligero_verifier.verify(
            nw,
            &sym_res.b,
            &zkp.root,
            &zkp.ligero_proof,
            &sym_res.a,
            &statement_hash,
            &self.lqc_triples(),
            &mut ts,
        )?;

        Ok(())
    }
}
