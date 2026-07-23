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

use core::fmt;

use runtime_algebra::{ElementOf, InterpolatorFactory, ZkField};
use runtime_ligero::param::{LigeroConfig, LigeroParam};
use runtime_random::Transcript;
use runtime_sumcheck::TranscriptSumcheck;

use crate::{common::ZkContext, ZkProof};

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
    PublicInputLengthMismatch {
        expected: usize,
        actual: usize,
    },
    LigeroVerification(String),
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

impl std::error::Error for ZkVerificationError {}

/// The Zero-Knowledge Verifier.
pub struct ZkVerifier<const W: usize, F: ZkField<W>> {
    pub circuit: core_proto::circuit::Circuit<F>,
    pub config: LigeroConfig,
}

impl<const W: usize, F: ZkField<W>> ZkVerifier<W, F> {
    /// Constructs a new `ZkVerifier` with the given Ligero configuration.
    pub fn new(circuit: core_proto::circuit::Circuit<F>, config: LigeroConfig) -> Self {
        Self { circuit, config }
    }

    pub fn geometry<IF: InterpolatorFactory<W, F>>(
        &self,
        ctx: &ZkContext<'_, W, F, IF>,
    ) -> runtime_proto::ZkProofGeometry {
        let n_witness = self.circuit.raw.ninput - self.circuit.raw.npublic_input;
        let pad_sz = crate::circuit_pad::CircuitPad::pad_size::<W, F>(&self.circuit);
        let ligero_param = LigeroParam::new(
            n_witness + pad_sz,
            self.circuit.raw.layers.len(),
            self.config,
            ctx.make_interpolator,
        );
        let sc_geom = runtime_proto::sumcheck::SumcheckProofGeometry {
            logw_layers: self
                .circuit
                .raw
                .layers
                .iter()
                .map(core_proto::Layer::logw)
                .collect(),
        };
        runtime_proto::ZkProofGeometry {
            sc_geom,
            com_geom: ligero_param.geom,
        }
    }

    /// Replays commitment transmission from P to V.
    pub fn recv_commitment<IF: InterpolatorFactory<W, F>>(
        &self,
        zkp: &ZkProof<W, F>,
        tv: &mut Transcript,
        ctx: &ZkContext<'_, W, F, IF>,
    ) {
        let n_witness = self.circuit.raw.ninput - self.circuit.raw.npublic_input;
        let pad_sz = crate::circuit_pad::CircuitPad::pad_size::<W, F>(&self.circuit);
        let ligero_param = LigeroParam::new(
            n_witness + pad_sz,
            self.circuit.raw.layers.len(),
            self.config,
            ctx.make_interpolator,
        );
        let mut lv = runtime_ligero::LigeroVerifier::new(tv, &ligero_param);
        lv.receive_commitment(&zkp.com);
    }

    /// Verifies ZK proof against public inputs and circuit.
    pub fn verify<IF: InterpolatorFactory<W, F>>(
        &self,
        pub_inputs: Vec<ElementOf<F>>,
        zkp: &ZkProof<W, F>,
        tv: &mut Transcript,
        ctx: &ZkContext<'_, W, F, IF>,
    ) -> Result<(), ZkVerificationError> {
        if pub_inputs.len() != self.circuit.raw.npublic_input {
            return Err(ZkVerificationError::PublicInputLengthMismatch {
                expected: self.circuit.raw.npublic_input,
                actual: pub_inputs.len(),
            });
        }
        if zkp.sumcheck_proof.layers.len() != self.circuit.raw.layers.len() {
            return Err(ZkVerificationError::SumcheckProofLayerMismatch {
                expected: self.circuit.raw.layers.len(),
                actual: zkp.sumcheck_proof.layers.len(),
            });
        }
        for (ly, (plr, clr)) in zkp
            .sumcheck_proof
            .layers
            .iter()
            .zip(&self.circuit.raw.layers)
            .enumerate()
        {
            if plr.hp[0].len() != clr.logw() || plr.hp[1].len() != clr.logw() {
                return Err(ZkVerificationError::SumcheckProofRoundMismatch {
                    layer: ly,
                    expected: clr.logw(),
                    actual: plr.hp[0].len(),
                });
            }
        }

        // Initialize Fiat-Shamir transcript with the sumcheck statement here, rather than
        // relying on sumcheck_verifier (since ZkVerifier calls symbolic_sumcheck_verifier_core
        // directly instead of standard sumcheck verification).
        tv.write_sumcheck_statement(&self.circuit, &pub_inputs, ctx.f);

        let n_witness = self.circuit.raw.ninput - self.circuit.raw.npublic_input;
        let (a, b) = crate::symbolic_sumcheck_verifier::symbolic_sumcheck_verifier_core(
            n_witness,
            &pub_inputs,
            &self.circuit,
            &zkp.sumcheck_proof,
            None,
            tv,
            ctx.f,
        );

        let statement_hash = crate::common::DEFAULT_STATEMENT_HASH;

        let pad_sz = crate::circuit_pad::CircuitPad::pad_size::<W, F>(&self.circuit);
        let ligero_param = LigeroParam::new(
            n_witness + pad_sz,
            self.circuit.raw.layers.len(),
            self.config,
            ctx.make_interpolator,
        );
        let lqc = crate::common::setup_lqc(n_witness, &self.circuit);

        let mut lv = runtime_ligero::LigeroVerifier::new(tv, &ligero_param);
        lv.verify(
            &b,
            &zkp.com,
            &zkp.com_proof,
            &a,
            &statement_hash,
            &lqc,
            ctx.make_interpolator,
            ctx.f,
        )
        .map_err(|e| ZkVerificationError::LigeroVerification(format!("{e:?}")))
    }
}
