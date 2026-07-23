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

use runtime_algebra::{ElementOf, InterpolatorFactory, Subfield, ZkField};
use runtime_ligero::{param::LigeroQuadraticConstraint, LigeroProver};
use runtime_random::{RandomEngine, Transcript};
use runtime_sumcheck::{prove_core as sumcheck_prove_core, SumcheckProof, TranscriptSumcheck};

use crate::{common::ZkContext, ZkProof};

/// The Zero-Knowledge Prover.
pub struct ZkProver<const W: usize, F: ZkField<W>> {
    pub circuit: core_proto::circuit::Circuit<F>,
    pub config: runtime_ligero::param::LigeroConfig,
}

pub struct ZkCommitResult<const W: usize, F: ZkField<W>> {
    pad: SumcheckProof<W, F>,
    lqc: Vec<LigeroQuadraticConstraint>,
    lp: LigeroProver<W, F>,
    pub com: runtime_proto::ligero::LigeroCommitment,
}

impl<const W: usize, F: ZkField<W>> ZkProver<W, F> {
    pub fn new(
        circuit: core_proto::circuit::Circuit<F>,
        config: runtime_ligero::param::LigeroConfig,
    ) -> Self {
        Self { circuit, config }
    }
    /// Computes ZK commitment of the witness and ZK pads.
    #[allow(clippy::too_many_arguments)]
    pub fn commit<
        IF: InterpolatorFactory<W, F>,
        R: RandomEngine,
        SF: Subfield<E = ElementOf<F>>,
    >(
        &self,
        witness_only: &[ElementOf<F>],
        ctx: &ZkContext<'_, W, F, IF>,
        ts: &mut Transcript,
        rng: &mut R,
        sf: &SF,
    ) -> (ZkCommitResult<W, F>, runtime_proto::ZkProofGeometry) {
        let n_witness = self.circuit.raw.ninput - self.circuit.raw.npublic_input;
        assert_eq!(witness_only.len(), n_witness, "witness length mismatch");

        // Rebase the subfield boundary to private witnesses
        let mut subfield_boundary = 0;
        if self.circuit.raw.subfield_boundary >= self.circuit.raw.npublic_input {
            subfield_boundary = self.circuit.raw.subfield_boundary - self.circuit.raw.npublic_input;
        }

        let (pad, pad_witness) = new_pad(&self.circuit, rng, ctx.f);

        let mut witness = witness_only.to_vec();
        witness.extend(pad_witness);

        let lqc = crate::common::setup_lqc(n_witness, &self.circuit);

        let ligero_param = runtime_ligero::param::LigeroParam::new(
            witness.len(),
            self.circuit.raw.layers.len(),
            self.config,
            ctx.make_interpolator,
        );

        let (lp, com) = runtime_ligero::prover::LigeroProver::commit(
            subfield_boundary,
            &witness,
            ligero_param,
            ts,
            &lqc,
            ctx.make_interpolator,
            rng,
            ctx.f,
            sf,
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
        let geom = runtime_proto::ZkProofGeometry {
            com_geom: ligero_param.geom,
            sc_geom,
        };
        (ZkCommitResult { pad, lqc, lp, com }, geom)
    }

    /// Generates ZK proof over the committed witness and pads.
    pub fn prove<IF: InterpolatorFactory<W, F>>(
        &self,
        public_inputs: Vec<ElementOf<F>>,
        witness_only: Vec<ElementOf<F>>,
        commit_info: &ZkCommitResult<W, F>,
        tsp: &mut Transcript,
        ctx: &ZkContext<'_, W, F, IF>,
    ) -> Result<ZkProof<W, F>, String> {
        let n_public = self.circuit.raw.npublic_input;
        let n_witness = self.circuit.raw.ninput - self.circuit.raw.npublic_input;
        assert_eq!(
            public_inputs.len(),
            n_public,
            "public inputs length mismatch"
        );
        let mut inputs_and_witnesses = Vec::with_capacity(n_public + n_witness);
        inputs_and_witnesses.extend(public_inputs.clone());
        inputs_and_witnesses.extend(witness_only);

        // Initialize Fiat-Shamir transcript with the sumcheck statement here before forking,
        // rather than inside sumcheck_prove_core, because ZkProver runs both sumcheck_prove_core
        // and symbolic_sumcheck_verifier_core in parallel over the same transcript state.
        tsp.write_sumcheck_statement(&self.circuit, &public_inputs, ctx.f);

        // We clone tsp into ts_sumcheck_prover.  ZKProver is running
        // both a sumcheck prover and a (symbolic) sumcheck verifier
        // in parallel.  Following the ZKVerifier flow, we give the
        // main TSP transcript to the sumcheck verifier, and fork it
        // for the sumcheck prover.
        let mut ts_sumcheck_prover = tsp.clone();

        let in_layers = runtime_sumcheck::eval_circuit(inputs_and_witnesses, &self.circuit, ctx.f)
            .map_err(|e| format!("eval_circuit failed: {e}"))?;

        let (proof, aux) = sumcheck_prove_core(
            in_layers,
            &commit_info.pad,
            &self.circuit,
            &mut ts_sumcheck_prover,
            ctx.f,
        );

        // The prover does not need the RHS constants vector `b` and can discard it,
        // since it is public and computed by the verifier during verification.
        let (a, b) = crate::symbolic_sumcheck_verifier::symbolic_sumcheck_verifier_core(
            n_witness,
            &public_inputs,
            &self.circuit,
            &proof,
            Some(&aux),
            tsp,
            ctx.f,
        );

        let statement_hash = crate::common::DEFAULT_STATEMENT_HASH;

        let com_proof = commit_info.lp.prove(
            &b,
            tsp,
            &a,
            &statement_hash,
            &commit_info.lqc,
            ctx.make_interpolator,
            ctx.f,
        );

        Ok(ZkProof {
            com: commit_info.com.clone(),
            sumcheck_proof: proof,
            com_proof,
        })
    }
}

/// Generates a new random sumcheck proof pad for a given circuit.
fn new_pad<
    const W: usize,
    F: runtime_algebra::poly::InterpolationField<W>
        + core_algebra::SerializableField
        + runtime_algebra::SupportsSampling<W>,
    R: RandomEngine,
>(
    circuit: &core_proto::circuit::Circuit<F>,
    rng: &mut R,
    f: &F,
) -> (SumcheckProof<W, F>, Vec<ElementOf<F>>) {
    let mut pad = SumcheckProof { layers: Vec::new() };
    let mut witness = Vec::new();

    for ly in 0..circuit.raw.layers.len() {
        let clr = &circuit.raw.layers[ly];

        // 2. hp: hand variables pad
        let mut hp = [
            Vec::with_capacity(clr.logw()),
            Vec::with_capacity(clr.logw()),
        ];
        for _round in 0..clr.logw() {
            for hp_slot in &mut hp {
                let r0 = rng.elt_field(f);
                let r2 = rng.elt_field(f);
                witness.push(r0.clone());
                witness.push(r2.clone());
                hp_slot.push(runtime_proto::RoundPoly {
                    evaluations: [r0, r2],
                });
            }
        }

        // 3. wc: final layer evaluations pad
        let r0 = rng.elt_field(f);
        let r1 = rng.elt_field(f);
        witness.push(r0.clone());
        witness.push(r1.clone());

        // Commit to product of pads for product proof.
        let rr = f.mulf(&r0, &r1);
        witness.push(rr);

        pad.layers.push(runtime_sumcheck::LayerProof {
            hp,
            claims: [r0, r1],
        });
    }

    (pad, witness)
}
