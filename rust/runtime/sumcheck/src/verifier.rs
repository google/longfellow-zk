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

use runtime_algebra::{poly::InterpolationField, ElementOf, RuntimeField, SupportsSampling};
use runtime_random::Transcript;

use crate::{
    dense,
    hquad::HQuad,
    poly::QuadWirePoly,
    proof::{RoundPoly, SumcheckProof},
    transcript::TranscriptSumcheck,
};

/// The intermediate claim values tracked during sumcheck verification.
pub struct Claims<const W: usize, F: RuntimeField<W>> {
    /// The number of inputs/witness elements in the current layer.
    pub nv: usize,
    /// The logarithm of the number of copy/quad variables.
    pub logv: usize,
    /// The current claimed evaluations of the witness at the current challenge points.
    pub claim: [F::E; 2],
    /// The current query vectors for the quad/gate variables (for right/left hands).
    pub hc: [Vec<F::E>; 2],
}

/// Verifies a complete Sumcheck proof against a given circuit and witness inputs.
///
/// # Warning
/// This sumcheck verifier is not zero-knowledge (ZK) and is for demonstration/testing
/// purposes only. Production code uses the ZK protocol (which pads the sumcheck with
/// random masking variables).
///
/// Returns `Ok(())` if verification succeeds, or an `Err(String)` containing
/// the failure reason.
pub fn verify<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    w_in: Vec<ElementOf<F>>,
    pad: &SumcheckProof<W, F>,
    circuit: &core_proto::circuit::Circuit<F>,
    proof: &SumcheckProof<W, F>,
    transcript: &mut Transcript,
    f: &F,
) -> Result<(), String> {
    assert!(
        circuit.raw.ninput >= circuit.raw.npublic_input,
        "npublic_input ({}) exceeds ninput ({})",
        circuit.raw.npublic_input,
        circuit.raw.ninput
    );
    assert!(
        w_in.len() >= circuit.raw.npublic_input,
        "input vector too short: expected at least npublic_input ({}) entries, got {}",
        circuit.raw.npublic_input,
        w_in.len()
    );

    // 1. Initialize the sumcheck transcript with the sumcheck statement.
    let public_inputs = &w_in[..circuit.raw.npublic_input];
    transcript.write_sumcheck_statement(circuit, public_inputs, f);
    verify_core(w_in, pad, circuit, proof, transcript, f)
}

pub fn verify_core<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    mut w_in: Vec<ElementOf<F>>,
    pad: &SumcheckProof<W, F>,
    circuit: &core_proto::circuit::Circuit<F>,
    proof: &SumcheckProof<W, F>,
    transcript: &mut Transcript,
    f: &F,
) -> Result<(), String> {
    if proof.layers.len() != circuit.raw.layers.len() {
        return Err(format!(
            "Proof layers count mismatch: expected {}, got {}",
            circuit.raw.layers.len(),
            proof.layers.len()
        ));
    }
    if pad.layers.len() != circuit.raw.layers.len() {
        return Err(format!(
            "Pad layers count mismatch: expected {}, got {}",
            circuit.raw.layers.len(),
            pad.layers.len()
        ));
    }

    // 2. Generate the initial challenges for the circuit output.
    let (_cc, hc) = transcript.begin_circuit(f);

    // 3. Initialize the claim with the circuit output's claims.
    let claims_init = Claims {
        nv: circuit.raw.noutput,
        logv: circuit.raw.logv,
        claim: [f.zero(), f.zero()],
        hc: [hc.clone(), hc],
    };

    // 4. Verify all circuit layers sequentially, updating the claims bottom-up.
    let claims = verify_layers(pad, circuit, proof, transcript, claims_init, f)?;

    let mut w1 = w_in.clone();

    // Check right hand witness evaluation
    if !crate::sane_logw(claims.logv) {
        return Err(format!("insane logv: {}", claims.logv));
    }
    if (w_in.len() as u64) > (1u64 << claims.logv) {
        return Err(format!(
            "size of wires {} exceeds 2^logw {}",
            w_in.len(),
            1u64 << claims.logv
        ));
    }
    dense::bind_all(claims.logv, &mut w_in, &claims.hc[0], f);
    let got0 = dense::as_scalar::<W, F>(&w_in);
    if got0 != claims.claim[0] {
        return Err("got0 != cl.claim[0]".to_string());
    }

    // Check left hand witness evaluation
    if (w1.len() as u64) > (1u64 << claims.logv) {
        return Err(format!(
            "size of wires {} exceeds 2^logw {}",
            w1.len(),
            1u64 << claims.logv
        ));
    }
    dense::bind_all(claims.logv, &mut w1, &claims.hc[1], f);
    let got1 = dense::as_scalar::<W, F>(&w1);
    if got1 != claims.claim[1] {
        return Err("got1 != cl.claim[1]".to_string());
    }

    Ok(())
}

/// Verifies the sumcheck claims layer-by-layer, bottom-up (from output layer to input layer).
fn verify_layers<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    pad: &SumcheckProof<W, F>,
    circuit: &core_proto::circuit::Circuit<F>,
    proof: &SumcheckProof<W, F>,
    ts: &mut Transcript,
    claims_init: Claims<W, F>,
    f: &F,
) -> Result<Claims<W, F>, String> {
    let mut claims = claims_init;

    for ly in 0..circuit.raw.layers.len() {
        let clr = &circuit.raw.layers[ly];
        let plr = proof
            .layers
            .get(ly)
            .ok_or_else(|| format!("Missing proof at layer {ly}"))?;
        let pad_layer = pad
            .layers
            .get(ly)
            .ok_or_else(|| format!("Missing pad at layer {ly}"))?;
        // Combine the right and left hand claims linearly using challenge alpha/beta.
        let (alpha, beta) = ts.begin_layer(f);
        let mut claim = claims.claim[0].clone();
        f.fma(&mut claim, &alpha, &claims.claim[1]);

        // Phase 2: Verify the quad/gate constraints sumcheck (quadratic round polynomials).
        let lchal_hc = verify_layer_quad(clr.logw(), &mut claim, plr, &pad_layer.hp, ts, f)?;

        // Reconstruct and evaluate HQuad at the sampled challenges to check consistency.
        let mut equad = HQuad::bind_g(
            clr,
            &circuit.raw.constants,
            claims.logv,
            claims.nv,
            &claims.hc[0],
            &claims.hc[1],
            &alpha,
            &beta,
            f,
        );

        for (lc0, lc1) in lchal_hc[0].iter().zip(&lchal_hc[1]).take(clr.logw()) {
            equad.bind_h(lc0, 0, f);
            equad.bind_h(lc1, 1, f);
        }

        // Feed final evaluations of this layer back to the transcript and reconstruct next claims.
        ts.end_layer(&plr.claims, f);
        let mut next_claims = [plr.claims[0].clone(), plr.claims[1].clone()];
        f.add(&mut next_claims[0], &pad_layer.claims[0]);
        f.add(&mut next_claims[1], &pad_layer.claims[1]);

        let mut got = equad.scalar();
        f.mul(&mut got, &next_claims[0]);
        f.mul(&mut got, &next_claims[1]);

        if got != claim {
            return Err("got != claim (layer)".to_string());
        }

        claims = Claims {
            nv: clr.nw(),
            logv: clr.logw(),
            claim: next_claims,
            hc: lchal_hc,
        };
    }
    Ok(claims)
}

/// Verifies Phase 2 (quad/gate variables sumcheck) for a layer.
fn verify_layer_quad<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    logw: usize,
    claim: &mut ElementOf<F>,
    plr: &crate::proof::LayerProof<W, F>,
    pad_hp: &[Vec<RoundPoly<W, F>>; 2],
    ts: &mut Transcript,
    f: &F,
) -> Result<[Vec<ElementOf<F>>; 2], String> {
    if !crate::sane_logw(logw) {
        return Err(format!("insane logw: {logw}"));
    }
    if plr.hp[0].len() != logw || plr.hp[1].len() != logw {
        return Err(format!(
            "Proof round polynomials count mismatch at layer: expected {}, got [{}, {}]",
            logw,
            plr.hp[0].len(),
            plr.hp[1].len()
        ));
    }
    if pad_hp[0].len() != logw || pad_hp[1].len() != logw {
        return Err(format!(
            "Pad round polynomials count mismatch at layer: expected {}, got [{}, {}]",
            logw,
            pad_hp[0].len(),
            pad_hp[1].len()
        ));
    }
    let mut hc = [Vec::with_capacity(logw), Vec::with_capacity(logw)];
    for (round, (pad0, pad1)) in pad_hp[0].iter().zip(&pad_hp[1]).enumerate().take(logw) {
        for (hand, hc_vec) in hc.iter_mut().enumerate() {
            let tp_proof = &plr.hp[hand][round];
            let tp_pad = if hand == 0 { pad0 } else { pad1 };

            let rnd = ts.round(tp_proof, f);
            let tp = tp_proof.add(tp_pad, f).to_poly(claim, f);

            *claim = tp.eval_lagrange(&rnd, f);
            hc_vec.push(rnd);
        }
    }
    Ok(hc)
}
