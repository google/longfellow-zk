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

use core_algebra::ElementOf;
use runtime_algebra::{poly::InterpolationField, SupportsSampling};
use runtime_random::Transcript;

use crate::{
    hquad::HQuad,
    poly::{Poly, QuadRoundPoly, QuadWirePoly},
    proof::{LayerProof, SumcheckProof, MAX_LOGW},
    transcript::TranscriptSumcheck,
};

struct Bindings<const W: usize, F: InterpolationField<W>> {
    logv: usize,
    nv: usize,
    challenges: [Vec<ElementOf<F>>; 2],
}

pub struct SumcheckProofAux<const W: usize, F: InterpolationField<W>> {
    pub bound_quad: Vec<ElementOf<F>>,
}

impl<const W: usize, F: InterpolationField<W>> SumcheckProofAux<W, F> {
    pub fn new(num_layers: usize, f: &F) -> Self {
        Self {
            bound_quad: vec![f.zero(); num_layers],
        }
    }
}

pub fn prove<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    in_layers: Vec<Vec<ElementOf<F>>>,
    pad: &SumcheckProof<W, F>,
    circuit: &core_proto::circuit::Circuit<F>,
    transcript: &mut Transcript,
    f: &F,
) -> (SumcheckProof<W, F>, SumcheckProofAux<W, F>) {
    assert!(
        circuit.raw.ninput >= circuit.raw.npublic_input,
        "npublic_input ({}) exceeds ninput ({})",
        circuit.raw.npublic_input,
        circuit.raw.ninput
    );

    let inputs = &in_layers[circuit.raw.layers.len() - 1];
    assert!(
        inputs.len() >= circuit.raw.npublic_input,
        "input vector too short: expected at least npublic_input ({}) entries, got {}",
        circuit.raw.npublic_input,
        inputs.len()
    );
    let public_inputs = &inputs[..circuit.raw.npublic_input];
    transcript.write_sumcheck_statement(circuit, public_inputs, f);
    prove_core(in_layers, pad, circuit, transcript, f)
}

pub fn prove_core<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    mut in_layers: Vec<Vec<ElementOf<F>>>,
    pad: &SumcheckProof<W, F>,
    circuit: &core_proto::circuit::Circuit<F>,
    transcript: &mut Transcript,
    f: &F,
) -> (SumcheckProof<W, F>, SumcheckProofAux<W, F>) {
    // The wire array is conceptually infinite (padded with zeros), but we normalize
    // each layer's wire vector to contain at least one 0 to simplify the implementation
    // and avoid handling the empty vec case in downstream binding functions.
    for wires in &mut in_layers {
        *wires = crate::dense::normalize(std::mem::take(wires), f);
    }
    let (_copy_challenges, challenges_0) = transcript.begin_circuit(f);
    let mut bindings = Bindings {
        logv: circuit.raw.logv,
        nv: circuit.raw.noutput,
        challenges: [
            challenges_0[..circuit.raw.logv].to_vec(),
            challenges_0[..circuit.raw.logv].to_vec(),
        ],
    };

    let num_layers = circuit.raw.layers.len();
    assert!(in_layers.len() >= num_layers && pad.layers.len() >= num_layers);
    let layers_slice = &circuit.raw.layers[..num_layers];
    let in_layers_slice = &mut in_layers[..num_layers];
    let pad_layers_slice = &pad.layers[..num_layers];

    let mut claims = [f.zero(), f.zero()];
    let mut layers = Vec::with_capacity(num_layers);
    let mut bound_quad = Vec::with_capacity(num_layers);

    for i in 0..num_layers {
        let clr = &layers_slice[i];
        let (alpha, beta) = transcript.begin_layer(f);
        let wires = std::mem::take(&mut in_layers_slice[i]);
        let hquad = HQuad::bind_g(
            clr,
            &circuit.raw.constants,
            bindings.logv,
            bindings.nv,
            &bindings.challenges[0],
            &bindings.challenges[1],
            &alpha,
            &beta,
            f,
        );
        let (layer_proof, new_bindings, new_claims, hquad_scalar) = layer(
            clr.logw(),
            clr.nw(),
            wires,
            &pad_layers_slice[i],
            transcript,
            hquad,
            &alpha,
            claims,
            f,
        );
        bindings = new_bindings;
        claims = new_claims;

        bound_quad.push(hquad_scalar);
        layers.push(layer_proof);
    }

    (SumcheckProof { layers }, SumcheckProofAux { bound_quad })
}

#[allow(clippy::too_many_arguments)]
fn layer<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    logw: usize,
    nw: usize,
    wires: Vec<ElementOf<F>>,
    pad: &LayerProof<W, F>,
    transcript: &mut Transcript,
    mut hquad: HQuad<W, F>,
    alpha: &ElementOf<F>,
    claims: [ElementOf<F>; 2],
    f: &F,
) -> (
    LayerProof<W, F>,
    Bindings<W, F>,
    [ElementOf<F>; 2],
    ElementOf<F>,
) {
    assert!(crate::sane_logw(logw), "logw must be sane");
    assert!(
        wires.len() as u64 <= (1u64 << logw),
        "size of wires {} exceeds 2^logw {}",
        wires.len(),
        1u64 << logw
    );
    let mut challenges = [Vec::with_capacity(logw), Vec::with_capacity(logw)];
    let mut round_polys = [Vec::with_capacity(logw), Vec::with_capacity(logw)];
    let mut sum = claims[0].clone();
    f.fma(&mut sum, alpha, &claims[1]);

    // Wrap the initial wire vector in an Rc to avoid cloning the massive input slice.
    // At round 0, both right hand (w[0]) and left hand (w[1]) point to the same shared buffer.
    let wires_rc = std::rc::Rc::new(wires);
    let mut w = [wires_rc.clone(), wires_rc];
    let mut qw = vec![f.zero(); w[0].len()];

    for round in 0..logw {
        for hand in 0..2 {
            let other_hand = 1 - hand;
            let wh_hand = &w[hand];
            let wh_other_hand = &w[other_hand];

            let wh_size = wh_hand.len();
            runtime_algebra::blas::clear(&mut qw[..wh_size], f);

            if hand == 0 {
                for i in 0..hquad.hc.len() {
                    let p0 = hquad.hc[i].h[0] as usize;
                    let p1 = hquad.hc[i].h[1] as usize;
                    let dst = &mut qw[p0];
                    let witness_other_hand_val = &wh_other_hand[p1];
                    f.fma(dst, &hquad.vc[i], witness_other_hand_val);
                }
            } else {
                for i in 0..hquad.hc.len() {
                    let p0 = hquad.hc[i].h[1] as usize;
                    let p1 = hquad.hc[i].h[0] as usize;
                    let dst = &mut qw[p0];
                    let witness_other_hand_val = &wh_other_hand[p1];
                    f.fma(dst, &hquad.vc[i], witness_other_hand_val);
                }
            }

            let evaluations = quad_round_poly(wh_size, &qw[..wh_size], wh_hand, &sum, f);

            assert!(round < MAX_LOGW);
            let round_challenge = sample_round_challenge(
                transcript,
                &evaluations,
                &pad.hp[hand][round],
                &mut round_polys[hand],
                &mut challenges[hand],
                f,
            );
            sum = evaluations.eval_lagrange(&round_challenge, f);

            // In-place vs out-of-place binding optimization:
            // When w[hand] has strong count 1 (sole owner), get_mut returns Some(v) and we bind
            // in-place, reusing the allocated buffer without heap allocations.
            // In round 0 for hand=0, w[0] and w[1] share the Rc (strong count 2), so get_mut
            // returns None. We bind out-of-place to allocate a new halved buffer for
            // w[0], leaving w[1] as the sole owner of the original buffer. All
            // subsequent halvings across both hands then happen in-place!
            if let Some(v) = std::rc::Rc::get_mut(&mut w[hand]) {
                crate::dense::bind(v, &round_challenge, f);
            } else {
                let bound_v = crate::dense::bind_out_of_place(&w[hand], &round_challenge, f);
                w[hand] = std::rc::Rc::new(bound_v);
            }
            hquad.bind_h(&round_challenge, hand, f);
        }
    }

    let next_claims = [
        crate::dense::as_scalar::<W, F>(&w[0]),
        crate::dense::as_scalar::<W, F>(&w[1]),
    ];

    let hquad_scalar = hquad.scalar();
    let mut expected_sum = next_claims[0].clone();
    f.mul(&mut expected_sum, &next_claims[1]);
    f.mul(&mut expected_sum, &hquad_scalar);
    assert_eq!(
        sum, expected_sum,
        "reconstructed sum does not match expected"
    );

    let mut proof_claims = [next_claims[0].clone(), next_claims[1].clone()];
    f.sub(&mut proof_claims[0], &pad.claims[0]);
    f.sub(&mut proof_claims[1], &pad.claims[1]);
    transcript.end_layer(&proof_claims, f);

    let bindings = Bindings {
        logv: logw,
        nv: nw,
        challenges,
    };

    (
        LayerProof {
            hp: round_polys,
            claims: proof_claims, // padded
        },
        bindings,
        next_claims,
        hquad_scalar,
    )
}

/// Absorbs the unpadded round polynomial into the transcript after applying ZK padding,
/// samples the round challenge, and records the padded polynomial and challenge.
#[inline]
fn sample_round_challenge<const W: usize, F: InterpolationField<W> + SupportsSampling<W>>(
    transcript: &mut Transcript,
    unpadded_poly: &Poly<3, W, F>,
    pad_poly: &crate::proof::RoundPoly<W, F>,
    round_polys: &mut Vec<crate::proof::RoundPoly<W, F>>,
    challenges: &mut Vec<ElementOf<F>>,
    f: &F,
) -> ElementOf<F> {
    let poly_padded = unpadded_poly.to_wire().sub(pad_poly, f);
    let round_challenge = transcript.round(&poly_padded, f);
    round_polys.push(poly_padded);
    challenges.push(round_challenge.clone());
    round_challenge
}

/// Evaluates the quad round polynomial of degree 2 (represented
/// by 3 evaluation points) for the current sumcheck prover round.
///
/// Directly computes the evaluations [g(0), g(1), g(2)] without intermediate
/// monomial or Newton conversions.
#[inline]
fn quad_round_poly<const W: usize, F: InterpolationField<W>>(
    num_variables: usize,
    qw: &[ElementOf<F>],
    witness_values: &[ElementOf<F>],
    sum: &ElementOf<F>,
    f: &F,
) -> Poly<3, W, F> {
    let num_pairs = num_variables / 2;
    let mut accum_a0 = f.zero_accum();
    let mut accum_a2 = f.zero_accum();

    for i in 0..num_pairs {
        let idx = 2 * i;
        f.mac(&mut accum_a0, &qw[idx], &witness_values[idx]);
        let dqw = f.subf(&qw[idx + 1], &qw[idx]);
        let dw = f.subf(&witness_values[idx + 1], &witness_values[idx]);
        f.mac(&mut accum_a2, &dqw, &dw);
    }

    if !num_variables.is_multiple_of(2) {
        let last = num_variables - 1;
        f.mac(&mut accum_a0, &qw[last], &witness_values[last]);
        f.mac(&mut accum_a2, &qw[last], &witness_values[last]);
    }

    let a0 = f.accum_reduce(&accum_a0);
    let a2 = f.accum_reduce(&accum_a2);

    // g(0) = a0
    // g(1) = sum - a0
    let mut g1 = sum.clone();
    f.sub(&mut g1, &a0);

    // c1 = g(1) - a0 - a2 = sum - 2*a0 - a2
    let mut c1 = g1.clone();
    f.sub(&mut c1, &a0);
    f.sub(&mut c1, &a2);

    // Evaluate g(2) = a2*pt(2)^2 + c1*pt(2) + a0 using Horner's method for binary field
    // compatibility:
    let pt2 = f.poly_evaluation_point(2);
    let mut g2 = a2.clone();
    f.mul(&mut g2, &pt2);
    f.add(&mut g2, &c1);
    f.mul(&mut g2, &pt2);
    f.add(&mut g2, &a0);

    Poly {
        evaluations: [a0, g1, g2],
    }
}
