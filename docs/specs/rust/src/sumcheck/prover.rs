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

#![allow(clippy::needless_range_loop)]
use crate::{
    algebra::{Field, ceil_lg2},
    circuit::{Circuit, Term},
    sumcheck::{
        CircuitPad, LayerPad, SumcheckLayerProof, SumcheckRoundEvals, begin_circuit, begin_layer,
        bind_g, end_layer, round_poly,
    },
    transcript::Transcript,
};

/// Returns the element at `index`, treating the slice as infinitely padded with zeroes.
pub fn vector_ref<F: Field>(w: &[F], index: usize) -> F {
    if index < w.len() { w[index] } else { F::zero() }
}

/// Evaluates a single round polynomial for the sumcheck protocol.
/// Returns evaluations at 0, 1, and x2.
fn eval_round_poly<F: Field + 'static>(
    quad_terms: &[Term<F>],
    active_hand: &[F],
    other_hand: &[F],
    hand: usize,
    eval_point_x2: F,
) -> [F; 3] {
    let one_minus_x2 = F::one() - eval_point_x2;
    let mut ev0 = F::zero();
    let mut ev1 = F::zero();
    let mut ev2 = F::zero();

    let other_hand_idx = 1 - hand;

    for term in quad_terms {
        let is_even = term.h[hand] % 2 == 0;
        let pair_base_idx = term.h[hand] & !1;

        let w0 = vector_ref(active_hand, pair_base_idx);
        let w1 = vector_ref(active_hand, pair_base_idx | 1);
        let other_val = vector_ref(other_hand, term.h[other_hand_idx]);

        let coef = term.k * other_val;
        let wx2 = w0 + eval_point_x2 * (w1 - w0);

        if is_even {
            ev0 += coef * w0;
            ev2 += coef * one_minus_x2 * wx2;
        } else {
            ev1 += coef * w1;
            ev2 += coef * eval_point_x2 * wx2;
        }
    }

    [ev0, ev1, ev2]
}

/// Binds active wires to a challenge point.
pub fn bind<F: Field>(wires: &mut Vec<F>, challenge: F) {
    let n = wires.len().div_ceil(2);
    let one_minus_c = F::one() - challenge;
    for i in 0..n {
        let w0 = vector_ref(wires, 2 * i);
        let w1 = vector_ref(wires, 2 * i + 1);
        wires[i] = w0 * one_minus_c + w1 * challenge;
    }
    wires.truncate(n);
}

pub fn sumcheck_prove_layer<F: Field + 'static>(
    transcript: &mut Transcript,
    layer_pad: &LayerPad<F>,
    wires: &[F],
    mut quad_terms: Vec<Term<F>>,
    logw: usize,
) -> (SumcheckLayerProof<F>, [Vec<F>; 2], [F; 2]) {
    let mut challenges = [Vec::new(), Vec::new()];
    let mut hp = [Vec::with_capacity(logw), Vec::with_capacity(logw)];

    let x2 = F::sumcheck_eval_points()[2];
    let mut active_wires = [wires.to_vec(), wires.to_vec()];

    for round in 0..logw {
        for hand in 0..2 {
            let other_hand = 1 - hand;
            let evaluations = eval_round_poly(
                &quad_terms,
                &active_wires[hand],
                &active_wires[other_hand],
                hand,
                x2,
            );

            // Pad the polynomial evaluations
            let round_pad = &layer_pad.rounds[round].hp[hand];
            let padded_sumcheck_poly =
                [evaluations[0] - round_pad[0], evaluations[2] - round_pad[1]];

            // Get challenge from transcript
            let challenge = round_poly(transcript, &padded_sumcheck_poly);
            challenges[hand].push(challenge);

            hp[hand].push(SumcheckRoundEvals {
                evals: padded_sumcheck_poly,
            });

            // Fold the active wires with the challenge
            bind(&mut active_wires[hand], challenge);

            // Update quadratic terms for the next round
            let one_minus_c = F::one() - challenge;
            for term in quad_terms.iter_mut() {
                if term.h[hand] % 2 == 0 {
                    term.k *= one_minus_c;
                } else {
                    term.k *= challenge;
                }
                term.h[hand] /= 2;
            }
        }
    }

    let next_claims = [
        vector_ref(&active_wires[0], 0),
        vector_ref(&active_wires[1], 0),
    ];
    let proof_claims = [
        next_claims[0] - layer_pad.claims.c0,
        next_claims[1] - layer_pad.claims.c1,
    ];

    end_layer(transcript, &proof_claims);

    let proof = SumcheckLayerProof {
        hp,
        claims: proof_claims,
    };
    (proof, challenges, next_claims)
}

pub fn sumcheck_prove<F: Field + 'static>(
    transcript: &mut Transcript,
    in_layers: &[Vec<F>],
    circuit_data: &Circuit<F>,
    circuit_pad: &CircuitPad<F>,
) -> (Vec<SumcheckLayerProof<F>>, [F; 2]) {
    let (_copy_challenges, global_challenges) = begin_circuit::<F>(transcript);

    let initial_logv = ceil_lg2(circuit_data.noutput);
    let mut current_logv = initial_logv;
    let mut current_challenges = [
        global_challenges[0..initial_logv].to_vec(),
        global_challenges[0..initial_logv].to_vec(),
    ];

    let mut final_claims = [F::zero(); 2];
    let mut proofs = Vec::with_capacity(circuit_data.layers.len());

    for layer_index in 0..circuit_data.layers.len() {
        let layer = &circuit_data.layers[layer_index];
        let (alpha, beta) = begin_layer(transcript);

        let mut quad_terms = layer.quad.clone();
        bind_g(
            &mut quad_terms,
            current_logv,
            &current_challenges[0],
            &current_challenges[1],
            alpha,
            beta,
        );

        let (proof, next_challenges, next_claims) = sumcheck_prove_layer(
            transcript,
            &circuit_pad.layers[layer_index],
            &in_layers[layer_index],
            quad_terms,
            layer.logw,
        );

        current_logv = layer.logw;
        current_challenges = next_challenges;
        final_claims = next_claims;
        proofs.push(proof);
    }

    (proofs, final_claims)
}
