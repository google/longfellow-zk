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
    algebra::{Field, ceil_lg2, lagrange_basis},
    circuit::{Circuit, CircuitLayer},
    ligero::LigeroTerm,
    sumcheck::{
        CircuitPad, LayerPad, SumcheckLayerProof, begin_circuit, begin_layer, end_layer, eq2,
        eval_bound_quad, round_poly,
    },
    transcript::Transcript,
};

pub use super::expression::{Expression, Var};

pub fn symbolic_sumcheck_round<F: Field + 'static>(
    claim: Expression<F>,
    round_pad: &[usize; 2],
    hp_evals: &[F; 2],
    ts: &mut Transcript,
) -> (Expression<F>, F) {
    let challenge_val = round_poly(ts, hp_evals);
    let lag = lagrange_basis(challenge_val);

    let p0 = Var(round_pad[0]) + hp_evals[0];
    let p2 = Var(round_pad[1]) + hp_evals[1];
    let p1 = claim - p0.clone();

    let next_claim = p0 * lag[0] + p1 * lag[1] + p2 * lag[2];

    (next_claim, challenge_val)
}

pub struct ClaimsState<F> {
    pub logv: usize,
    pub claim: [Expression<F>; 2],
    pub hc: [Vec<F>; 2],
}

pub struct SymRes<F> {
    pub a: Vec<LigeroTerm<F>>,
    pub b: Vec<F>,
}

fn constrain_to_be_zero<F: Field>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    expr: &Expression<F>,
) {
    let c = b.len();
    for (&witness_idx, &coeff) in &expr.terms {
        a.push(LigeroTerm {
            coeff,
            constraint_idx: c,
            witness_idx,
        });
    }
    b.push(expr.known);
}

fn verify_layer<F: Field + 'static>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    claims_state: &mut ClaimsState<F>,
    pad: &LayerPad<usize>,
    clr: &CircuitLayer<F>,
    plr: &SumcheckLayerProof<F>,
    ts: &mut Transcript,
) {
    let (alpha, beta) = begin_layer(ts);
    let mut lchal_hc = [Vec::new(), Vec::new()];

    let mut claim = claims_state.claim[0].clone() + claims_state.claim[1].clone() * alpha;

    for round in 0..clr.logw {
        for hand in 0..2 {
            let hp = &plr.hp[hand][round];
            let round_pad = &pad.rounds[round].hp[hand];
            let (next_claim, challenge_val) =
                symbolic_sumcheck_round(claim, round_pad, &hp.evals, ts);
            claim = next_claim;
            lchal_hc[hand].push(challenge_val);
        }
    }

    let eqq = eval_bound_quad(
        &clr.quad,
        claims_state.logv,
        &claims_state.hc[0],
        &claims_state.hc[1],
        &lchal_hc[0],
        &lchal_hc[1],
        clr.logw,
        alpha,
        beta,
    );

    let prod_expr = (Var(pad.claims.c0) * plr.claims[1]
        + Var(pad.claims.c1) * plr.claims[0]
        + Var(pad.claims.cr)
        + (plr.claims[0] * plr.claims[1]))
        * eqq;

    claim -= prod_expr;

    constrain_to_be_zero(a, b, &claim);

    end_layer(ts, &plr.claims);

    *claims_state = ClaimsState {
        logv: clr.logw,
        claim: [
            Var(pad.claims.c0) + plr.claims[0],
            Var(pad.claims.c1) + plr.claims[1],
        ],
        hc: lchal_hc,
    };
}

#[allow(clippy::too_many_arguments)]
fn input_constraint<F: Field>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    num_public_inputs: usize,
    num_inputs: usize,
    pub_inputs: &[F],
    claims_logv: usize,
    claims_hc0: &[F],
    claims_hc1: &[F],
    got_expr: Expression<F>,
    alpha: F,
) {
    let mut eq_vec = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        eq_vec.push(eq2(i, claims_logv, claims_hc0, claims_hc1, alpha));
    }

    let mut pub_binding = F::zero();
    for i in 0..num_public_inputs {
        pub_binding += eq_vec[i] * pub_inputs[i];
    }

    let mut mle_expr = Expression::from(pub_binding);
    for w in 0..(num_inputs - num_public_inputs) {
        mle_expr += Var(w) * eq_vec[num_public_inputs + w];
    }

    mle_expr -= got_expr;

    constrain_to_be_zero(a, b, &mle_expr);
}

pub fn symbolic_sumcheck_verifier_core<F: Field + 'static>(
    mut pad_index: usize,
    pub_inputs: &[F],
    circuit_data: &Circuit<F>,
    proof: &[SumcheckLayerProof<F>],
    ts: &mut Transcript,
) -> SymRes<F> {
    let mut a = Vec::new();
    let mut b = Vec::new();

    let num_inputs = circuit_data.ninput;
    let num_public_inputs = circuit_data.npublic_input;

    let logv_output = ceil_lg2(circuit_data.noutput);
    let (_, g_ch) = begin_circuit::<F>(ts);
    let hc_init = g_ch[0..logv_output].to_vec();

    let mut claims_state = ClaimsState {
        logv: logv_output,
        claim: [Expression::zero(), Expression::zero()],
        hc: [hc_init.clone(), hc_init],
    };

    let circuit_pad = CircuitPad::generate_indices(circuit_data, &mut pad_index);

    for ly in 0..circuit_data.layers.len() {
        verify_layer(
            &mut a,
            &mut b,
            &mut claims_state,
            &circuit_pad.layers[ly],
            &circuit_data.layers[ly],
            &proof[ly],
            ts,
        );
    }

    let alpha_input = ts.get_elt_field();
    let got_expr = claims_state.claim[0].clone() + claims_state.claim[1].clone() * alpha_input;

    input_constraint(
        &mut a,
        &mut b,
        num_public_inputs,
        num_inputs,
        pub_inputs,
        claims_state.logv,
        &claims_state.hc[0],
        &claims_state.hc[1],
        got_expr,
        alpha_input,
    );

    SymRes { a, b }
}
