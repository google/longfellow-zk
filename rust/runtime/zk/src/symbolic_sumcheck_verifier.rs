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

use core_proto::circuit::Circuit;
use runtime_algebra::{ElementOf, RuntimeField, ZkField};
use runtime_ligero::param::LigeroLinearConstraint;
use runtime_random::{RandomEngine, Transcript};
use runtime_sumcheck::{proof::SumcheckProof, transcript::TranscriptSumcheck, SumcheckProofAux};

use crate::expression::Expression;

pub(crate) struct ClaimsState<const W: usize, F: RuntimeField<W>> {
    pub logv: usize,
    pub nv: usize,
    pub claim: [Expression<W, F>; 2],
    pub hc: [Vec<ElementOf<F>>; 2],
}

pub(crate) fn symbolic_sumcheck_round<const W: usize, F: ZkField<W>>(
    mut claim: Expression<W, F>,
    round_pad: &[usize; 2],
    hp: &runtime_proto::RoundPoly<W, F>,
    lagrange_basis: &runtime_sumcheck::LagrangeBasis<3, W, F>,
    transcript: &mut Transcript,
    f: &F,
) -> (Expression<W, F>, ElementOf<F>) {
    let challenge_val = transcript.round(hp, f);
    let lag_poly = lagrange_basis.coef(&challenge_val, f);
    let hp_evals = &hp.evaluations;
    let lag = &lag_poly.evaluations;

    let l0_minus_l1 = f.subf(&lag[0], &lag[1]);
    let term0 = f.mulf(&hp_evals[0], &l0_minus_l1);
    let term2 = f.mulf(&hp_evals[1], &lag[2]);

    claim.scale(&lag[1], f);

    f.add(&mut claim.known, &term0);
    f.add(&mut claim.known, &term2);

    claim.add_var(round_pad[0], l0_minus_l1, f);
    claim.add_var(round_pad[1], lag[2].clone(), f);

    (claim, challenge_val)
}

#[allow(clippy::too_many_arguments)]
fn verify_layer<const W: usize, F: ZkField<W>>(
    ly: usize,
    a: &mut Vec<LigeroLinearConstraint<W, F>>,
    b: &mut Vec<ElementOf<F>>,
    claims_state: &mut ClaimsState<W, F>,
    pad: &crate::circuit_pad::LayerPad,
    clr: &core_proto::circuit::Layer<F>,
    plr: &runtime_sumcheck::proof::LayerProof<W, F>,
    aux: Option<&SumcheckProofAux<W, F>>,
    constants: &[ElementOf<F>],
    lagrange_basis: &runtime_sumcheck::LagrangeBasis<3, W, F>,
    transcript: &mut Transcript,
    f: &F,
) {
    let (alpha, beta) = transcript.begin_layer(f);

    let mut lchal_hc = [
        Vec::with_capacity(clr.logw()),
        Vec::with_capacity(clr.logw()),
    ];

    let mut claim = Expression::zero(f);
    claim.axpy(&claims_state.claim[0], &f.one(), f);
    claim.axpy(&claims_state.claim[1], &alpha, f);

    for round in 0..clr.logw() {
        for (hand, lchal_slot) in lchal_hc.iter_mut().enumerate() {
            let hp = &plr.hp[hand][round];
            let round_pad = &pad.rounds[round].hp[hand];
            let (next_claim, challenge_val) =
                symbolic_sumcheck_round(claim, round_pad, hp, lagrange_basis, transcript, f);
            claim = next_claim;
            lchal_slot.push(challenge_val);
        }
    }

    let bound_quad = match aux {
        Some(aux_data) => aux_data.bound_quad[ly].clone(),
        None => bind_quad(clr, constants, claims_state, &alpha, &beta, &lchal_hc, f),
    };

    let term0 = f.mulf(&bound_quad, &plr.claims[1]);
    let term1 = f.mulf(&bound_quad, &plr.claims[0]);
    let const_prod = f.mulf(&plr.claims[0], &plr.claims[1]);
    let const_term = f.mulf(&bound_quad, &const_prod);

    claim.sub_scalar(&const_term, f);
    claim.add_var(pad.claims.c0, f.neg(&term0), f);
    claim.add_var(pad.claims.c1, f.neg(&term1), f);
    claim.add_var(pad.claims.cr, f.neg(&bound_quad), f);

    claim.constrain_to_be_zero(a, b, f);

    transcript.end_layer(&plr.claims, f);

    let mut next_claim0 = Expression::var(pad.claims.c0, f);
    next_claim0.add_scalar(&plr.claims[0], f);

    let mut next_claim1 = Expression::var(pad.claims.c1, f);
    next_claim1.add_scalar(&plr.claims[1], f);

    *claims_state = ClaimsState {
        logv: clr.logw(),
        nv: clr.nw(),
        claim: [next_claim0, next_claim1],
        hc: lchal_hc,
    };
}

#[allow(clippy::too_many_arguments)]
fn input_constraint<const W: usize, F: ZkField<W>>(
    a: &mut Vec<LigeroLinearConstraint<W, F>>,
    b: &mut Vec<ElementOf<F>>,
    num_public_inputs: usize,
    num_inputs: usize,
    pub_inputs: &[ElementOf<F>],
    claims_state: &ClaimsState<W, F>,
    got_expr: Expression<W, F>,
    alpha: ElementOf<F>,
    f: &F,
) {
    let eq = runtime_sumcheck::eq::eq2(
        claims_state.logv,
        num_inputs,
        &claims_state.hc[0],
        &claims_state.hc[1],
        &alpha,
        f,
    );

    let pub_binding = runtime_algebra::blas::dot(
        &eq[..num_public_inputs],
        &pub_inputs[..num_public_inputs],
        f,
    );

    let c = b.len();

    let const_val = f.subf(&pub_binding, &got_expr.known);
    b.push(const_val);

    let num_non_pub = num_inputs - num_public_inputs;
    a.reserve(num_non_pub + got_expr.symbolic.len());

    for w in 0..num_non_pub {
        let b_i = &eq[num_public_inputs + w];
        if *b_i != f.zero() {
            a.push(LigeroLinearConstraint {
                c,
                w,
                k: b_i.clone(),
            });
        }
    }

    let base = got_expr.base_idx;
    for (i, coeff) in got_expr.symbolic.iter().enumerate() {
        if *coeff != f.zero() {
            a.push(LigeroLinearConstraint {
                c,
                w: base + i,
                k: f.neg(coeff),
            });
        }
    }
}

pub fn symbolic_sumcheck_verifier_core<const W: usize, F: ZkField<W>>(
    mut pad_index: usize,
    pub_inputs: &[ElementOf<F>],
    circuit: &Circuit<F>,
    proof: &SumcheckProof<W, F>,
    aux: Option<&SumcheckProofAux<W, F>>,
    transcript: &mut Transcript,
    f: &F,
) -> (Vec<LigeroLinearConstraint<W, F>>, Vec<ElementOf<F>>) {
    let mut a = Vec::new();
    let mut b = Vec::new();

    let num_inputs = circuit.raw.ninput;
    let num_public_inputs = circuit.raw.npublic_input;

    assert!(
        num_inputs >= num_public_inputs,
        "npublic_input ({}) exceeds ninput ({})",
        num_public_inputs,
        num_inputs
    );
    assert!(
        pub_inputs.len() >= num_public_inputs,
        "public_inputs length too short: expected at least npublic_input ({}) entries, got {}",
        num_public_inputs,
        pub_inputs.len()
    );

    let logv_output = circuit.raw.logv;
    let (_cc, hc) = transcript.begin_circuit(f);
    let hc_init = hc;

    let mut claims_state = ClaimsState {
        logv: logv_output,
        nv: circuit.raw.noutput,
        claim: [Expression::zero(f), Expression::zero(f)],
        hc: [hc_init.clone(), hc_init],
    };

    let logw_layers: Vec<usize> = circuit.raw.layers.iter().map(|l| l.logw()).collect();
    let circuit_pad =
        crate::circuit_pad::CircuitPad::generate_indices(&logw_layers, &mut pad_index);
    let lagrange_basis = runtime_sumcheck::LagrangeBasis::<3, W, F>::new(f);

    for ly in 0..circuit.raw.layers.len() {
        verify_layer(
            ly,
            &mut a,
            &mut b,
            &mut claims_state,
            &circuit_pad.layers[ly],
            &circuit.raw.layers[ly],
            &proof.layers[ly],
            aux,
            &circuit.raw.constants,
            &lagrange_basis,
            transcript,
            f,
        );
    }

    let alpha = transcript.elt_field(f);
    let mut got = claims_state.claim[0].clone();
    got.axpy(&claims_state.claim[1], &alpha, f);

    input_constraint(
        &mut a,
        &mut b,
        num_public_inputs,
        num_inputs,
        pub_inputs,
        &claims_state,
        got,
        alpha,
        f,
    );

    (a, b)
}

fn bind_quad<const W: usize, F: ZkField<W>>(
    clr: &core_proto::circuit::Layer<F>,
    constants: &[ElementOf<F>],
    claims: &ClaimsState<W, F>,
    alpha: &ElementOf<F>,
    beta: &ElementOf<F>,
    hc: &[Vec<ElementOf<F>>; 2],
    f: &F,
) -> ElementOf<F> {
    let mut equad = runtime_sumcheck::hquad::HQuad::bind_g(
        clr,
        constants,
        claims.logv,
        claims.nv,
        &claims.hc[0],
        &claims.hc[1],
        alpha,
        beta,
        f,
    );

    for (lc0, lc1) in hc[0].iter().zip(&hc[1]).take(clr.logw()) {
        equad.bind_h(lc0, 0, f);
        equad.bind_h(lc1, 1, f);
    }

    equad.scalar()
}
