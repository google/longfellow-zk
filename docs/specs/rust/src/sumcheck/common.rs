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
    algebra::Field,
    circuit::{Circuit, Term},
};

pub fn eq<F: Field>(r: &[F], x_int: usize, nbits: usize) -> F {
    let mut product = F::one();
    for b in 0..nbits {
        if ((x_int >> b) & 1) == 1 {
            product *= r[b];
        } else {
            product *= F::one() - r[b];
        }
    }
    product
}

pub fn eq2<F: Field>(x: usize, logn: usize, g0: &[F], g1: &[F], alpha: F) -> F {
    eq(g0, x, logn) + alpha * eq(g1, x, logn)
}

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitEvaluationError {
    GateMultiplicationConstraintFailed,
    CircuitOutputNotZero,
}

impl fmt::Display for CircuitEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GateMultiplicationConstraintFailed => {
                write!(f, "gate multiplication constraint not satisfied")
            }
            Self::CircuitOutputNotZero => {
                write!(f, "Circuit output is not zero")
            }
        }
    }
}

impl std::error::Error for CircuitEvaluationError {}

pub fn eval_quad<F: Field>(
    nv: usize,
    w: &[F],
    layer_quad: &[Term<F>],
) -> Result<Vec<F>, CircuitEvaluationError> {
    let mut v = vec![F::zero(); nv];
    for t in layer_quad {
        if t.k.is_zero() {
            if !(w[t.h[1]] * w[t.h[0]]).is_zero() {
                return Err(CircuitEvaluationError::GateMultiplicationConstraintFailed);
            }
        } else {
            v[t.g] += t.k * w[t.h[1]] * w[t.h[0]];
        }
    }
    Ok(v)
}

pub fn eval_circuit<F: Field>(
    w: &[F],
    circuit_data: &Circuit<F>,
) -> Result<Vec<Vec<F>>, CircuitEvaluationError> {
    let mut curr_w = w.to_vec();
    let mut in_layers = vec![Vec::new(); circuit_data.layers.len()];

    for (l, layer) in circuit_data.layers.iter().enumerate().rev() {
        in_layers[l] = curr_w.clone();
        let nv = if l > 0 {
            circuit_data.layers[l - 1].nw
        } else {
            circuit_data.noutput
        };
        curr_w = eval_quad(nv, &curr_w, &layer.quad)?;
    }
    if !curr_w.iter().all(|val| val.is_zero()) {
        return Err(CircuitEvaluationError::CircuitOutputNotZero);
    }
    Ok(in_layers)
}

pub fn bind_g<F: Field>(
    quad_terms: &mut [Term<F>],
    logv: usize,
    g0: &[F],
    g1: &[F],
    alpha: F,
    beta: F,
) {
    for term in quad_terms.iter_mut() {
        let dot_val = eq2(term.g, logv, g0, g1, alpha);
        term.k = if term.k.is_zero() {
            beta * dot_val
        } else {
            term.k * dot_val
        };
        term.g = 0;
    }
}

#[allow(clippy::too_many_arguments)]
pub fn eval_bound_quad<F: Field>(
    quad_terms: &[Term<F>],
    claims_logv: usize,
    claims_hc0: &[F],
    claims_hc1: &[F],
    lchal_hc0: &[F],
    lchal_hc1: &[F],
    logw: usize,
    alpha: F,
    beta: F,
) -> F {
    let mut eqq = F::zero();
    for term in quad_terms {
        let dot_val = eq2(term.g, claims_logv, claims_hc0, claims_hc1, alpha);
        let k_val = if term.k.is_zero() {
            beta * dot_val
        } else {
            term.k * dot_val
        };

        eqq += k_val
            * eq(&lchal_hc0[..logw], term.h[0], logw)
            * eq(&lchal_hc1[..logw], term.h[1], logw);
    }
    eqq
}

pub fn begin_circuit<F: Field + 'static>(
    t: &mut crate::transcript::Transcript,
) -> (Vec<F>, Vec<F>) {
    const MAX_LOGW: usize = 40;
    let q = (0..MAX_LOGW).map(|_| t.get_elt_field()).collect();
    let g = (0..MAX_LOGW).map(|_| t.get_elt_field()).collect();
    (q, g)
}

pub fn begin_layer<F: Field + 'static>(t: &mut crate::transcript::Transcript) -> (F, F) {
    let alpha = t.get_elt_field();
    let beta = t.get_elt_field();
    (alpha, beta)
}

pub fn end_layer<F: Field + 'static>(t: &mut crate::transcript::Transcript, claims: &[F]) {
    t.write_elt_field_slice(claims);
}

pub fn round_poly<F: Field>(t: &mut crate::transcript::Transcript, poly: &[F; 2]) -> F {
    t.write_elt_field(poly[0]);
    t.write_elt_field(poly[1]);
    t.get_elt_field()
}
