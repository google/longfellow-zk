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
use runtime_algebra::{blas, Interpolator, InterpolatorFactory, RuntimeField, SupportsSampling};
use runtime_proto::LigeroProof;
use runtime_random::Transcript;
use sha2::digest::Update;

use crate::{
    common::{inner_product_vector, layout_aext_into},
    param::{LigeroCommitment, LigeroLinearConstraint, LigeroParam, LigeroQuadraticConstraint},
    transcript::TranscriptLigero,
    LigeroError,
};

pub struct LigeroVerifier<'a> {
    ts: &'a mut Transcript,
    param: &'a LigeroParam,
}

impl<'a> LigeroVerifier<'a> {
    pub fn new(ts: &'a mut Transcript, param: &'a LigeroParam) -> Self {
        Self { ts, param }
    }

    /// Replays commitment transmission from P to V.
    pub fn receive_commitment(&mut self, commitment: &LigeroCommitment) {
        // P -> V
        self.ts.write_commitment(commitment);
    }

    /// Main verification algorithm for Ligero arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn verify<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SerializableField + SupportsSampling<W>,
        IF: InterpolatorFactory<W, F>,
    >(
        &mut self,
        linear_evals: &[ElementOf<F>],
        commitment: &LigeroCommitment,
        proof: &LigeroProof<W, F>,
        linear_constraints: &[LigeroLinearConstraint<W, F>],
        hash_of_ligero_statement: &runtime_merkle::Digest,
        quadratic_constraints: &[LigeroQuadraticConstraint],
        make_interpolator: &IF,
        f: &F,
    ) -> Result<(), LigeroError> {
        if proof.y_ldt.len() != self.param.block {
            return Err(LigeroError::InvalidProof(
                "invalid y_ldt length".to_string(),
            ));
        }
        if proof.y_dot.len() != self.param.dblock {
            return Err(LigeroError::InvalidProof(
                "invalid y_dot length".to_string(),
            ));
        }
        if proof.y_quad_0.len() != self.param.r {
            return Err(LigeroError::InvalidProof(
                "invalid y_quad_0 length".to_string(),
            ));
        }
        if proof.y_quad_2.len() != self.param.dblock - self.param.block {
            return Err(LigeroError::InvalidProof(
                "invalid y_quad_2 length".to_string(),
            ));
        }
        if proof.req.len() != self.param.nrow * self.param.nreq {
            return Err(LigeroError::InvalidProof("invalid req length".to_string()));
        }

        for term in linear_constraints {
            if term.w >= self.param.nw || term.c >= linear_evals.len() {
                return Err(LigeroError::InvalidProof(
                    "linear constraint index out of bounds".to_string(),
                ));
            }
        }
        if quadratic_constraints.len() < self.param.nq {
            return Err(LigeroError::InvalidProof(
                "invalid quadratic constraints length".to_string(),
            ));
        }
        for l in &quadratic_constraints[..self.param.nq] {
            if l.x >= self.param.nw || l.y >= self.param.nw || l.z >= self.param.nw {
                return Err(LigeroError::InvalidProof(
                    "quadratic constraint index out of bounds".to_string(),
                ));
            }
        }

        // Replay the protocol first in order to compute all the challenges.
        //
        // # Note on Batched Challenge Sampling & Soundness in Ligero
        // In general interactive protocols, a challenge at round `k` must depend on the prover's
        // message at round `k-1`. Here, notice that `u_ldt`, `alphal`, `alphaq`, and
        // `u_quad` are sampled *before* the folded polynomial evaluations (`y_ldt`,
        // `y_dot`, `y_quad`) are written to the transcript.
        //
        // This batched challenge sampling is cryptographically sound by design in Ligero:
        // 1. The prover commits to the entire tableau (all rows) in the initial Merkle commitment
        //    `C` (absorbed during `receive_commitment`).
        // 2. The subsequent polynomial evaluations (`y_ldt`, `y_dot`, `y_quad`) are not arbitrary
        //    new polynomials; they are strictly homomorphic linear combinations of the
        //    already-committed rows in `C`.
        // 3. Because the underlying rows are already frozen in `C`, once the random combination
        //    weights (`u_ldt`, `alphal`, `alphaq`, `u_quad`) are drawn, the true folded polynomials
        //    are mathematically fixed and unique.
        //
        // Therefore, only the final column query challenge (`idx`) needs to depend on the
        // transmitted polynomial evaluations (`y_ldt`, `y_dot`, `y_quad`). As seen below,
        // `idx` is sampled strictly after absorbing all three polynomials into the
        // transcript, ensuring that any discrepancy between the transmitted polynomials and
        // the committed tableau rows is caught during column verification.

        // P -> V theorem statement
        self.ts.write_ligero_statement(hash_of_ligero_statement);

        // V -> P
        let u_ldt = self.ts.gen_uldt(self.param, f);

        // V -> P
        let alphal = self.ts.gen_alphal(linear_evals.len(), f);
        let alphaq = self.ts.gen_alphaq(self.param, f);

        // V -> P
        let u_quad = self.ts.gen_uquad(self.param, f);

        // P -> V
        self.ts.write_elt_field_slice(&proof.y_ldt, f);
        self.ts.write_elt_field_slice(&proof.y_dot, f);
        self.ts.write_elt_field_slice(&proof.y_quad_0, f);
        self.ts.write_elt_field_slice(&proof.y_quad_2, f);

        // V -> P
        let idx = self.ts.gen_idx(self.param);

        // P -> V (final message) - Omitted to match C++ behavior

        self.merkle_check(&idx, commitment, proof, f)
            .map_err(LigeroError::MerkleCheckFailed)?;

        if !self.low_degree_check(&idx, &u_ldt, proof, make_interpolator, f) {
            return Err(LigeroError::LowDegreeCheckFailed);
        }

        // Linear check
        let a = inner_product_vector(
            self.param,
            linear_constraints,
            &alphal,
            quadratic_constraints,
            &alphaq,
            f,
        );

        if !self.dot_check(&idx, &a, proof, make_interpolator, f) {
            return Err(LigeroError::DotCheckFailed);
        }

        // Check the putative value of the inner product for linear constraint A w + b = 0.
        // proof_dot = alpha_L . (A w)
        // want_dot  = alpha_L . b
        // Requirement: proof_dot + want_dot == 0
        let want_dot = blas::dot(linear_evals, &alphal, f);
        let proof_dot = blas::dot1(&proof.y_dot[self.param.r..self.param.r + self.param.w], f);

        let mut sum = proof_dot;
        f.add(&mut sum, &want_dot);

        if sum != f.zero() {
            return Err(LigeroError::LinearInnerProductMismatch);
        }

        if !self.quadratic_check(&idx, &u_quad, proof, make_interpolator, f) {
            return Err(LigeroError::QuadraticCheckFailed);
        }

        Ok(())
    }

    fn interpolate_req_columns<
        const W: usize,
        F: RuntimeField<W>,
        IF: InterpolatorFactory<W, F>,
    >(
        &self,
        ylen: usize,
        idx: &[usize],
        y: &[F::E],
        make_interpolator: &IF,
        f: &F,
    ) -> Vec<F::E> {
        let interpy = make_interpolator.make(ylen, self.param.block_enc);
        let mut yext = y[..ylen].to_vec();
        yext.resize(self.param.block_enc, f.zero());
        interpy.interpolate(&mut yext);

        let mut yp = Vec::with_capacity(self.param.nreq);
        for &i in idx {
            yp.push(yext[self.param.dblock + i].clone());
        }
        yp
    }

    fn merkle_check<const W: usize, F: RuntimeField<W> + core_algebra::SerializableField>(
        &self,
        idx: &[usize],
        commitment: &LigeroCommitment,
        proof: &LigeroProof<W, F>,
        f: &F,
    ) -> Result<(), runtime_merkle::MerkleError> {
        let len = f.serialized_size_bytes();
        let mut updhash = |r: usize, _col_idx: usize, sha: &mut sha2::Sha256| {
            let mut buf = [0u8; 128];
            for i in 0..self.param.nrow {
                let val = &proof.req[i * self.param.nreq + r];
                f.to_bytes_into(val, &mut buf[..len]);
                sha.update(&buf[..len]);
            }
        };

        runtime_merkle::verify(
            self.param.block_enc - self.param.dblock,
            &commitment.root,
            idx,
            &proof.merkle,
            &mut updhash,
        )
    }

    fn low_degree_check<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SerializableField,
        IF: InterpolatorFactory<W, F>,
    >(
        &self,
        idx: &[usize],
        u_ldt: &[F::E],
        proof: &LigeroProof<W, F>,
        make_interpolator: &IF,
        f: &F,
    ) -> bool {
        // The ILDT blinding row with coefficient 1
        let mut yc = proof.req
            [self.param.ildt * self.param.nreq..(self.param.ildt + 1) * self.param.nreq]
            .to_vec();

        // All remaining witness and quadratic rows with coefficient u_ldt[]
        for (i, u_ldt_elt) in u_ldt.iter().enumerate().take(self.param.nwqrow) {
            blas::axpy(
                &mut yc,
                u_ldt_elt,
                &proof.req[(i + self.param.iw) * self.param.nreq
                    ..(i + self.param.iw + 1) * self.param.nreq],
                f,
            );
        }

        let yp =
            self.interpolate_req_columns(self.param.block, idx, &proof.y_ldt, make_interpolator, f);

        blas::equal(&yp, &yc)
    }

    fn dot_check<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SerializableField,
        IF: InterpolatorFactory<W, F>,
    >(
        &self,
        idx: &[usize],
        a: &[F::E],
        proof: &LigeroProof<W, F>,
        make_interpolator: &IF,
        f: &F,
    ) -> bool {
        // The IDOT blinding row with coefficient 1
        let mut yc = proof.req
            [self.param.idot * self.param.nreq..(self.param.idot + 1) * self.param.nreq]
            .to_vec();

        {
            let interp_a = make_interpolator.make(self.param.block, self.param.block_enc);
            let mut a_ext = vec![f.zero(); self.param.block_enc];
            for i in 0..self.param.nwqrow {
                layout_aext_into(self.param, i, a, &mut a_ext, f);
                interp_a.interpolate(&mut a_ext);
                let a_req = blas::gather(idx, &a_ext[self.param.dblock..]);

                // Accumulate yc += A[i] \otimes W[i].
                blas::vaxpy(
                    &mut yc,
                    &a_req,
                    &proof.req[(i + self.param.iw) * self.param.nreq
                        ..(i + self.param.iw + 1) * self.param.nreq],
                    f,
                );
            }
        }

        let yp = self.interpolate_req_columns(
            self.param.dblock,
            idx,
            &proof.y_dot,
            make_interpolator,
            f,
        );
        blas::equal(&yp, &yc)
    }

    fn quadratic_check<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SerializableField,
        IF: InterpolatorFactory<W, F>,
    >(
        &self,
        idx: &[usize],
        u_quad: &[F::E],
        proof: &LigeroProof<W, F>,
        make_interpolator: &IF,
        f: &F,
    ) -> bool {
        // The IQUAD blinding row with coefficient 1
        let mut yc = proof.req
            [self.param.iquad * self.param.nreq..(self.param.iquad + 1) * self.param.nreq]
            .to_vec();

        {
            let (iqx, iqy, iqz) = (
                self.param.iq,
                self.param.iq + self.param.nqtriples,
                self.param.iq + 2 * self.param.nqtriples,
            );

            let mut tmp = vec![f.zero(); self.param.nreq];
            // All quadratic triples with coefficient u_quad[]
            for (i, u_quad_elt) in u_quad.iter().enumerate().take(self.param.nqtriples) {
                // yc += u_quad[i] * (z[i] - x[i] * y[i])

                // tmp = z[i]
                blas::copy(
                    &mut tmp,
                    &proof.req[(iqz + i) * self.param.nreq..(iqz + i + 1) * self.param.nreq],
                );

                // tmp -= x[i] \otimes y[i]
                blas::vymax(
                    &mut tmp,
                    &proof.req[(iqx + i) * self.param.nreq..(iqx + i + 1) * self.param.nreq],
                    &proof.req[(iqy + i) * self.param.nreq..(iqy + i + 1) * self.param.nreq],
                    f,
                );

                // yc += u_quad[i] * tmp
                blas::axpy(&mut yc, u_quad_elt, &tmp, f);
            }
        }

        // Reconstruct y_quad from the two parts in the proof
        let mut yquad = proof.y_quad_0.clone();
        yquad.resize(self.param.block, f.zero());
        yquad.extend_from_slice(&proof.y_quad_2);

        // Interpolate y_quad at the opened columns
        let yp = self.interpolate_req_columns(self.param.dblock, idx, &yquad, make_interpolator, f);

        blas::equal(&yp, &yc)
    }
}
