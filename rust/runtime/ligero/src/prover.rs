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
use runtime_algebra::{
    blas, Interpolator, InterpolatorFactory, RuntimeField, Subfield, SupportsSampling,
};
use runtime_merkle::{commit, open, MerkleCommitment};
use runtime_proto::LigeroProof;
use runtime_random::{RandomEngine, Transcript};
use sha2::digest::Update;

use crate::{
    common::{inner_product_vector, layout_aext_into},
    param::{LigeroCommitment, LigeroLinearConstraint, LigeroParam, LigeroQuadraticConstraint},
    tableau::Tableau,
    transcript::TranscriptLigero,
};

pub struct LigeroProver<const W: usize, F: RuntimeField<W>> {
    param: LigeroParam,
    mc: MerkleCommitment,
    tableau: Tableau<ElementOf<F>>,
}

impl<
        const W: usize,
        F: RuntimeField<W> + core_algebra::SerializableField + SupportsSampling<W>,
    > LigeroProver<W, F>
{
    /// The `subfield_boundary` parameter is kind of a hack.
    ///
    /// Most, but not all, witnesses in witness[] are known statically to be in
    /// the subfield of Field, for example because they are bits or
    /// bit-plucked values in the subfield. For zero-knowledge, for
    /// these witnesses, it suffices to choose blinding randomness in the
    /// subfield, which yields a shorter proof since most column openings
    /// are fully in the subfield. The problem is now to distinguish
    /// subfield witnesses from field witnesses.
    ///
    /// In the fullness of time we should have a compiler with typing
    /// information (field vs subfield) of all input wires. For now
    /// we implement the following hack: witness[i] is in the subfield for
    /// i < `subfield_boundary`, and in the full field otherwise.
    /// If you don't know better, set `subfield_boundary` = 0 which
    /// trivially works for any input.
    #[allow(clippy::too_many_arguments)]
    pub fn commit<
        IF: InterpolatorFactory<W, F>,
        R: RandomEngine,
        SF: Subfield<E = ElementOf<F>>,
    >(
        subfield_boundary: usize,
        witness: &[ElementOf<F>],
        param: LigeroParam,
        ts: &mut Transcript,
        quadratic_constraints: &[LigeroQuadraticConstraint],
        make_interpolator: &IF,
        rng: &mut R,
        f: &F,
        sf: &SF,
    ) -> (Self, LigeroCommitment) {
        for val in &witness[..subfield_boundary] {
            debug_assert!(sf.contains(val), "element not in subfield");
        }

        let tableau = layout(
            subfield_boundary,
            witness,
            &param,
            quadratic_constraints,
            make_interpolator,
            rng,
            f,
            sf,
        );

        let len = f.serialized_size_bytes();
        let mut update_leaf_hash = |j: usize, sha: &mut sha2::Sha256| {
            let col_idx = j + param.dblock;
            let mut buf = [0u8; 128];
            for r in 0..param.nrow {
                let val = &tableau[(r, col_idx)];
                f.to_bytes_into(val, &mut buf[..len]);
                sha.update(&buf[..len]);
            }
        };

        // Merkle commitment
        let (mc, root) = commit(param.block_enc - param.dblock, rng, &mut update_leaf_hash);
        let commitment = LigeroCommitment { root };

        // P -> V
        ts.write_commitment(&commitment);

        (Self { param, mc, tableau }, commitment)
    }

    /// Returns a reference to the `LigeroParam`.
    #[must_use]
    pub fn param(&self) -> &LigeroParam {
        &self.param
    }

    fn low_degree_proof(&self, u_ldt: &[ElementOf<F>], f: &F) -> Vec<ElementOf<F>> {
        let mut y = self.tableau.row(self.param.ildt)[..self.param.block].to_vec();
        // All witness and quadratic rows with coefficient u_ldt[]
        for (i, u) in u_ldt.iter().enumerate().take(self.param.nwqrow) {
            blas::axpy(
                &mut y,
                u,
                &self.tableau.row(i + self.param.iw)[..self.param.block],
                f,
            );
        }
        y
    }

    fn dot_proof<IF: InterpolatorFactory<W, F>>(
        &self,
        a: &[ElementOf<F>],
        make_interpolator: &IF,
        f: &F,
    ) -> Vec<ElementOf<F>> {
        let interp_a = make_interpolator.make(self.param.block, self.param.dblock);
        let mut y = self.tableau.row(self.param.idot)[..self.param.dblock].to_vec();
        let mut a_ext = vec![f.zero(); self.param.dblock];

        for i in 0..self.param.nwqrow {
            layout_aext_into(&self.param, i, a, &mut a_ext, f);
            interp_a.interpolate(&mut a_ext);

            // Accumulate y += A \otimes W.
            blas::vaxpy(
                &mut y,
                &a_ext,
                &self.tableau.row(i + self.param.iw)[..self.param.dblock],
                f,
            );
        }
        y
    }

    fn quadratic_proof(
        &self,
        u_quad: &[ElementOf<F>],
        f: &F,
    ) -> (Vec<ElementOf<F>>, Vec<ElementOf<F>>) {
        let mut y = self.tableau.row(self.param.iquad)[..self.param.dblock].to_vec();

        let iqx = self.param.iq;
        let iqy = iqx + self.param.nqtriples;
        let iqz = self.param.iq + 2 * self.param.nqtriples;

        let mut tmp = vec![f.zero(); self.param.dblock];
        for (i, _u) in u_quad.iter().enumerate().take(self.param.nqtriples) {
            // y[i] += u_quad[i] * (z[i] - x[i] * y[i])

            blas::copy(&mut tmp, &self.tableau.row(iqz + i)[..self.param.dblock]);

            // tmp[i] -= x[i] * y[i]
            blas::vymax(
                &mut tmp,
                &self.tableau.row(iqx + i)[..self.param.dblock],
                &self.tableau.row(iqy + i)[..self.param.dblock],
                f,
            );

            // y[i] += u_quad[i] * tmp[i]
            blas::axpy(&mut y, &u_quad[i], &tmp, f);
        }

        // Sanity check: the W part of Y is zero
        let ok = blas::equal0(&y[self.param.r..self.param.r + self.param.w], f);
        assert!(ok, "W part is nonzero");

        // Extract the first and last parts
        let y0 = y[..self.param.r].to_vec();
        let y2 = y[self.param.block..].to_vec();
        (y0, y2)
    }

    fn gather_opened_columns(&self, idx: &[usize]) -> Vec<ElementOf<F>> {
        let mut req = Vec::with_capacity(self.param.nrow * self.param.nreq);
        for i in 0..self.param.nrow {
            let row_req = blas::gather(idx, &self.tableau.row(i)[self.param.dblock..]);
            req.extend(row_req);
        }
        req
    }

    /// `hash_of_ligero_statement` is the binding digest of the Ligero statement.
    #[allow(clippy::too_many_arguments)]
    pub fn prove<IF: InterpolatorFactory<W, F>>(
        &self,
        linear_evals: &[ElementOf<F>],
        ts: &mut Transcript,
        linear_constraints: &[LigeroLinearConstraint<W, F>],
        hash_of_ligero_statement: &runtime_merkle::Digest,
        quadratic_constraints: &[LigeroQuadraticConstraint],
        make_interpolator: &IF,
        f: &F,
    ) -> LigeroProof<W, F> {
        // P -> V theorem statement
        ts.write_ligero_statement(hash_of_ligero_statement);

        // V -> P
        let y_ldt = self.low_degree_proof(&ts.gen_uldt(&self.param, f), f);

        // V -> P
        let nl = linear_evals.len();
        let alphal = ts.gen_alphal(nl, f);
        let alphaq = ts.gen_alphaq(&self.param, f);

        let a = inner_product_vector(
            &self.param,
            linear_constraints,
            &alphal,
            quadratic_constraints,
            &alphaq,
            f,
        );
        let y_dot = self.dot_proof(&a, make_interpolator, f);

        // V -> P
        let (y_quad_0, y_quad_2) = self.quadratic_proof(&ts.gen_uquad(&self.param, f), f);

        // P -> V
        ts.write_elt_field_slice(&y_ldt, f);
        ts.write_elt_field_slice(&y_dot, f);
        ts.write_elt_field_slice(&y_quad_0, f);
        ts.write_elt_field_slice(&y_quad_2, f);

        // V -> P
        let idx = ts.gen_idx(&self.param);

        let req = self.gather_opened_columns(&idx);

        let merkle = open(&self.mc, &idx);

        // P -> V (final message) - Omitted to match C++ behavior

        LigeroProof {
            y_ldt,
            y_dot,
            y_quad_0,
            y_quad_2,
            req,
            merkle,
        }
    }
}

// Fill tableau[i, [0,n)] with random elements.
fn random_row<const W: usize, F: SupportsSampling<W>, R: RandomEngine>(
    i: usize,
    n: usize,
    tableau: &mut Tableau<ElementOf<F>>,
    rng: &mut R,
    f: &F,
) {
    for j in 0..n {
        tableau[(i, j)] = rng.elt_field(f);
    }
}

fn random_subfield_row<SF: Subfield, R: RandomEngine>(
    i: usize,
    n: usize,
    tableau: &mut Tableau<SF::E>,
    rng: &mut R,
    sf: &SF,
) {
    for j in 0..n {
        tableau[(i, j)] = rng.elt_subfield(sf);
    }
}

fn layout_blinding_rows<
    const W: usize,
    F: SupportsSampling<W>,
    IF: InterpolatorFactory<W, F>,
    R: RandomEngine,
>(
    param: &LigeroParam,
    tableau: &mut Tableau<ElementOf<F>>,
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
) {
    // Blinds of size [BLOCK]
    let interp_block = make_interpolator.make(param.block, param.block_enc);

    // Low-degree blinding row
    random_row(param.ildt, param.block, tableau, rng, f);

    interp_block.interpolate(tableau.row_mut(param.ildt));

    // Blinds of size [DBLOCK]
    let interp_dblock = make_interpolator.make(param.dblock, param.block_enc);

    // Dot-product blinding row constrained to SUM(W) = 0. First
    // randomize the dblock:
    random_row(param.idot, param.dblock, tableau, rng, f);

    // Then constrain to sum(W) = 0
    let (idot, r, w) = (param.idot, param.r, param.w);
    let sum = blas::dot1(&tableau.row(idot)[r..r + w], f);
    f.sub(&mut tableau[(idot, r)], &sum);

    interp_dblock.interpolate(tableau.row_mut(idot));

    // Quadratic-test blinding row constrained to W = 0. First randomize
    // the entire dblock:
    random_row(param.iquad, param.dblock, tableau, rng, f);

    // Then constrain to W = 0
    blas::clear(&mut tableau.row_mut(param.iquad)[r..r + w], f);

    interp_dblock.interpolate(tableau.row_mut(param.iquad));
}

#[allow(clippy::too_many_arguments)]
fn layout_witness_rows<
    const W: usize,
    F: SupportsSampling<W>,
    IF: InterpolatorFactory<W, F>,
    R: RandomEngine,
    SF: Subfield<E = ElementOf<F>>,
>(
    subfield_boundary: usize,
    witness: &[ElementOf<F>],
    param: &LigeroParam,
    tableau: &mut Tableau<ElementOf<F>>,
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
    sf: &SF,
) {
    let interp = make_interpolator.make(param.block, param.block_enc);
    let (r, w, iw, nw) = (param.r, param.w, param.iw, param.nw);
    // Witness row EXTEND([RANDOM[R], WITNESS[W]], BLOCK)
    for i in 0..param.nwrow {
        // TRUE if the entire row is in the subfield
        let subfield_only = (i + 1) * w <= subfield_boundary;

        let row_idx = i + iw;
        if subfield_only {
            random_subfield_row(row_idx, r, tableau, rng, sf);
        } else {
            random_row(row_idx, r, tableau, rng, f);
        }

        let max_col = std::cmp::min(w, nw - i * w);
        let row_slice = &mut tableau.row_mut(row_idx)[r..r + w];
        blas::copy(&mut row_slice[..max_col], &witness[i * w..i * w + max_col]);
        if max_col < w {
            blas::clear(&mut row_slice[max_col..w], f);
        }
        interp.interpolate(tableau.row_mut(row_idx));
    }
}

fn layout_quadratic_rows<
    const W: usize,
    F: SupportsSampling<W>,
    IF: InterpolatorFactory<W, F>,
    R: RandomEngine,
>(
    witness: &[ElementOf<F>],
    param: &LigeroParam,
    tableau: &mut Tableau<ElementOf<F>>,
    quadratic_constraints: &[LigeroQuadraticConstraint],
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
) {
    let interp = make_interpolator.make(param.block, param.block_enc);
    let iqx = param.iq;
    let iqy = iqx + param.nqtriples;
    let iqz = param.iq + 2 * param.nqtriples;
    let (r, w, nq) = (param.r, param.w, param.nq);

    for i in 0..param.nqtriples {
        random_row(iqx + i, r, tableau, rng, f);
        random_row(iqy + i, r, tableau, rng, f);
        random_row(iqz + i, r, tableau, rng, f);

        let max_j = std::cmp::min(w, nq.saturating_sub(i * w));

        for j in 0..max_j {
            let l = &quadratic_constraints[j + i * w];
            debug_assert_eq!(
                witness[l.z],
                f.mulf(&witness[l.x], &witness[l.y]),
                "invalid quadratic constraints"
            );
            tableau[(iqx + i, j + r)] = witness[l.x].clone();
            tableau[(iqy + i, j + r)] = witness[l.y].clone();
            tableau[(iqz + i, j + r)] = witness[l.z].clone();
        }

        if max_j < w {
            blas::clear(&mut tableau.row_mut(iqx + i)[r + max_j..r + w], f);
            blas::clear(&mut tableau.row_mut(iqy + i)[r + max_j..r + w], f);
            blas::clear(&mut tableau.row_mut(iqz + i)[r + max_j..r + w], f);
        }
        interp.interpolate(tableau.row_mut(iqx + i));
        interp.interpolate(tableau.row_mut(iqy + i));
        interp.interpolate(tableau.row_mut(iqz + i));
    }
}

#[allow(clippy::too_many_arguments)]
fn layout<
    const W: usize,
    F: SupportsSampling<W>,
    IF: InterpolatorFactory<W, F>,
    R: RandomEngine,
    SF: Subfield<E = ElementOf<F>>,
>(
    subfield_boundary: usize,
    witness: &[ElementOf<F>],
    param: &LigeroParam,
    quadratic_constraints: &[LigeroQuadraticConstraint],
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
    sf: &SF,
) -> Tableau<ElementOf<F>> {
    let mut tableau = Tableau::new(param.nrow, param.block_enc, f.zero());
    layout_blinding_rows(param, &mut tableau, make_interpolator, rng, f);
    layout_witness_rows(
        subfield_boundary,
        witness,
        param,
        &mut tableau,
        make_interpolator,
        rng,
        f,
        sf,
    );
    layout_quadratic_rows(
        witness,
        param,
        &mut tableau,
        quadratic_constraints,
        make_interpolator,
        rng,
        f,
    );
    tableau
}
