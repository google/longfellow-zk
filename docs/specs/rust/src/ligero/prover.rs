#![allow(clippy::needless_range_loop)]

use super::{
    LigeroConfig, LigeroGeometry, LigeroProof, LigeroTerm, LqcTriple, ReedSolomonCode, gen_alphal,
    gen_alphaq, gen_uldt, gen_uquad,
};
use crate::{
    algebra::{Field, Rng, Subfield, axpy, dot1, vaxpy},
    merkle::{MerkleHeap, commit_merkle_heap, open_merkle_heap},
    transcript::Transcript,
};

pub struct LigeroCommitResult<F> {
    pub geometry: LigeroGeometry,
    pub tableau: Vec<Vec<F>>,
    pub merkle: MerkleHeap,
    pub nonces: Vec<Vec<u8>>,
}

pub struct LigeroProver<F: Field + 'static> {
    pub config: LigeroConfig,
    pub geometry: LigeroGeometry,
    pub rs_block: ReedSolomonCode<F>,
    pub rs_dblock: ReedSolomonCode<F>,
    pub subfield: F::Subfield,
}

impl<F: Field + 'static> LigeroProver<F> {
    pub fn new(config: LigeroConfig, nw: usize, nq: usize, subfield: F::Subfield) -> Self {
        let geometry = LigeroGeometry::new(&config, nw, nq);
        let rs_block = ReedSolomonCode::new(geometry.block_len, geometry.encoded_len, &subfield);
        let rs_dblock = ReedSolomonCode::new(geometry.dblock_len, geometry.encoded_len, &subfield);

        Self {
            config,
            geometry,
            rs_block,
            rs_dblock,
            subfield,
        }
    }

    fn layout_ildt_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let row = (0..self.geometry.block_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        self.rs_block.encode_row()(&row)
    }

    fn layout_idot_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let geom = self.geometry;
        let mut row = (0..geom.dblock_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        let sum_w1 = dot1(&row[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]);
        row[geom.num_queries] -= sum_w1;
        self.rs_dblock.encode_row()(&row)
    }

    fn layout_iquad_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let geom = self.geometry;
        let mut row = (0..geom.dblock_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        for j in 0..geom.witnesses_per_row {
            row[geom.num_queries + j] = F::zero();
        }
        self.rs_dblock.encode_row()(&row)
    }

    fn layout_witness_rows<R: Rng>(
        &self,
        witness: &[F],
        subfield_boundary: usize,
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let geom = self.geometry;
        let nw = witness.len();
        let mut witness_rows = Vec::new();

        for i in 0..geom.num_witness_rows {
            let subfield_only = (i + 1) * geom.witnesses_per_row <= subfield_boundary;
            let mut row_raw = vec![F::zero(); geom.block_len];
            for k in 0..geom.num_queries {
                row_raw[k] = if subfield_only {
                    self.subfield.sample(rng)
                } else {
                    F::sample(rng)
                };
            }
            let start = i * geom.witnesses_per_row;
            if start < nw {
                let max_col = std::cmp::min(geom.witnesses_per_row, nw - start);
                row_raw[geom.num_queries..(geom.num_queries + max_col)]
                    .copy_from_slice(&witness[start..(start + max_col)]);
            }
            witness_rows.push(self.rs_block.encode_row()(&row_raw));
        }

        witness_rows
    }

    fn sample_random_prefix_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let geom = self.geometry;
        let mut row = vec![F::zero(); geom.block_len];
        for k in 0..geom.num_queries {
            row[k] = F::sample(rng);
        }
        row
    }

    fn layout_quadratic_constraint_rows<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let geom = self.geometry;
        let nq = lqc.len();

        let mut tableau = Vec::new();
        let mut x_rows = Vec::new();
        let mut y_rows = Vec::new();
        let mut z_rows = Vec::new();
        for i in 0..geom.num_quad_rows {
            let mut row_x = self.sample_random_prefix_row(rng);
            let mut row_y = self.sample_random_prefix_row(rng);
            let mut row_z = self.sample_random_prefix_row(rng);
            let start = i * geom.witnesses_per_row;
            if start < nq {
                let max_j = std::cmp::min(geom.witnesses_per_row, nq - start);
                for j in 0..max_j {
                    let c = lqc[start + j];
                    row_x[geom.num_queries + j] = witness[c.x];
                    row_y[geom.num_queries + j] = witness[c.y];
                    row_z[geom.num_queries + j] = witness[c.z];
                }
            }
            x_rows.push(self.rs_block.encode_row()(&row_x));
            y_rows.push(self.rs_block.encode_row()(&row_y));
            z_rows.push(self.rs_block.encode_row()(&row_z));
        }

        tableau.extend(x_rows);
        tableau.extend(y_rows);
        tableau.extend(z_rows);
        tableau
    }

    fn layout_tableau<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        subfield_boundary: usize,
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let mut tableau = Vec::new();

        // 1. Row 0 (ILDT)
        tableau.push(self.layout_ildt_row(rng));

        // 2. Row 1 (IDOT)
        tableau.push(self.layout_idot_row(rng));

        // 3. Row 2 (IQUAD)
        tableau.push(self.layout_iquad_row(rng));

        // 4. Witness Rows
        tableau.extend(self.layout_witness_rows(witness, subfield_boundary, rng));

        // 5. Quadratic Constraint Rows
        tableau.extend(self.layout_quadratic_constraint_rows(witness, lqc, rng));

        tableau
    }

    pub fn commit<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        rng: &mut R,
        subfield_boundary: usize,
    ) -> LigeroCommitResult<F> {
        assert_eq!(
            witness.len(),
            self.geometry.num_witnesses,
            "Witness length {} does not match Ligero geometry num_witnesses {}",
            witness.len(),
            self.geometry.num_witnesses
        );
        for (i, triple) in lqc.iter().enumerate() {
            assert!(
                triple.x < witness.len() && triple.y < witness.len(),
                "LQC triple {} index out of bounds: x={}, y={}, nw={}",
                i,
                triple.x,
                triple.y,
                witness.len()
            );
        }

        let tableau = self.layout_tableau(witness, lqc, subfield_boundary, rng);

        // Committing columns
        let geom = self.geometry;
        let dblock = geom.dblock_len;
        let block_enc = geom.encoded_len;

        let num_committed_cols = block_enc - dblock;
        let update_leaf_hash = |j: usize| {
            let col_idx = j + dblock;
            let mut data = Vec::new();
            for row in 0..tableau.len() {
                data.extend_from_slice(&tableau[row][col_idx].to_bytes());
            }
            data
        };

        let (heap, nonces) = commit_merkle_heap(num_committed_cols, update_leaf_hash, rng);

        LigeroCommitResult {
            geometry: geom,
            tableau,
            merkle: heap,
            nonces,
        }
    }

    fn prove_compute_y_ldt(&self, commit: &LigeroCommitResult<F>, u_ldt: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let mut y_ldt = commit.tableau[geom.ldt_row_idx()][0..geom.block_len].to_vec();
        for i in 0..nwqrow {
            axpy(
                &mut y_ldt,
                &commit.tableau[geom.witness_row_start() + i][0..geom.block_len],
                u_ldt[i],
            );
        }
        y_ldt
    }

    fn prove_compute_a_full(
        &self,
        lqc: &[LqcTriple],
        a: &[LigeroTerm<F>],
        alphal: &[F],
        alphaq: &[Vec<F>],
    ) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let nq = lqc.len();

        let mut a_full = vec![F::zero(); nwqrow * geom.witnesses_per_row];
        for term in a {
            a_full[term.witness_idx] += term.coeff * alphal[term.constraint_idx];
        }

        let nqtriples_w = geom.num_quad_rows * geom.witnesses_per_row;
        let ax_offset = (nwqrow - 3 * geom.num_quad_rows) * geom.witnesses_per_row;
        let ay_offset = ax_offset + nqtriples_w;
        let az_offset = ay_offset + nqtriples_w;

        for i in 0..geom.num_quad_rows {
            let mut j = 0;
            while j < geom.witnesses_per_row && j + i * geom.witnesses_per_row < nq {
                let idx = j + i * geom.witnesses_per_row;
                let l = lqc[idx];
                a_full[ax_offset + idx] += alphaq[idx][0];
                a_full[l.x] -= alphaq[idx][0];
                a_full[ay_offset + idx] += alphaq[idx][1];
                a_full[l.y] -= alphaq[idx][1];
                a_full[az_offset + idx] += alphaq[idx][2];
                a_full[l.z] -= alphaq[idx][2];
                j += 1;
            }
        }
        a_full
    }

    fn prove_compute_y_dot(&self, commit: &LigeroCommitResult<F>, a_full: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let mut y_dot = commit.tableau[geom.linear_row_idx()][0..geom.dblock_len].to_vec();
        for i in 0..nwqrow {
            let mut a_ext = vec![F::zero(); geom.block_len];
            let start = i * geom.witnesses_per_row;
            a_ext[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]
                .copy_from_slice(&a_full[start..(start + geom.witnesses_per_row)]);
            let a_evals = self.rs_block.encode_row()(&a_ext);
            vaxpy(
                &mut y_dot,
                &commit.tableau[geom.witness_row_start() + i][0..geom.dblock_len],
                &a_evals[0..geom.dblock_len],
            );
        }
        y_dot
    }

    fn prove_compute_y_quad(&self, commit: &LigeroCommitResult<F>, u_quad: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let mut y_quad = commit.tableau[geom.quad_row_idx()][0..geom.dblock_len].to_vec();
        for i in 0..geom.num_quad_rows {
            let mut tmp = commit.tableau[geom.quad_z_row_start() + i][0..geom.dblock_len].to_vec();
            for j in 0..geom.dblock_len {
                tmp[j] -= commit.tableau[geom.quad_x_row_start() + i][j]
                    * commit.tableau[geom.quad_y_row_start() + i][j];
            }
            axpy(&mut y_quad, &tmp, u_quad[i]);
        }
        y_quad
    }

    // Note that this implementation proves that A w + b = 0 instead
    // of A w = b.  This form is marginally more convenient for
    // generating constraints in the symbolic sumcheck verifier.
    pub fn prove(
        &self,
        commit: &LigeroCommitResult<F>,
        lqc: &[LqcTriple],
        a: &[LigeroTerm<F>],
        b: &[F],
        statement_hash: &[u8],
        ts: &mut Transcript,
    ) -> LigeroProof<F> {
        ts.write_bytes(statement_hash);

        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let nq = lqc.len();

        let u_ldt = gen_uldt(ts, nwqrow);
        let alphal = gen_alphal(ts, b.len());
        let alphaq = gen_alphaq(ts, nq);
        let u_quad = gen_uquad(ts, geom.num_quad_rows);

        let y_ldt = self.prove_compute_y_ldt(commit, &u_ldt);
        let a_full = self.prove_compute_a_full(lqc, a, &alphal, &alphaq);
        let y_dot = self.prove_compute_y_dot(commit, &a_full);
        let y_quad = self.prove_compute_y_quad(commit, &u_quad);

        let y_quad_0 = y_quad[0..geom.num_queries].to_vec();
        let y_quad_2 = y_quad[geom.block_len..geom.dblock_len].to_vec();

        ts.write_elt_field_slice(&y_ldt);
        ts.write_elt_field_slice(&y_dot);
        ts.write_elt_field_slice(&y_quad_0);
        ts.write_elt_field_slice(&y_quad_2);

        let idx = ts.choose(geom.encoded_len - geom.dblock_len, geom.num_queries);
        let mut query_nonces = Vec::with_capacity(geom.num_queries);
        for &col in &idx {
            query_nonces.push(commit.nonces[col].clone());
        }
        let merkle_paths =
            open_merkle_heap(&commit.merkle, &idx).expect("Failed to open Merkle heap");

        let mut req = Vec::new();
        for row in 0..commit.tableau.len() {
            for &col in &idx {
                let col_idx = col + geom.dblock_len;
                req.push(commit.tableau[row][col_idx]);
            }
        }

        LigeroProof {
            ldt_poly: y_ldt,
            linear_poly: y_dot,
            quad_poly_low: y_quad_0,
            quad_poly_high: y_quad_2,
            column_nonces: query_nonces,
            queried_columns: req,
            merkle_paths,
        }
    }
}
