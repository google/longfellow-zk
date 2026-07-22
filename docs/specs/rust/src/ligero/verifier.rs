#![allow(clippy::needless_range_loop)]

use std::fmt;

use super::{
    LigeroConfig, LigeroGeometry, LigeroProof, LigeroTerm, LqcTriple, ReedSolomonCode, gen_alphal,
    gen_alphaq, gen_uldt, gen_uquad,
};
use crate::{
    algebra::{Field, axpy, dot, dot1, vaxpy},
    merkle::{sha256_bytes, verify_merkle_proof},
    transcript::Transcript,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidQueriedColumnsLength { expected: usize, actual: usize },
    InvalidProofPolynomialsLength,
    MerkleProofInvalid,
    LowDegreeTestFailed,
    LinearConstraintFailed,
    LinearConstraintSumMismatch,
    QuadraticConstraintFailed,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueriedColumnsLength { expected, actual } => {
                write!(
                    f,
                    "Invalid queried columns length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidProofPolynomialsLength => write!(f, "Invalid proof polynomials length"),
            Self::MerkleProofInvalid => write!(f, "Merkle proof verification failed"),
            Self::LowDegreeTestFailed => write!(f, "Low-degree test verification failed"),
            Self::LinearConstraintFailed => write!(f, "Linear constraint evaluation failed"),
            Self::LinearConstraintSumMismatch => write!(f, "Linear constraint sumcheck failed"),
            Self::QuadraticConstraintFailed => write!(f, "Quadratic constraint evaluation failed"),
        }
    }
}

impl std::error::Error for VerificationError {}

pub struct LigeroVerifier<F: Field + 'static> {
    pub config: LigeroConfig,
    pub subfield: F::Subfield,
}

impl<F: Field + 'static> LigeroVerifier<F> {
    pub fn new(config: LigeroConfig, subfield: F::Subfield) -> Self {
        Self { config, subfield }
    }

    fn interpolate_req_columns(
        &self,
        geom: &LigeroGeometry,
        k: usize,
        y: &[F],
        idx: &[usize],
    ) -> Vec<F> {
        let rs = ReedSolomonCode::new(k, geom.encoded_len, &self.subfield);
        let y_ext = rs.encode_row()(y);
        idx.iter()
            .map(|&col| y_ext[geom.dblock_len + col])
            .collect()
    }

    fn verify_merkle(
        &self,
        geom: &LigeroGeometry,
        root: &[u8; 32],
        proof: &LigeroProof<F>,
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let leaf_hash_fn = |col: usize| {
            let mut r_idx = 0;
            for i in 0..idx.len() {
                if idx[i] == col {
                    r_idx = i;
                    break;
                }
            }
            let mut data = Vec::new();
            data.extend_from_slice(&proof.column_nonces[r_idx]);
            for row in 0..geom.total_rows {
                data.extend_from_slice(
                    &proof.queried_columns[row * geom.num_queries + r_idx].to_bytes(),
                );
            }
            sha256_bytes(&data)
        };

        verify_merkle_proof(
            geom.encoded_len - geom.dblock_len,
            root,
            idx,
            &proof.merkle_paths,
            leaf_hash_fn,
        )
        .map_err(|_| VerificationError::MerkleProofInvalid)
    }

    fn verify_ldt(
        &self,
        geom: &LigeroGeometry,
        proof: &LigeroProof<F>,
        u_ldt: &[F],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let nwqrow = geom.total_rows - 3;
        let ildt = geom.ldt_row_idx();
        let iw = geom.witness_row_start();

        let mut yc_ldt =
            proof.queried_columns[ildt * geom.num_queries..(ildt + 1) * geom.num_queries].to_vec();
        for i in 0..nwqrow {
            let row_req = &proof.queried_columns
                [(iw + i) * geom.num_queries..(iw + i + 1) * geom.num_queries];
            axpy(&mut yc_ldt, row_req, u_ldt[i]);
        }
        let yp_ldt = self.interpolate_req_columns(geom, geom.block_len, &proof.ldt_poly, idx);
        if yc_ldt == yp_ldt {
            Ok(())
        } else {
            Err(VerificationError::LowDegreeTestFailed)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_dot(
        &self,
        geom: &LigeroGeometry,
        b: &[F],
        proof: &LigeroProof<F>,
        a: &[LigeroTerm<F>],
        lqc: &[LqcTriple],
        alphal: &[F],
        alphaq: &[Vec<F>],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let nwqrow = geom.total_rows - 3;
        let idot = geom.linear_row_idx();
        let iw = geom.witness_row_start();

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
            while j < geom.witnesses_per_row && j + i * geom.witnesses_per_row < lqc.len() {
                let idx_lqc = j + i * geom.witnesses_per_row;
                let l = lqc[idx_lqc];
                a_full[ax_offset + idx_lqc] += alphaq[idx_lqc][0];
                a_full[l.x] -= alphaq[idx_lqc][0];
                a_full[ay_offset + idx_lqc] += alphaq[idx_lqc][1];
                a_full[l.y] -= alphaq[idx_lqc][1];
                a_full[az_offset + idx_lqc] += alphaq[idx_lqc][2];
                a_full[l.z] -= alphaq[idx_lqc][2];
                j += 1;
            }
        }

        let mut yc_dot =
            proof.queried_columns[idot * geom.num_queries..(idot + 1) * geom.num_queries].to_vec();
        let a_interp = ReedSolomonCode::new(geom.block_len, geom.encoded_len, &self.subfield);
        for i in 0..nwqrow {
            let mut a_ext = vec![F::zero(); geom.block_len];
            let start = i * geom.witnesses_per_row;
            a_ext[geom.num_queries..geom.block_len]
                .copy_from_slice(&a_full[start..(start + geom.witnesses_per_row)]);
            let a_evals = a_interp.encode_row()(&a_ext);
            let mut a_queried = Vec::with_capacity(geom.num_queries);
            for &col in idx {
                a_queried.push(a_evals[geom.dblock_len + col]);
            }
            let row_req = &proof.queried_columns
                [(iw + i) * geom.num_queries..(iw + i + 1) * geom.num_queries];
            vaxpy(&mut yc_dot, row_req, &a_queried);
        }
        let yp_dot = self.interpolate_req_columns(geom, geom.dblock_len, &proof.linear_poly, idx);
        if yc_dot != yp_dot {
            return Err(VerificationError::LinearConstraintFailed);
        }

        let want_dot = dot(b, alphal);
        let proof_dot =
            dot1(&proof.linear_poly[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]);
        if proof_dot + want_dot != F::zero() {
            return Err(VerificationError::LinearConstraintSumMismatch);
        }

        Ok(())
    }

    fn verify_quad(
        &self,
        geom: &LigeroGeometry,
        proof: &LigeroProof<F>,
        u_quad: &[F],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let iquad = geom.quad_row_idx();
        let iqx = geom.quad_x_row_start();
        let iqy = geom.quad_y_row_start();
        let iqz = geom.quad_z_row_start();

        let mut yc_quad = proof.queried_columns
            [iquad * geom.num_queries..(iquad + 1) * geom.num_queries]
            .to_vec();
        for i in 0..geom.num_quad_rows {
            let u = u_quad[i];
            let mut tmp = vec![F::zero(); geom.num_queries];
            for j in 0..geom.num_queries {
                let x_val = proof.queried_columns[(iqx + i) * geom.num_queries + j];
                let y_val = proof.queried_columns[(iqy + i) * geom.num_queries + j];
                let z_val = proof.queried_columns[(iqz + i) * geom.num_queries + j];
                tmp[j] = z_val - x_val * y_val;
            }
            axpy(&mut yc_quad, &tmp, u);
        }
        let mut y_quad = proof.quad_poly_low.clone();
        y_quad.resize(geom.block_len, F::zero());
        y_quad.extend_from_slice(&proof.quad_poly_high);
        let yp_quad = self.interpolate_req_columns(geom, geom.dblock_len, &y_quad, idx);
        if yc_quad != yp_quad {
            return Err(VerificationError::QuadraticConstraintFailed);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        nw: usize,
        b: &[F],
        root: &[u8; 32],
        proof: &LigeroProof<F>,
        a: &[LigeroTerm<F>],
        statement_hash: &[u8],
        lqc: &[LqcTriple],
        ts: &mut Transcript,
    ) -> Result<(), VerificationError> {
        ts.write_bytes(statement_hash);

        let geom = LigeroGeometry::new(&self.config, nw, lqc.len());
        let expected_req_len = geom.total_rows * geom.num_queries;
        if proof.queried_columns.len() != expected_req_len {
            return Err(VerificationError::InvalidQueriedColumnsLength {
                expected: expected_req_len,
                actual: proof.queried_columns.len(),
            });
        }
        if proof.ldt_poly.len() != geom.block_len
            || proof.linear_poly.len() != geom.dblock_len
            || proof.quad_poly_low.len() != geom.num_queries
            || proof.quad_poly_high.len() != geom.dblock_len - geom.block_len
            || proof.column_nonces.len() != geom.num_queries
        {
            return Err(VerificationError::InvalidProofPolynomialsLength);
        }
        let nwqrow = geom.total_rows - 3;

        let u_ldt = gen_uldt(ts, nwqrow);
        let alphal = gen_alphal(ts, b.len());
        let alphaq = gen_alphaq(ts, lqc.len());
        let u_quad = gen_uquad(ts, geom.num_quad_rows);

        ts.write_elt_field_slice(&proof.ldt_poly);
        ts.write_elt_field_slice(&proof.linear_poly);
        ts.write_elt_field_slice(&proof.quad_poly_low);
        ts.write_elt_field_slice(&proof.quad_poly_high);

        let idx = ts.choose(geom.encoded_len - geom.dblock_len, geom.num_queries);

        self.verify_merkle(&geom, root, proof, &idx)?;
        self.verify_ldt(&geom, proof, &u_ldt, &idx)?;
        self.verify_dot(&geom, b, proof, a, lqc, &alphal, &alphaq, &idx)?;
        self.verify_quad(&geom, proof, &u_quad, &idx)?;

        Ok(())
    }
}
