#![allow(clippy::needless_range_loop)]

use crate::algebra::{Field, Subfield, lagrange_matrix};

#[derive(Clone, Debug)]
pub struct ReedSolomonCode<F> {
    pub k: usize,
    pub n: usize,
    pub lagrange_matrix: Vec<F>,
}

impl<F: Field + 'static> ReedSolomonCode<F> {
    pub fn new(k: usize, n: usize, sf: &F::Subfield) -> Self {
        let pts: Vec<F> = (0..n).map(|x| sf.reed_solomon_eval_point(x)).collect();
        let l = lagrange_matrix(&pts, k, n);
        Self {
            k,
            n,
            lagrange_matrix: l,
        }
    }

    pub fn encode_row(&self) -> impl Fn(&[F]) -> Vec<F> + '_ {
        move |row: &[F]| {
            assert_eq!(row.len(), self.k, "Row length mismatch");
            let mut encoded = Vec::with_capacity(self.n);
            for x in 0..self.n {
                let mut sum = F::zero();
                for i in 0..self.k {
                    sum += row[i] * self.lagrange_matrix[i * self.n + x];
                }
                encoded.push(sum);
            }
            encoded
        }
    }
}
