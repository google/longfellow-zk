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

use core_algebra::{
    gf2_128::{Gf2_128, Gf2_128Field},
    AlgebraicField,
};

fn decompose(basis: &[Gf2_128; 128], x: Gf2_128) -> [bool; 128] {
    let mut matrix = vec![[false; 129]; 128];
    for (col, &b_elt) in basis.iter().enumerate() {
        for (row, m_r) in matrix.iter_mut().enumerate() {
            m_r[col] = ((b_elt.0 >> row) & 1) != 0;
        }
    }
    for (row, m_r) in matrix.iter_mut().enumerate() {
        m_r[128] = ((x.0 >> row) & 1) != 0;
    }

    let mut pivot_row = 0;
    let mut pivot_cols = vec![];
    for col in 0..128 {
        let mut found = false;
        for r in pivot_row..128 {
            if matrix[r][col] {
                matrix.swap(pivot_row, r);
                found = true;
                break;
            }
        }
        if found {
            pivot_cols.push(col);
            let pivot_row_vals = matrix[pivot_row];
            for (r, m_r) in matrix.iter_mut().enumerate() {
                if r != pivot_row && m_r[col] {
                    for (c_idx, cell) in m_r.iter_mut().enumerate().skip(col) {
                        *cell ^= pivot_row_vals[c_idx];
                    }
                }
            }
            pivot_row += 1;
        }
    }

    assert_eq!(pivot_row, 128, "Basis is not linearly independent!");

    let mut sol = [false; 128];
    for (i, &col) in pivot_cols.iter().enumerate() {
        sol[col] = matrix[i][128];
    }
    sol
}

fn trace_in_subfield(f: &Gf2_128Field, x: &Gf2_128, subfield_dim: usize) -> bool {
    let mut sum = f.zero();
    let mut val = *x;
    for _ in 0..subfield_dim {
        sum = f.addf(&sum, &val);
        val = f.mulf(&val, &val);
    }
    if sum == f.one() {
        true
    } else if sum == f.zero() {
        false
    } else {
        panic!("Trace value is not in GF(2): {sum:?}");
    }
}

#[test]
fn test_cantor_basis_properties() {
    let f = Gf2_128Field::new();
    let basis = f.cantor_basis();

    // 1. Verify linear independence of the basis.
    // Decomposing zero should give all coefficients as false.
    let zero_coeffs = decompose(basis, f.zero());
    for &coeff in &zero_coeffs {
        assert!(!coeff, "Decomposition of zero must be all zeros");
    }

    // 2. Verify Cantor basis tensor product structure and subfield trace relations.
    assert_eq!(basis[0], f.one(), "First basis element z_0 must be 1");

    for j in 1..=7 {
        let subfield_dim = 1 << (j - 1);
        let root = basis[subfield_dim];

        // w = root^2 + root
        let root_sq = f.mulf(&root, &root);
        let w = f.addf(&root_sq, &root);

        // Assert w is in S_{j-1} (spanned by the first `subfield_dim` elements of basis)
        let w_coeffs = decompose(basis, w);
        for &coeff in &w_coeffs[subfield_dim..128] {
            assert!(!coeff, "w must lie in the subfield S_{{j-1}}");
        }

        // Assert trace of w in S_{j-1} is 1
        assert!(
            trace_in_subfield(&f, &w, subfield_dim),
            "trace_{{S_{{j-1}}}}(w) must be 1"
        );

        // Assert basis[subfield_dim + i] = basis[i] * root for i < subfield_dim
        for i in 0..subfield_dim {
            let expected = f.mulf(&basis[i], &root);
            assert_eq!(
                basis[subfield_dim + i],
                expected,
                "Cantor basis tensor product relation failed at j={j}, i={i}"
            );
        }
    }
}
