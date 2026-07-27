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

use core_algebra::{AlgebraicField, SupportsU128Conversions};
use runtime_algebra::gf2_128::{Gf2_128, Gf2_128RuntimeField};

fn solve_quadratic_equation(c: Gf2_128) -> Gf2_128 {
    let f = Gf2_128RuntimeField::new();
    let mut matrix = [[false; 129]; 128];
    for (col, m_row) in (0..128).enumerate() {
        let e = f.u128_to_element(1u128 << col);
        let e_sq = f.mulf(&e, &e);
        let res = f.addf(&e_sq, &e);
        for (row, m_r) in matrix.iter_mut().enumerate() {
            m_r[col] = res.bit(row);
        }
        let _ = m_row;
    }
    for (row, m_r) in matrix.iter_mut().enumerate() {
        m_r[128] = c.bit(row);
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

    let mut sol_bits = [false; 128];
    for (i, &col) in pivot_cols.iter().enumerate() {
        sol_bits[col] = matrix[i][128];
    }

    let mut sol_val = 0u128;
    for (i, &bit) in sol_bits.iter().enumerate() {
        if bit {
            sol_val |= 1u128 << i;
        }
    }
    f.u128_to_element(sol_val)
}

fn trace_in_subfield(f: &Gf2_128RuntimeField, x: &Gf2_128, subfield_dim: usize) -> bool {
    let mut sum = f.zero();
    let mut val = *x;
    for _ in 0..subfield_dim {
        sum = f.addf(&sum, &val);
        val = f.mulf(&val, &val);
    }
    sum.bit(0)
}

#[test]
fn test_compute_cantor_basis() {
    let f = Gf2_128RuntimeField::new();
    let mut z = vec![f.one()]; // z_0 = 1

    let mut cantor_basis = vec![f.one()];

    for j in 1..=7 {
        let subfield_dim = 1 << (j - 1);
        // Find an element w in the current cantor_basis (which is the subfield F_{j-1})
        // that has trace 1 in F_{j-1}. At least one basis vector must have trace 1.
        let mut w_opt = None;
        for &w in cantor_basis.iter().take(subfield_dim) {
            if trace_in_subfield(&f, &w, subfield_dim) {
                w_opt = Some(w);
                break;
            }
        }

        let w = w_opt.unwrap_or_else(|| panic!("Could not find w in subfield at step {j}"));

        let root = solve_quadratic_equation(w);
        let root_sq = f.mulf(&root, &root);
        assert_eq!(
            f.addf(&root_sq, &root),
            w,
            "Quadratic solver returned incorrect root at step {j}"
        );

        z.push(root);

        // Update cantor_basis to size 2^j
        let mut new_basis = Vec::with_capacity(2 * subfield_dim);
        new_basis.extend_from_slice(&cantor_basis[..subfield_dim]);
        for &cb in &cantor_basis[..subfield_dim] {
            new_basis.push(f.mulf(&cb, &root));
        }
        cantor_basis = new_basis;
    }

    // Assert linear independence of the final basis of size 128
    let mut matrix = [[false; 128]; 128];
    for col in 0..128 {
        for (row, m_r) in matrix.iter_mut().enumerate() {
            m_r[col] = cantor_basis[col].bit(row);
        }
    }

    let mut pivot_row = 0;
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

    assert_eq!(pivot_row, 128, "Cantor basis is not linearly independent!");
}
