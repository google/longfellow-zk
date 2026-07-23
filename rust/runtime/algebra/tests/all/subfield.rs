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

use core_algebra::{AlgebraicField, Comparable, SupportsU128Conversions};
use runtime_algebra::{gf2_128::Gf2_128RuntimeField, subfield::BinarySubfield, Subfield};

struct SimpleRng(u64);
impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self, max: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 as usize) % max
    }
}

#[test]
fn test_runtime_subfield_gf2_16() {
    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1); // GF(2^16) -> 65536 elements

    let n = 65536;
    let mut elements = Vec::with_capacity(n);
    for i in 0..n {
        let el = subfield.embed(i as u64);
        elements.push(el);
    }

    // 1. Exhaustive check that project(embed(x)) = x for all x
    for i in 0..n {
        let el = subfield.embed(i as u64);
        assert!(subfield.contains(&el), "contains(embed(x)) must be true");
        let projected = subfield.project(&el).expect("project must succeed");
        assert_eq!(projected, i as u64, "project(embed(x)) != x for x = {i}");
    }

    // 2. Check distinct
    let mut sorted = elements.clone();
    sorted.sort_by(|a, b| f.compare(a, b));
    sorted.dedup();
    assert_eq!(sorted.len(), n, "All elements must be distinct");

    // 3. Check 0 and 1 are there
    let zero = f.zero();
    let one = f.one();
    assert!(elements.contains(&zero), "0 must be in subfield");
    assert!(elements.contains(&one), "1 must be in subfield");

    // 4. Deterministically sample pairs and test closure under addition and multiplication
    let mut rng = SimpleRng::new(42);

    for _ in 0..10000 {
        let i = rng.next(n);
        let j = rng.next(n);

        let a = &elements[i];
        let b = &elements[j];

        let sum = f.addf(a, b);
        let sum_idx = subfield.project(&sum).expect("sum must be in subfield");
        assert_eq!(sum_idx, (i ^ j) as u64, "sum index mismatch");

        // a * b
        let prod = f.mulf(a, b);
        let prod_idx = subfield
            .project(&prod)
            .expect("product must be in subfield");
        assert!(prod_idx < 65536, "product not in subfield");
    }

    // 6. Check contains returns false for elements not in subfield
    let not_in_subfield = f.u128_to_element(1 << 64);
    assert!(
        !subfield.contains(&not_in_subfield),
        "contains must return false for elements outside subfield"
    );
}

#[test]
fn test_subfield_gf2_128() {
    use runtime_algebra::subfield::BinarySubfield;
    let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);

    let f = Gf2_128RuntimeField::new();
    let zero = f.zero();
    let one = f.one();

    assert!(sf.contains(&zero));
    assert!(sf.contains(&one));

    let zero_bytes = sf.to_bytes(&zero);
    let one_bytes = sf.to_bytes(&one);

    assert_eq!(zero_bytes, vec![0, 0]);
    assert_eq!(one_bytes, vec![1, 0]);
}

#[test]
fn test_gf2_16_basis_v1_properties() {
    let sf_basis = core_algebra::proto::GF2_16_BASIS_V1;

    // 1. Ensure exactly 16 elements
    assert_eq!(sf_basis.len(), 16);

    // 2. Put them in a 128x16 bit matrix to check rank
    let mut matrix = [[false; 16]; 128];
    for (col, &val) in sf_basis.iter().enumerate().take(16) {
        for (row, m_r) in matrix.iter_mut().enumerate() {
            m_r[col] = ((val >> row) & 1) != 0;
        }
    }

    // Perform Gaussian elimination
    let mut pivot_row = 0;
    for col in 0..16 {
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
                    for (c_idx, cell) in m_r.iter_mut().enumerate().take(16).skip(col) {
                        *cell ^= pivot_row_vals[c_idx];
                    }
                }
            }
            pivot_row += 1;
        }
    }

    // If the elements are linearly independent, the rank must be exactly 16
    assert_eq!(
        pivot_row, 16,
        "GF2_16_BASIS_V1 is not linearly independent!"
    );
}

#[test]
fn test_subfield_closed_under_multiplication() {
    let f = Gf2_128RuntimeField::new();
    let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);

    // 1. Check all pairs of basis elements
    for &a in sf.basis() {
        for &b in sf.basis() {
            let prod = f.mulf(&a, &b);
            assert!(sf.contains(&prod), "Basis product not in subfield!");
        }
    }

    let mut rng_state = 12345u64;
    let mut next_rng = || {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_state
    };

    // 2. Check 1000 random pairs
    for _ in 0..1000 {
        let a_val = next_rng() % 65536;
        let b_val = next_rng() % 65536;
        let a = sf.embed(a_val);
        let b = sf.embed(b_val);
        let prod = f.mulf(&a, &b);
        assert!(sf.contains(&prod), "Subfield product not in subfield!");
    }
}
