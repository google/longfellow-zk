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

use runtime_algebra::{
    field::SupportsU64Conversions, gf2_128::Gf2_128RuntimeField, p256::P256Field,
    poly::InterpolationField,
};
use runtime_sumcheck::poly::{LagrangeBasis, Poly};

fn test_poly_evaluation_generic<const W: usize, F: InterpolationField<W>>(
    f: &F,
    y0: F::E,
    y1: F::E,
    y2: F::E,
    x3: F::E,
) {
    let x0 = f.poly_evaluation_point(0);
    let x1 = f.poly_evaluation_point(1);
    let x2 = f.poly_evaluation_point(2);

    let mut p: Poly<3, W, F> = Poly::zero(f);
    p.evaluations[0] = y0.clone();
    p.evaluations[1] = y1.clone();
    p.evaluations[2] = y2.clone();

    // 1. Check evaluations at interpolation points match exactly
    assert_eq!(p.eval_lagrange(&x0, f), y0);
    assert_eq!(p.eval_lagrange(&x1, f), y1);
    assert_eq!(p.eval_lagrange(&x2, f), y2);

    // 2. Check Newton representation computation
    let mut p_newton = p.clone();
    p_newton.newton_of_lagrange(f);

    let c0 = &p_newton.evaluations[0];
    let c1 = &p_newton.evaluations[1];
    let c2 = &p_newton.evaluations[2];

    // c0 should be y0
    assert_eq!(c0, &y0);

    // c0 + c1 * (x1 - x0) should be y1
    let term1 = f.mulf(c1, &f.subf(&x1, &x0));
    assert_eq!(f.addf(c0, &term1), y1);

    // c0 + c1 * (x2 - x0) + c2 * (x2 - x0) * (x2 - x1) should be y2
    let term2_1 = f.subf(&x2, &x0);
    let term2_2 = f.subf(&x2, &x1);
    let term2 = f.mulf(c2, &f.mulf(&term2_1, &term2_2));
    let term1_at_x2 = f.mulf(c1, &term2_1);
    assert_eq!(f.addf(&f.addf(c0, &term1_at_x2), &term2), y2);

    // 3. Test LagrangeBasis
    let lagrange_basis = LagrangeBasis::<3, W, F>::new(f);

    let val3 = p.eval_lagrange(&x3, f);

    let coefs = lagrange_basis.coef(&x3, f);
    let mut reconstructed = f.zero();
    for i in 0..3 {
        reconstructed = f.addf(
            &reconstructed,
            &f.mulf(&coefs.evaluations[i], &p.evaluations[i]),
        );
    }
    assert_eq!(reconstructed, val3);
}

#[test]
fn test_poly_evaluation_p256() {
    let f = P256Field::new();
    test_poly_evaluation_generic(
        &f,
        f.u64_to_element(5),
        f.u64_to_element(10),
        f.u64_to_element(20),
        f.u64_to_element(15),
    );
}

#[test]
fn test_poly_evaluation_gf2_128() {
    let f = Gf2_128RuntimeField::new();
    let sf = runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    test_poly_evaluation_generic(&f, sf.embed(5), sf.embed(10), sf.embed(20), sf.embed(15));
}

#[test]
fn test_fixed_cubic_polynomial() {
    let f = P256Field::new();
    // P(x) = 2x^3 - 3x^2 + 5x + 7
    // Interpolation points: x_0=0, x_1=1, x_2=2, x_3=3
    // Evaluations: P(0)=7, P(1)=11, P(2)=21, P(3)=49
    let mut p: Poly<4, 4, _> = Poly::zero(&f);
    p.evaluations[0] = f.u64_to_element(7);
    p.evaluations[1] = f.u64_to_element(11);
    p.evaluations[2] = f.u64_to_element(21);
    p.evaluations[3] = f.u64_to_element(49);

    // Test evaluation at x = 4, P(4) should be 107
    let x4 = f.u64_to_element(4);
    let val4 = p.eval_lagrange(&x4, &f);
    assert_eq!(val4, f.u64_to_element(107));

    // Test evaluation at x = 5, P(5) should be 207
    let x5 = f.u64_to_element(5);
    let val5 = p.eval_lagrange(&x5, &f);
    assert_eq!(val5, f.u64_to_element(207));
}
