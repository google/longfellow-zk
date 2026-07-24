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

use compile_algebra::{
    field::{CompileField, SupportsU64Conversions},
    gf2_128::Gf2_128Field,
    interpolation::{eval_monomial, eval_newton, monomial_of_newton, newton_of_lagrange},
    p256::P256Field,
};
use core_algebra::ElementOf;

fn test_interpolation_for_field<F: CompileField + SupportsU64Conversions>(f: &F)
where ElementOf<F>: PartialEq + std::fmt::Debug {
    let n = 47;
    let mut x = Vec::with_capacity(n);
    let mut monomial = Vec::with_capacity(n);
    for i in 0..n {
        let xv = (i * i) + 3 + i + 37;
        x.push(f.u64_to_element(xv as u64));

        let mv = (i * i * i) + (i & 0xf) + (i >> 3);
        monomial.push(f.u64_to_element(mv as u64));
    }

    let mut lagrange = Vec::with_capacity(n);
    for point_x in &x[..n] {
        lagrange.push(eval_monomial(f, &monomial, point_x));
    }

    let newton = newton_of_lagrange(f, &lagrange, &x);

    for i in 0..1000 {
        let point = f.u64_to_element(i as u64);
        assert_eq!(
            eval_newton(f, &newton, &x, &point),
            eval_monomial(f, &monomial, &point)
        );
    }

    let m2 = monomial_of_newton(f, &newton, &x);
    for i in 0..n {
        assert_eq!(monomial[i], m2[i]);
    }
}

#[test]
fn test_interpolation() {
    let gf2 = Gf2_128Field::new();
    test_interpolation_for_field(&gf2);
    let p256 = P256Field::new();
    test_interpolation_for_field(&p256);
}
