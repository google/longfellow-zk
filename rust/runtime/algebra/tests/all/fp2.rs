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
    field::{RuntimeField, SupportsU64Conversions},
    fp2::{Fp2Element, Fp2Field},
    p256::P256Field,
    AlgebraicField,
};

#[test]
fn test_fp2_algebraic_properties() {
    let base = P256Field::new();
    let field: Fp2Field<'_, 4, 8, _> = Fp2Field::new(&base);

    let zero = field.zero();
    let one = field.one();

    let a = Fp2Element {
        re: field.base_field().u64_to_element(1234567890u64),
        im: field.base_field().u64_to_element(9876543210u64),
    };
    let b = Fp2Element {
        re: field.base_field().u64_to_element(1111111111u64),
        im: field.base_field().u64_to_element(2222222222u64),
    };
    let c = Fp2Element {
        re: field.base_field().u64_to_element(3333333333u64),
        im: field.base_field().u64_to_element(4444444444u64),
    };

    // 1. Addition identity: a + 0 = a
    assert_eq!(field.addf(&a, &zero), a);

    // 2. Subtraction identity: a - a = 0
    assert_eq!(field.subf(&a, &a), zero);

    // 3. Multiplicative identity: a * 1 = a
    assert_eq!(field.mulf(&a, &one), a);

    // 4. Distributivity: a * (b + c) = a * b + a * c
    let lhs = field.mulf(&a, &field.addf(&b, &c));
    let rhs = field.addf(&field.mulf(&a, &b), &field.mulf(&a, &c));
    assert_eq!(lhs, rhs);

    // 5. Inversion: a * a^-1 = 1
    let a_inv = field.invert(&a);
    let a_mul_inv = field.mulf(&a, &a_inv);
    assert_eq!(a_mul_inv, one);

    // 6. Subfield properties: base field elements mapped to Fp2 behave identically
    let s1 = field.u64_to_element(42);
    let s2 = field.u64_to_element(100);
    let s_sum = field.addf(&s1, &s2);
    let s_prod = field.mulf(&s1, &s2);

    assert_eq!(s_sum.re, field.base_field().u64_to_element(142));
    assert_eq!(s_sum.im, field.base_field().zero());
    assert_eq!(s_prod.re, field.base_field().u64_to_element(4200));
    assert_eq!(s_prod.im, field.base_field().zero());

    // 7. Basis verification
    let d = field.pseudo_dimension();
    for i in 0..d {
        let b_i = field.pseudo_basis(i);
        assert_eq!(b_i.re, field.base_field().pseudo_basis(i));
        assert_eq!(b_i.im, field.base_field().zero());
    }
}
