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

use compile_algebra::{field::CompileField, gf2_128::Gf2_128Field as UnoptField};
use core_algebra::{AlgebraicField, SerializableField, SupportsU128Conversions};
use runtime_algebra::{field::RuntimeField, gf2_128::*, poly::InterpolationField, Subfield};

#[test]
fn test_gf2_128_optimized_vs_unoptimized() {
    let field_unopt = UnoptField::new();
    let field_opt = Gf2_128RuntimeField::new();

    let inputs = vec![
        [0u8; 16],
        {
            let mut b = [0u8; 16];
            b[0] = 1;
            b
        },
        {
            let mut b = [0u8; 16];
            b[0] = 2;
            b
        },
        {
            let mut b = [0u8; 16];
            b[0] = 0xd2;
            b[1] = 0x02;
            b[2] = 0x96;
            b[3] = 0x49;
            b
        },
        [0xff; 16],
        {
            let mut b = [0xff; 16];
            b[0] = 0x9c;
            b
        },
    ];

    for b1 in &inputs {
        for b2 in &inputs {
            let e1_unopt = field_unopt.bytes_to_element(b1).unwrap();
            let e2_unopt = field_unopt.bytes_to_element(b2).unwrap();
            let res_unopt = field_unopt.addf(&e1_unopt, &e2_unopt);

            let e1_opt = field_opt.bytes_to_element(b1).unwrap();
            let e2_opt = field_opt.bytes_to_element(b2).unwrap();
            let res_opt = field_opt.addf(&e1_opt, &e2_opt);

            assert_eq!(
                field_unopt.to_bytes(&res_unopt),
                field_opt.to_bytes(&res_opt)
            );

            let res_unopt_sub = field_unopt.subf(&e1_unopt, &e2_unopt);
            let res_opt_sub = field_opt.subf(&e1_opt, &e2_opt);
            assert_eq!(
                field_unopt.to_bytes(&res_unopt_sub),
                field_opt.to_bytes(&res_opt_sub)
            );

            let res_unopt_mul = field_unopt.mulf(&e1_unopt, &e2_unopt);
            let res_opt_mul = field_opt.mulf(&e1_opt, &e2_opt);
            assert_eq!(
                field_unopt.to_bytes(&res_unopt_mul),
                field_opt.to_bytes(&res_opt_mul)
            );

            if !field_unopt.is_zero(&e1_unopt) {
                let res_unopt_inv = field_unopt.invert(&e1_unopt);
                let res_opt_inv = field_opt.invert(&e1_opt);
                assert_eq!(
                    field_unopt.to_bytes(&res_unopt_inv),
                    field_opt.to_bytes(&res_opt_inv)
                );
            }
        }
    }
}

#[test]
fn test_newton_denominators_and_interpolation() {
    let f = Gf2_128RuntimeField::new();
    for i in 1..6 {
        for k in i..6 {
            let dx = f.subf(&f.poly_evaluation_point(k), &f.poly_evaluation_point(k - i));
            let inv_dx_precomputed = f.newton_denominator(k, i);
            let prod_precomputed = f.mulf(&dx, &inv_dx_precomputed);
            assert_eq!(prod_precomputed, f.one(), "precomputed prod != 1");
        }
    }
}

#[test]
fn test_precomputed_agrees_with_algebra() {
    let field_unopt = UnoptField::new();
    let field_opt = Gf2_128RuntimeField::new();

    // 1. Check basis
    for i in 0..128 {
        assert_eq!(
            field_unopt.to_bytes(&field_unopt.pseudo_basis(i)),
            field_opt.to_bytes(&field_opt.pseudo_basis(i))
        );
    }

    // 3. Check poly_evaluation_points
    let mut expected_points = [field_unopt.zero(); 6];
    expected_points[0] = field_unopt.zero();
    let mut gi = field_unopt.one();
    let g = field_unopt.u128_to_element(0x5c5971877501d4b8_f1871e01b64fda4c_u128);
    for pt in expected_points.iter_mut().skip(1).take(5) {
        *pt = gi;
        gi = field_unopt.mulf(&gi, &g);
    }
    for (i, expected_point) in expected_points.iter().enumerate().take(6) {
        assert_eq!(
            field_unopt.to_bytes(expected_point),
            field_opt.to_bytes(&field_opt.poly_evaluation_point(i))
        );
    }

    // 4. Check newton_denominators
    let mut expected_denoms = [[field_unopt.zero(); 6]; 6];
    for i in 1..6 {
        for k in (i..6).rev() {
            let dx = field_unopt.subf(&expected_points[k], &expected_points[k - i]);
            expected_denoms[k][i] = field_unopt.invert(&dx);
        }
    }
    for (k, row) in expected_denoms.iter().enumerate().take(6) {
        for (i, denom) in row.iter().enumerate().take(k + 1).skip(1) {
            assert_eq!(
                field_unopt.to_bytes(denom),
                field_opt.to_bytes(&field_opt.newton_denominator(k, i))
            );
        }
    }
}

#[test]
fn test_serialization() {
    let field = Gf2_128RuntimeField::new();
    let one = field.one();
    let bytes = field.to_bytes(&one);
    assert_eq!(bytes.len(), field.serialized_size_bytes());

    let sf = runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let sub_bytes = sf.to_bytes(&one);
    assert_eq!(sub_bytes.len(), sf.serialized_size_bytes());
}
