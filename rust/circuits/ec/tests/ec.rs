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

use circuits_ec::{
    concrete::{add, affine, double, projective, push_pt2, scalar_mul},
    pt2_wires, EcCircuit,
};
use compile_algebra::{
    field::{CompileField, CompilePrimeField, SupportsNatConversions},
    p256::P256Field,
    secp256r1::Secp256r1,
    Curve,
};
use compile_eval::FieldID;
use compile_logic::{concrete::push_eltw, Logic, LogicIO};
use core_algebra::{Nat, SerializableField};
use runtime_algebra::field::RuntimeField;

fn test_compile_ec_generic<
    const W: usize,
    FC: CompilePrimeField + SupportsNatConversions<W> + SerializableField,
    FR: RuntimeField<W> + SerializableField,
    CC: Curve<W, F = FC>,
    CR: Curve<W, F = FR>,
>(
    curve_c: &CC,
    fc: &FC,
    curve_r: &CR,
    fr: &FR,
) {
    let (circuit, stats, symbols) = compile_compiler::top::compile_new(fc, |iologic| {
        let ec_circuit = EcCircuit::new(&iologic, curve_c);

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let p1 = pt2_wires(&iologic, &mut pos);
        let p2 = pt2_wires(&iologic, &mut pos);
        let p1_double_target = pt2_wires(&iologic, &mut pos);
        let p1_double_zinv = iologic.next(&mut pos);
        let p3_target = pt2_wires(&iologic, &mut pos);
        let p3_zinv = iologic.next(&mut pos);

        let p1_proj = ec_circuit.projective(&p1);
        let p2_proj = ec_circuit.projective(&p2);

        let p1_double_proj = ec_circuit.double(&p1_proj);
        let p3_proj = ec_circuit.add(&p1_proj, &p2_proj);

        let a1 = ec_circuit.is_on_curve(&p1);
        let a2 = ec_circuit.is_on_curve(&p2);
        let a3 = ec_circuit.point_equality(&p1_double_proj, &p1_double_zinv, &p1_double_target);
        let a4 = ec_circuit.point_equality(&p3_proj, &p3_zinv, &p3_target);

        (
            iologic.assert_all("ec_add_double", &[a1, a2, a3, a4]),
            iologic.tracker,
            1,
            0,
        )
    });

    compile_compiler::top::dump_stats("ec_add_double", &circuit, &stats);

    // Fill concrete values into environment using RuntimeField
    let g_2d_run = curve_r.g();
    let g = projective(curve_r, fr, g_2d_run);

    let g2 = double(curve_r, fr, &g);
    let g2_normalized = affine(fr, &g2);
    let g2_zinv_val = fr.invert(&g2.2);

    // To match circuit execution (where p2 input wire is normalized with Z=1),
    // we must project g2_normalized back to projective coordinates with Z=1.
    let g2_normalized_proj = projective(curve_r, fr, &g2_normalized);
    let g3 = add(curve_r, fr, &g, &g2_normalized_proj);
    let g3_normalized = affine(fr, &g3);
    let g3_zinv_val = fr.invert(&g3.2);

    let mut inputs = compile_eval::initial_inputs(fr);
    push_pt2(g_2d_run, &mut inputs);
    push_pt2(&g2_normalized, &mut inputs);
    push_pt2(&g2_normalized, &mut inputs);
    push_eltw(g2_zinv_val, &mut inputs);
    push_pt2(&g3_normalized, &mut inputs);
    push_eltw(g3_zinv_val, &mut inputs);

    compile_eval::eval_circuit_fc(fc, fr, &circuit, &symbols, &inputs, FieldID::P256)
        .unwrap()
        .assert_all_passed();
}

#[test]
fn test_compile_ec() {
    let fc = P256Field::new();
    let curve_c = Secp256r1::new(&fc);
    let fr = runtime_algebra::p256::P256Field::new();
    let curve_r = runtime_algebra::secp256r1::Secp256r1::new(&fr);
    test_compile_ec_generic::<4, _, _, _, _>(&curve_c, &fc, &curve_r, &fr);
}

use compile_logic::eval::EvalLogic;

fn test_ec_runtime_arithmetic_robust_generic<
    const W: usize,
    FR: CompileField + SupportsNatConversions<W>,
    C: Curve<W, F = FR>,
>(
    curve: &C,
    fr: &FR,
) {
    // Get curve generator point
    let g_2d = curve.g();
    let g = projective(curve, fr, g_2d);

    // Compute doubling via runtime
    let g2_runtime = double(curve, fr, &g);
    let g2_runtime_normalized = affine(fr, &g2_runtime);

    // Compute doubling via standard affine formulas using CompileField
    let g2_affine = {
        let (x, y) = g_2d;
        let three = fr.addf(&fr.one(), &fr.addf(&fr.one(), &fr.one()));
        let two = fr.addf(&fr.one(), &fr.one());
        let x_sq = fr.mulf(x, x);
        let a_val = curve.a();
        let num = fr.addf(&fr.mulf(&three, &x_sq), a_val);
        let den = fr.mulf(&two, y);
        let lambda = fr.mulf(&num, &fr.invert(&den));
        let two_x = fr.mulf(&two, x);
        let x3 = fr.subf(&fr.mulf(&lambda, &lambda), &two_x);
        let y3 = fr.subf(&fr.mulf(&lambda, &fr.subf(x, &x3)), y);
        (x3, y3)
    };

    // Assert doubling outputs match
    assert_eq!(g2_runtime_normalized.0, g2_affine.0);
    assert_eq!(g2_runtime_normalized.1, g2_affine.1);

    // Compute addition via runtime (G + 2G = 3G)
    let g3_runtime = add(curve, fr, &g, &g2_runtime);
    let g3_runtime_normalized = affine(fr, &g3_runtime);

    // Compute addition via standard affine formulas
    let g3_affine = {
        let (x1, y1) = g_2d;
        let (x2, y2) = &g2_affine;
        let num = fr.subf(y2, y1);
        let den = fr.subf(x2, x1);
        let lambda = fr.mulf(&num, &fr.invert(&den));
        let x3 = fr.subf(&fr.subf(&fr.mulf(&lambda, &lambda), x1), x2);
        let y3 = fr.subf(&fr.mulf(&lambda, &fr.subf(x1, &x3)), y1);
        (x3, y3)
    };

    // Assert addition outputs match
    assert_eq!(g3_runtime_normalized.0, g3_affine.0);
    assert_eq!(g3_runtime_normalized.1, g3_affine.1);

    // Test scalar_mul doubling
    let g2_scalar = scalar_mul(curve, fr, 2, &C::N::from_u64(2), &g);
    let g2_scalar_normalized = affine(fr, &g2_scalar);
    assert_eq!(g2_runtime_normalized.0, g2_scalar_normalized.0);
    assert_eq!(g2_runtime_normalized.1, g2_scalar_normalized.1);

    // Test scalar_mul tripling
    let g3_scalar = scalar_mul(curve, fr, 2, &C::N::from_u64(3), &g);
    let g3_scalar_normalized = affine(fr, &g3_scalar);
    assert_eq!(g3_runtime_normalized.0, g3_scalar_normalized.0);
    assert_eq!(g3_runtime_normalized.1, g3_scalar_normalized.1);
}

#[test]
fn test_ec_runtime_arithmetic_robust() {
    let fr = P256Field::new();
    let curve = Secp256r1::new(&fr);
    test_ec_runtime_arithmetic_robust_generic::<4, _, _>(&curve, &fr);
}

fn test_ec_circuit_evaluation_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    C: Curve<W, F = F>,
>(
    curve: &C,
    f: &F,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f, &tracker);
    let ec_circuit = EcCircuit::new(&l, curve);

    // Generator coordinates
    let g_2d = curve.g();
    let g_wire = (l.konst(&g_2d.0), l.konst(&g_2d.1));

    // Project generator to projective coordinates
    let g_proj_wire = ec_circuit.projective(&g_wire);

    // Double G in circuit
    let g2_proj_wire = ec_circuit.double(&g_proj_wire);

    // Verify coordinates of 2G via point_equality
    let g2_runtime = double(curve, f, &projective(curve, f, g_2d));
    let g2_runtime_normalized = affine(f, &g2_runtime);

    let zinv_val = f.invert(&g2_proj_wire.2.value);
    let zinv_wire = l.konst(&zinv_val);
    let g2_normalized_wire = (
        l.konst(&g2_runtime_normalized.0),
        l.konst(&g2_runtime_normalized.1),
    );

    let eq_assertion = ec_circuit.point_equality(&g2_proj_wire, &zinv_wire, &g2_normalized_wire);
    eq_assertion.unwrap();
}

#[test]
fn test_ec_circuit_evaluation() {
    let f = P256Field::new();
    let curve = Secp256r1::new(&f);
    test_ec_circuit_evaluation_generic::<4, _, _>(&curve, &f);
}

fn run_test_ec_runtime_arithmetic<
    const W: usize,
    FR: CompileField + SupportsNatConversions<W>,
    C: Curve<W, F = FR>,
>(
    curve: &C,
    fr: &FR,
) {
    // Get curve generator point
    let g_2d = curve.g();
    let g = projective(curve, fr, g_2d);

    // test normalization
    let g_norm = affine(fr, &g);
    assert_eq!(g_norm.0, g_2d.0);
    assert_eq!(g_norm.1, g_2d.1);

    // Compute doubling via runtime
    let g2 = double(curve, fr, &g);
    let g2_normalized = affine(fr, &g2);

    // Compute doubling via standard affine formulas
    let g2_affine = {
        let (x, y) = g_2d;
        let three = fr.addf(&fr.one(), &fr.addf(&fr.one(), &fr.one()));
        let two = fr.addf(&fr.one(), &fr.one());
        let x_sq = fr.mulf(x, x);
        let a_val = curve.a();
        let num = fr.addf(&fr.mulf(&three, &x_sq), a_val);
        let den = fr.mulf(&two, y);
        let lambda = fr.mulf(&num, &fr.invert(&den));
        let two_x = fr.mulf(&two, x);
        let x3 = fr.subf(&fr.mulf(&lambda, &lambda), &two_x);
        let y3 = fr.subf(&fr.mulf(&lambda, &fr.subf(x, &x3)), y);
        (x3, y3)
    };

    println!(
        "DEBUG: test_ec_runtime_arithmetic g2_normalized.0 = {:?}",
        fr.to_bytes(&g2_normalized.0)
    );
    println!(
        "DEBUG: test_ec_runtime_arithmetic g2_affine.0 = {:?}",
        fr.to_bytes(&g2_affine.0)
    );
    assert_eq!(g2_normalized.0, g2_affine.0);
    assert_eq!(g2_normalized.1, g2_affine.1);

    // Compute addition via runtime (G + 2G = 3G)
    let g3 = add(curve, fr, &g, &g2);
    let g3_normalized = affine(fr, &g3);

    // Compute addition via standard affine formulas
    let g3_affine = {
        let (x1, y1) = g_2d;
        let (x2, y2) = &g2_affine;
        let num = fr.subf(y2, y1);
        let den = fr.subf(x2, x1);
        let lambda = fr.mulf(&num, &fr.invert(&den));
        let x3 = fr.subf(&fr.subf(&fr.mulf(&lambda, &lambda), x1), x2);
        let y3 = fr.subf(&fr.mulf(&lambda, &fr.subf(x1, &x3)), y1);
        (x3, y3)
    };

    assert_eq!(g3_normalized.0, g3_affine.0);
    assert_eq!(g3_normalized.1, g3_affine.1);

    // Test scalar_mul doubling
    let g2_scalar = scalar_mul(curve, fr, 2, &C::N::from_u64(2), &g);
    let g2_scalar_normalized = affine(fr, &g2_scalar);
    assert_eq!(g2_normalized.0, g2_scalar_normalized.0);
    assert_eq!(g2_normalized.1, g2_scalar_normalized.1);

    // Test scalar_mul tripling
    let g3_scalar = scalar_mul(curve, fr, 2, &C::N::from_u64(3), &g);
    let g3_scalar_normalized = affine(fr, &g3_scalar);
    assert_eq!(g3_normalized.0, g3_scalar_normalized.0);
    assert_eq!(g3_normalized.1, g3_scalar_normalized.1);

    // Test scalar_mul by order yields zero point at infinity
    let inf = scalar_mul(curve, fr, 256, &curve.order(), &g);
    assert!(fr.is_zero(&inf.2));
}

#[test]
fn test_ec_runtime_arithmetic() {
    let fr = P256Field::new();
    let curve = Secp256r1::new(&fr);
    run_test_ec_runtime_arithmetic::<4, _, _>(&curve, &fr);
}
