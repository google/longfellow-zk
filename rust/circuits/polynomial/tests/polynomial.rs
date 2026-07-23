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

use circuits_polynomial::Polynomial;
use compile_algebra::{
    field::{SupportsNatConversions, SupportsU64Conversions},
    p256::P256Field,
};
use compile_compiler::{CompilerArena, CompilerLogic};
use compile_logic::{Logic, LogicIO};

#[test]
fn test_compile_polynomial() {
    let f = P256Field::new();
    let arena = CompilerArena::new();
    let iologic = CompilerLogic::new(&arena, &f);
    let p = Polynomial::new(&iologic);

    let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
    let cc: Vec<_> = (0..5).map(|_| iologic.next(&mut pos)).collect();
    let x = iologic.next(&mut pos);

    let res = p.eval(&cc, &x);
    let assertion = iologic.assert0("poly_res", &res);

    let (circuit, stats, _symbols) = compile_compiler::top::compile(&arena, &f, assertion, 1, 0);

    compile_compiler::top::dump_stats("polynomial_eval_compile", &circuit, &stats);
}

use compile_algebra::{field::CompileField, interpolation::eval_monomial};
use compile_logic::eval::EvalLogic;

fn test_polynomial_evaluation_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
) {
    let iologic = EvalLogic::new(f);
    let p = Polynomial::new(&iologic);

    let n = 47;
    let mut poly = Vec::with_capacity(n);
    for i in 0..n {
        let val = 7 + (i * i * i) + (i & 0xf) + (i >> 3);
        poly.push(f.u64_to_element(u64::from(val as u32)));
    }
    let poly_wires: Vec<_> = poly.iter().map(|c| iologic.konst(c)).collect();

    for k in 0..1000 {
        let pt = f.u64_to_element(u64::from(k as u32));
        let pt_wire = iologic.konst(&pt);
        let want = eval_monomial(f, &poly, &pt);
        let got = p.eval(&poly_wires, &pt_wire);
        let goth = p.eval_horner(&poly_wires, &pt_wire);

        assert_eq!(want, got.value, "Mismatch at standard eval for k = {k}");
        assert_eq!(want, goth.value, "Mismatch at horner eval for k = {k}");
    }
}

#[test]
fn test_polynomial_evaluation() {
    let f = P256Field::new();
    test_polynomial_evaluation_generic::<4, _>(&f);
}
