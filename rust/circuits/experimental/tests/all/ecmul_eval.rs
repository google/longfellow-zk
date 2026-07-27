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

use circuits_experimental::ecmul::{
    derived,
    evaluate::{evaluate_derived, evaluate_given},
    ConcreteGiven, EcmulCircuit,
};
use compile_algebra::{
    field::{CompileField, SupportsNatConversions},
    p256::P256Field,
    secp256r1::Secp256r1,
    Curve,
};
use compile_logic::eval::EvalLogic;
use core_algebra::Nat;

use super::testvec;

fn run_ecmul_eval_tests<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    C: Curve<W, F = F>,
>(
    curve: &C,
    f: &F,
) {
    let n = 256;
    let tv = testvec::get_testvec();

    let ax_fp = f.reduce_nat(&F::N::from_bytes_le(&tv.ax.to_bytes_le()));
    let ay_fp = f.reduce_nat(&F::N::from_bytes_le(&tv.ay.to_bytes_le()));
    let bx_fp = f.reduce_nat(&F::N::from_bytes_le(&tv.bx.to_bytes_le()));
    let by_fp = f.reduce_nat(&F::N::from_bytes_le(&tv.by.to_bytes_le()));

    let concrete_given = ConcreteGiven {
        exp: tv.exp.clone(),
        a: (ax_fp, ay_fp),
        b: (bx_fp, by_fp),
    };
    let concrete_derived = derived(curve, n, &concrete_given, f);

    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::<F>::new(f, &tracker);
    let circuit = EcmulCircuit::new(&l, curve, n);

    let wire_given = evaluate_given(&concrete_given, &l, n);
    let wire_derived = evaluate_derived(&concrete_derived, &l);

    let assertion = circuit.assert_scalar_mul(&wire_given, &wire_derived);
    assertion.unwrap();
}

#[test]
fn test_ecmul_eval() {
    let f = P256Field::new();
    let curve = Secp256r1::new(&f);
    run_ecmul_eval_tests::<4, _, _>(&curve, &f);
}
