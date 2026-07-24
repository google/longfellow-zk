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

use circuits_lookup::Lookup;
use compile_algebra::{
    field::{CompileField, SupportsNatConversions, SupportsU64Conversions},
    p256::P256Field,
};
use compile_logic::{Logic, LogicIO};

#[test]
fn test_compile_lookup() {
    let f = P256Field::new();
    let (circuit, stats, _symbols) = compile_compiler::compile(&f, |iologic| {
        let l = Lookup::new(&iologic);

        let n = 5;
        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let table_vals: Vec<_> = (0..n).map(|_| iologic.next(&mut pos)).collect();
        let x = iologic.next(&mut pos);

        let table = l.table_of_array(&table_vals);
        let res = table.eval(&x);
        (iologic.assert0("lookup_res", &res), 1, 0)
    });

    compile_compiler::dump_stats("lookup_eval_compile", &circuit, &stats);
}

use compile_logic::eval::EvalLogic;

fn test_lookup_evaluation_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    let iologic = EvalLogic::new(f, &tracker);
    let l = Lookup::new(&iologic);

    let n = 7;
    let mut table_vals = Vec::with_capacity(n);
    for i in 0..n {
        let val = (i * i) + 5;
        table_vals.push(iologic.konst(&f.u64_to_element((val) as u64)));
    }

    let table = l.table_of_array(&table_vals);

    for (i, table_val) in table_vals.iter().enumerate().take(n) {
        let pt = l.point(n, i);
        let pt_wire = iologic.konst(&pt);
        let got = table.eval(&pt_wire);
        let want = &table_val.value;
        assert_eq!(*want, got.value, "Mismatch at point i = {i}");
    }
}

fn test_lookup_circuit_evaluation_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    type L<'a, F> = EvalLogic<'a, F>;
    let l = L::new(f, &tracker);
    let lookup_circuit = Lookup::new(&l);

    let n = 7;
    let mut table_vals_r = Vec::with_capacity(n);
    for i in 0..n {
        let val = (i * i) + 5;
        table_vals_r.push(f.u64_to_element((val) as u64));
    }

    let table_vals_wire: Vec<_> = table_vals_r.iter().map(|v| l.konst(v)).collect();

    let table = lookup_circuit.table_of_array(&table_vals_wire);

    for (i, want_r) in table_vals_r.iter().enumerate() {
        let pt_r = f.lookup_point(n, i);
        let pt_wire = l.konst(&pt_r);
        let got_wire = table.eval(&pt_wire);

        let got_r = got_wire.value;

        assert_eq!(*want_r, got_r, "Mismatch at point index = {i}");
    }
}

#[test]
fn test_lookup_evaluation() {
    let fc = P256Field::new();
    test_lookup_evaluation_generic::<4, _>(&fc);
    test_lookup_circuit_evaluation_generic::<4, _>(&fc);
}
