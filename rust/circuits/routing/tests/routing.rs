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

use circuits_bitvec::{Bitvec, BitvecIO, BitvecLogic};
use circuits_boolean::{Bitw, Boolean};
use circuits_routing::Routing;
use compile_algebra::{field::SupportsU64Conversions, p256::P256Field};
use compile_logic::{Logic, LogicIO};

#[test]
fn test_compile_routing() {
    let f = P256Field::new();
    let (circuit, stats, _symbols) = compile_compiler::compile(&f, |iologic| {
        let bv = BitvecLogic::new(&iologic);
        let bitvec_io = BitvecIO::new(&bv);

        let n = 16;
        let unroll = 2;

        let mut pos = compile_logic::K_FIRST_WIRE_POSITION;
        let amount_bv: Bitvec<_, 4> = bitvec_io.next(&mut pos);

        let a_wires: Vec<_> = (0..n).map(|_| iologic.next(&mut pos)).collect();
        let default_wire = iologic.next(&mut pos);

        let routing = Routing::new(&iologic);
        let res = routing.shifte(unroll, &amount_bv, n, &a_wires, &default_wire);

        let mut asserts = Vec::new();
        for r in &res {
            asserts.push(iologic.assert0("res_zero", r));
        }
        (iologic.assert_all("shifte_routing", &asserts), 1, 0)
    });

    compile_compiler::dump_stats("shifte_16_16_2", &circuit, &stats);

    assert_eq!(stats.ninput, 22);
    assert_eq!(stats.npublic_input, 1);
    assert_eq!(stats.noutput, 16);
    assert_eq!(stats.nlayers, 3);
    assert_eq!(stats.nwires, 74);
    assert_eq!(stats.nterms, 184);
}

use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::eval::EvalLogic;

fn int_to_bits(val: usize, bits: usize) -> Vec<bool> {
    (0..bits).map(|i| ((val >> i) & 1) == 1).collect()
}

fn run_eval_test_e_generic<
    const W: usize,
    F: CompileField + SupportsNatConversions<W> + SupportsU64Conversions,
>(
    f: &F,
    logn: usize,
    n: usize,
    k: usize,
    shift: usize,
    unroll: usize,
    unshift: bool,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    let iologic = EvalLogic::new(f, &tracker);
    let boolean = Boolean::new(&iologic);
    let routing = Routing::new(&iologic);

    // amount bits
    let amount_bits_bool = int_to_bits(shift, logn);
    let amount_bits: Vec<Bitw<_>> = amount_bits_bool
        .into_iter()
        .map(|b| if b { boolean.trueb() } else { boolean.falseb() })
        .collect();
    let amount_bitvec = Bitvec::<_, 16>::new({
        let mut bits = amount_bits;
        bits.resize_with(16, || boolean.falseb());
        bits
    });

    // inputs
    let a_vals_raw: Vec<_> = (0..n).map(|i| f.u64_to_element((i + 42) as u64)).collect();
    let default_val_raw = f.u64_to_element(12345);

    let a_vals: Vec<_> = a_vals_raw.iter().map(|v| iologic.konst(v)).collect();
    let default_val = iologic.konst(&default_val_raw);

    let res = if unshift {
        routing.unshifte(unroll, &amount_bitvec, k, &a_vals, &default_val)
    } else {
        routing.shifte(unroll, &amount_bitvec, k, &a_vals, &default_val)
    };

    let real_shift = shift % (1 << logn);
    for i in 0..k {
        let expected = if unshift {
            if i >= real_shift && i < n + real_shift {
                a_vals_raw[i - real_shift].clone()
            } else {
                default_val_raw.clone()
            }
        } else {
            if i + real_shift < n {
                a_vals_raw[i + real_shift].clone()
            } else {
                default_val_raw.clone()
            }
        };
        assert_eq!(res[i].value, expected);
    }
}

fn run_eval_test_b_generic<const W: usize, F: CompileField + SupportsNatConversions<W>>(
    f: &F,
    logn: usize,
    n: usize,
    k: usize,
    shift: usize,
    unroll: usize,
    unshift: bool,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    let iologic = EvalLogic::new(f, &tracker);
    let boolean = Boolean::new(&iologic);
    let routing = Routing::new(&iologic);

    // amount bits
    let amount_bits_bool = int_to_bits(shift, logn);
    let amount_bits: Vec<Bitw<_>> = amount_bits_bool
        .into_iter()
        .map(|b| if b { boolean.trueb() } else { boolean.falseb() })
        .collect();
    let amount_bitvec = Bitvec::<_, 16>::new({
        let mut bits = amount_bits;
        bits.resize_with(16, || boolean.falseb());
        bits
    });

    // inputs
    let a_vals: Vec<bool> = (0..n).map(|i| (i ^ (i >> 2) ^ (i >> 5)) % 2 == 1).collect();
    let a_wires: Vec<Bitw<_>> = a_vals
        .iter()
        .map(|&b| if b { boolean.trueb() } else { boolean.falseb() })
        .collect();

    let default_val = (logn ^ n ^ k ^ shift ^ unroll) % 2 == 1;
    let default_wire = if default_val {
        boolean.trueb()
    } else {
        boolean.falseb()
    };

    let res = if unshift {
        routing.unshiftb(unroll, &amount_bitvec, k, &a_wires, &default_wire)
    } else {
        routing.shiftb(unroll, &amount_bitvec, k, &a_wires, &default_wire)
    };

    let real_shift = shift % (1 << logn);
    for i in 0..k {
        let expected = if unshift {
            if i >= real_shift && i < n + real_shift {
                a_vals[i - real_shift]
            } else {
                default_val
            }
        } else {
            if i + real_shift < n {
                a_vals[i + real_shift]
            } else {
                default_val
            }
        };

        let got = res[i].clone();
        let got_val = boolean.as_eltw(&got);
        let expected_val = if expected { f.one() } else { f.zero() };
        assert_eq!(got_val.value, expected_val);
    }
}

fn run_eval_test_bitvec_generic<const W: usize, F: CompileField + SupportsNatConversions<W>>(
    f: &F,
    logn: usize,
    n: usize,
    k: usize,
    shift: usize,
    unroll: usize,
    unshift: bool,
) {
    let tracker = compile_logic::scope::AssertionScope::new();
    let iologic = EvalLogic::new(f, &tracker);
    let boolean = Boolean::new(&iologic);
    let routing = Routing::new(&iologic);

    // amount bits
    let amount_bits_bool = int_to_bits(shift, logn);
    let amount_bits: Vec<Bitw<_>> = amount_bits_bool
        .into_iter()
        .map(|b| if b { boolean.trueb() } else { boolean.falseb() })
        .collect();
    let amount_bitvec = Bitvec::<_, 16>::new({
        let mut bits = amount_bits;
        bits.resize_with(16, || boolean.falseb());
        bits
    });

    // inputs
    let a_vals: Vec<u8> = (0..n).map(|i| (i + 42) as u8).collect();
    let a_wires: Vec<Bitvec<_, 8>> = a_vals
        .iter()
        .map(|&val| {
            let mut bits = Vec::new();
            for i in 0..8 {
                bits.push(if ((val >> i) & 1) == 1 {
                    boolean.trueb()
                } else {
                    boolean.falseb()
                });
            }
            Bitvec::new(bits)
        })
        .collect();

    let default_val = 123u8;
    let default_wire = Bitvec::new({
        let mut bits = Vec::new();
        for i in 0..8 {
            bits.push(if ((default_val >> i) & 1) == 1 {
                boolean.trueb()
            } else {
                boolean.falseb()
            });
        }
        bits
    });

    let res = if unshift {
        routing.unshift_bitvec(unroll, &amount_bitvec, k, &a_wires, &default_wire)
    } else {
        routing.shift_bitvec(unroll, &amount_bitvec, k, &a_wires, &default_wire)
    };

    let real_shift = shift % (1 << logn);
    for i in 0..k {
        let expected = if unshift {
            if i >= real_shift && i < n + real_shift {
                a_vals[i - real_shift]
            } else {
                default_val
            }
        } else {
            if i + real_shift < n {
                a_vals[i + real_shift]
            } else {
                default_val
            }
        };

        let mut got_val = 0u8;
        for j in 0..8 {
            let bit_val = boolean.as_eltw(res[i].bit(j));
            if bit_val.value == f.one() {
                got_val |= 1 << j;
            }
        }
        assert_eq!(got_val, expected);
    }
}

#[test]
fn test_routing_evaluation() {
    let f = P256Field::new();
    // Run small test suite similar to OCaml test_small
    for logn in 1..=4 {
        for n in 1..=8 {
            for k in 1..=8 {
                for shift in 0..=8 {
                    for unroll in 1..=4 {
                        run_eval_test_e_generic::<4, _>(&f, logn, n, k, shift, unroll, false);
                        run_eval_test_e_generic::<4, _>(&f, logn, n, k, shift, unroll, true);
                        run_eval_test_b_generic::<4, _>(&f, logn, n, k, shift, unroll, false);
                        run_eval_test_b_generic::<4, _>(&f, logn, n, k, shift, unroll, true);
                        run_eval_test_bitvec_generic::<4, _>(&f, logn, n, k, shift, unroll, false);
                        run_eval_test_bitvec_generic::<4, _>(&f, logn, n, k, shift, unroll, true);
                    }
                }
            }
        }
    }
}
