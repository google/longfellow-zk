use circuits_ec::{evaluate_pt2, evaluate_pt3};
use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::Logic;

use super::{
    circuit::{Derived as WireDerived, Given as WireGiven},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    given: &ConcreteGiven<W, F>,
    logic: &L,
    n: usize,
) -> WireGiven<L> {
    let boolean = circuits_boolean::Boolean::new(logic);
    let mut exp_bits = Vec::with_capacity(n);
    for i in 0..n {
        let bit_val = ((&given.exp >> i) & num_bigint::BigUint::from(1u32))
            == num_bigint::BigUint::from(1u32);
        exp_bits.push(boolean.konst(bit_val));
    }
    WireGiven {
        exp_bits,
        a: evaluate_pt2(&given.a, logic),
        b: evaluate_pt2(&given.b, logic),
    }
}

pub fn evaluate_derived<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    derived: &ConcreteDerived<W, F>,
    logic: &L,
) -> WireDerived<L> {
    let round = derived
        .round
        .iter()
        .map(|p| evaluate_pt3(p, logic))
        .collect();
    WireDerived {
        round,
        zinv: logic.konst(&derived.zinv),
    }
}
