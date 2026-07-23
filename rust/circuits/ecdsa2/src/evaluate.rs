use circuits_ec::{evaluate_pt2, evaluate_pt3};
use compile_algebra::field::{CompileField, SupportsNatConversions};
use compile_logic::Logic;

use super::{
    circuit::{Derived, Given, Slicing},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    given: &ConcreteGiven<F>,
    logic: &L,
) -> Given<L> {
    let pkxy = (logic.konst(&given.pkxy.0), logic.konst(&given.pkxy.1));
    let e = logic.konst(&given.e);
    let rxy = (logic.konst(&given.rxy.0), logic.konst(&given.rxy.1));
    let ers = std::array::from_fn(|i| logic.konst(&given.ers[i]));
    Given { pkxy, e, rxy, ers }
}

pub fn evaluate_derived<
    const W: usize,
    F: CompileField + SupportsNatConversions<W>,
    L: Logic<F = F>,
>(
    derived: &ConcreteDerived<F>,
    logic: &L,
) -> Derived<L> {
    let round = std::array::from_fn(|i| evaluate_pt3(&derived.slicing.round[i], logic));
    Derived {
        pkxinv: logic.konst(&derived.pkxinv),
        rxinv: logic.konst(&derived.rxinv),
        nmsinv: logic.konst(&derived.nmsinv),
        yinv: logic.konst(&derived.yinv),
        slicing: Slicing {
            g_pk: evaluate_pt2(&derived.slicing.g_pk, logic),
            g_r: evaluate_pt2(&derived.slicing.g_r, logic),
            pk_r: evaluate_pt2(&derived.slicing.pk_r, logic),
            g_pk_r: evaluate_pt2(&derived.slicing.g_pk_r, logic),
            round,
        },
    }
}
