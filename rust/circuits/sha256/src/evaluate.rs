use circuits_bitvec::BitvecLogic;
use compile_logic::Logic;

use super::{
    circuit::{Derived, Given},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> Given<L> {
    let input_block = std::array::from_fn(|i| bv.of_u32(given.input_block[i]));
    let h0 = std::array::from_fn(|i| bv.of_u32(given.h0[i]));
    Given { input_block, h0 }
}

pub fn evaluate_derived<L: Logic>(derived: &ConcreteDerived, bv: &BitvecLogic<L>) -> Derived<L> {
    let outw = std::array::from_fn(|i| bv.of_u32(derived.outw[i]));
    let oute = std::array::from_fn(|i| bv.of_u32(derived.oute[i]));
    let outa = std::array::from_fn(|i| bv.of_u32(derived.outa[i]));
    let h1 = std::array::from_fn(|i| bv.of_u32(derived.h1[i]));
    Derived {
        outw,
        oute,
        outa,
        h1,
    }
}
