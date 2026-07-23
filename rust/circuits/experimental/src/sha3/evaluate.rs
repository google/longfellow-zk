use circuits_bitvec::BitvecLogic;
use compile_logic::Logic;

use super::{
    circuit::{Derived as WireDerived, Given as WireGiven, State},
    concrete::{ConcreteDerived, ConcreteGiven},
};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> WireGiven<L> {
    let initial_state: State<L> =
        std::array::from_fn(|x| std::array::from_fn(|y| bv.of_u64_val(given.initial_state[x][y])));
    WireGiven { initial_state }
}

pub fn evaluate_derived<L: Logic>(
    derived: &ConcreteDerived,
    bv: &BitvecLogic<L>,
) -> WireDerived<L> {
    let mut intermediate_states = Vec::with_capacity(derived.intermediate_states.len());
    for rust_state in &derived.intermediate_states {
        let state: State<L> =
            std::array::from_fn(|x| std::array::from_fn(|y| bv.of_u64_val(rust_state[x][y])));
        intermediate_states.push(state);
    }
    WireDerived {
        intermediate_states,
    }
}
