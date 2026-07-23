use circuits_bitvec::BitvecLogic;
use compile_logic::Logic;

use super::{circuit::Given as WireGiven, concrete::ConcreteGiven};

pub fn evaluate_given<L: Logic>(given: &ConcreteGiven, bv: &BitvecLogic<L>) -> WireGiven<L> {
    let v = bv.of_u8(given.v);
    WireGiven { v }
}
