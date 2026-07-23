use circuits_bitvec::BitvecIO;
use compile_logic::LogicIO;

use super::circuit::{Derived, Given, State};

pub fn allocate_given<L: LogicIO>(
    bv: &circuits_bitvec::BitvecLogic<L>,
    pos: &mut usize,
) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let initial_state: State<L> =
        std::array::from_fn(|_x| std::array::from_fn(|_y| bitvec_io.next(pos)));
    Given { initial_state }
}

pub fn allocate_derived<L: LogicIO>(
    bv: &circuits_bitvec::BitvecLogic<L>,
    pos: &mut usize,
) -> Derived<L> {
    let bitvec_io = BitvecIO::new(bv);
    let mut intermediate_states = Vec::with_capacity(24);
    for _ in 0..24 {
        let state: State<L> =
            std::array::from_fn(|_x| std::array::from_fn(|_y| bitvec_io.next(pos)));
        intermediate_states.push(state);
    }
    Derived {
        intermediate_states,
    }
}
