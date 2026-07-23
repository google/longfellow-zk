use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(logic: &L, n: usize, pos: &mut usize) -> Given<L> {
    let boolean_io = circuits_boolean::BooleanIO::new(logic);
    let mut exp_bits = Vec::with_capacity(n);
    for _ in 0..n {
        exp_bits.push(boolean_io.next(pos));
    }
    let a = circuits_ec::pt2_wires(logic, pos);
    let b = circuits_ec::pt2_wires(logic, pos);
    Given { exp_bits, a, b }
}

pub fn allocate_derived<L: LogicIO>(logic: &L, n: usize, pos: &mut usize) -> Derived<L> {
    let mut round = Vec::with_capacity(n);
    for _ in 0..n {
        round.push(circuits_ec::pt3_wires(logic, pos));
    }
    let zinv = logic.next(pos);
    Derived { round, zinv }
}
