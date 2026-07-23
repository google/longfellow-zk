use circuits_bitvec::{BitvecIO, BitvecLogic};
use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let input_block = std::array::from_fn(|_| bitvec_io.next(pos));
    let h0 = std::array::from_fn(|_| bitvec_io.next(pos));
    Given { input_block, h0 }
}

pub fn allocate_derived<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Derived<L> {
    let bitvec_io = BitvecIO::new(bv);
    let outw = std::array::from_fn(|_| bitvec_io.next(pos));
    let oute = std::array::from_fn(|_| bitvec_io.next(pos));
    let outa = std::array::from_fn(|_| bitvec_io.next(pos));
    let h1 = std::array::from_fn(|_| bitvec_io.next(pos));
    Derived {
        outw,
        oute,
        outa,
        h1,
    }
}
