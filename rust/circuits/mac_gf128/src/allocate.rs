use circuits_bitvec::{BitvecIO, BitvecLogic};
use compile_logic::LogicIO;

use super::circuit::{Derived, Given};

pub fn allocate_given<L: LogicIO>(logic: &L, bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let message = bitvec_io.next::<256>(pos);
    let mac_av = logic.next(pos);
    let mac_ap0 = logic.next(pos);
    let mac_ap1 = logic.next(pos);
    let tag0 = logic.next(pos);
    let tag1 = logic.next(pos);
    Given {
        message,
        mac_av,
        mac_ap: [mac_ap0, mac_ap1],
        tag: [tag0, tag1],
    }
}

pub fn allocate_derived(_pos: &mut usize) -> Derived {}
