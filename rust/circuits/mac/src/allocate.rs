use circuits_bitvec::{BitvecIO, BitvecLogic};
use compile_logic::LogicIO;

use super::circuit::Given;

pub fn allocate_given<L: LogicIO>(bv: &BitvecLogic<L>, pos: &mut usize) -> Given<L> {
    let bitvec_io = BitvecIO::new(bv);
    let message = bitvec_io.next::<256>(pos);
    let mac_av = bitvec_io.next::<128>(pos);
    let mac_ap0 = bitvec_io.next::<128>(pos);
    let mac_ap1 = bitvec_io.next::<128>(pos);
    let tag0 = bitvec_io.next::<128>(pos);
    let tag1 = bitvec_io.next::<128>(pos);
    Given {
        message,
        mac_av,
        mac_ap: [mac_ap0, mac_ap1],
        tag: [tag0, tag1],
    }
}
