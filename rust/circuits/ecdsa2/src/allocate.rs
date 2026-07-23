use compile_logic::LogicIO;

use super::circuit::{Derived, Given, Slicing};

pub fn allocate_given_wires<L: LogicIO>(logic: &L, pos: &mut usize) -> Given<L> {
    let pkxy = (logic.next(pos), logic.next(pos));
    let e = logic.next(pos);
    let rxy = (logic.next(pos), logic.next(pos));
    let ers = std::array::from_fn(|_| logic.next(pos));
    Given { pkxy, e, rxy, ers }
}

pub fn allocate_derived_wires<L: LogicIO>(logic: &L, pos: &mut usize) -> Derived<L> {
    let pkxinv = logic.next(pos);
    let rxinv = logic.next(pos);
    let nmsinv = logic.next(pos);
    let yinv = logic.next(pos);

    let g_pk = (logic.next(pos), logic.next(pos));
    let g_r = (logic.next(pos), logic.next(pos));
    let pk_r = (logic.next(pos), logic.next(pos));
    let g_pk_r = (logic.next(pos), logic.next(pos));

    let round = std::array::from_fn(|_| (logic.next(pos), logic.next(pos), logic.next(pos)));

    Derived {
        pkxinv,
        rxinv,
        nmsinv,
        yinv,
        slicing: Slicing {
            g_pk,
            g_r,
            pk_r,
            g_pk_r,
            round,
        },
    }
}
