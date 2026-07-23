use circuits_bitvec::{BitvecLogic, V64};
use compile_logic::Logic;

use super::constants::{ROTC, ROUNDC};

pub type State<L> = [[V64<L>; 5]; 5];

pub struct Given<L: Logic> {
    pub initial_state: State<L>,
}

pub struct Derived<L: Logic> {
    pub intermediate_states: Vec<State<L>>,
}

pub struct Sha3<'a, L: Logic> {
    pub(crate) logic: &'a L,
    pub bv: BitvecLogic<'a, L>,
}

impl<'a, L: Logic> Sha3<'a, L> {
    pub fn new(logic: &'a L) -> Self {
        Self {
            logic,
            bv: BitvecLogic::new(logic),
        }
    }

    fn theta(&self, a: &State<L>) -> State<L> {
        let mut c0: [V64<L>; 5] = std::array::from_fn(|_| self.bv.zero());
        let mut c1: [V64<L>; 5] = std::array::from_fn(|_| self.bv.zero());

        for x in 0..5 {
            let a01 = self.bv.tree_xorb(&a[x][0], &a[x][1]);
            let a23 = self.bv.tree_xorb(&a[x][2], &a[x][3]);
            c0[x] = self.bv.tree_xorb(&a01, &a23);
            c1[x] = a[x][4].clone();
        }

        let mut next_a = a.clone();
        for x in 0..5 {
            let d0_x = self
                .bv
                .tree_xorb(&c0[(x + 4) % 5], &self.bv.rotl(1, &c0[(x + 1) % 5]));
            let d1_x = self
                .bv
                .tree_xorb(&c1[(x + 4) % 5], &self.bv.rotl(1, &c1[(x + 1) % 5]));
            for val in next_a[x].iter_mut().take(5) {
                *val = self.bv.tree_xorb(val, &d1_x);
                *val = self.bv.tree_xorb(val, &d0_x);
            }
        }
        next_a
    }

    fn rho(&self, a: &State<L>) -> State<L> {
        std::array::from_fn(|x| std::array::from_fn(|y| self.bv.rotl(ROTC[x][y], &a[x][y])))
    }

    fn pi(&self, a: &State<L>) -> State<L> {
        std::array::from_fn(|x| {
            std::array::from_fn(|y| {
                let src = &a[(x + 3 * y) % 5][x];
                self.bv.from_fn(|idx| self.bv.b(src.bit(idx)))
            })
        })
    }

    fn precious(&self, a: &State<L>) -> State<L> {
        std::array::from_fn(|x| std::array::from_fn(|y| self.bv.precious(&a[x][y])))
    }

    fn chi(&self, a: &State<L>) -> State<L> {
        std::array::from_fn(|x| {
            std::array::from_fn(|y| {
                self.bv
                    .chi_laneb(&a[x][y], &a[(x + 1) % 5][y], &a[(x + 2) % 5][y])
            })
        })
    }

    fn iota(&self, t: usize, a: &State<L>) -> State<L> {
        let mut next_a: State<L> = std::array::from_fn(|x| {
            std::array::from_fn(|y| self.bv.from_fn(|idx| self.bv.b(a[x][y].bit(idx))))
        });
        next_a[0][0] = self.bv.tree_xorb(&a[0][0], &self.bv.of_u64(ROUNDC[t]));
        next_a
    }

    pub fn round_without_iota(&self, a: &State<L>) -> State<L> {
        let a_theta = self.theta(a);
        let a_rho = self.rho(&a_theta);
        let a_pi = self.pi(&a_rho);
        let a_precious = self.precious(&a_pi);

        self.chi(&a_precious)
    }

    pub fn round(&self, t: usize, a: &State<L>) -> State<L> {
        let c = self.round_without_iota(a);
        self.iota(t, &c)
    }

    pub fn keccak_f_1600_without_final_iota(&self, a: &State<L>) -> State<L> {
        let mut curr = std::array::from_fn(|x| {
            std::array::from_fn(|y| self.bv.from_fn(|idx| self.bv.b(a[x][y].bit(idx))))
        });
        for t in 0..23 {
            curr = self.round(t, &curr);
        }
        self.round_without_iota(&curr)
    }

    pub fn keccak_f_1600(&self, a: &State<L>) -> State<L> {
        let mut curr = std::array::from_fn(|x| {
            std::array::from_fn(|y| self.bv.from_fn(|idx| self.bv.b(a[x][y].bit(idx))))
        });
        for t in 0..24 {
            curr = self.round(t, &curr);
        }
        curr
    }

    pub fn assert_eq_state(&self, a: &State<L>, b: &State<L>) -> L::Assertions {
        self.logic.assert_mapi("assert_eq_state", 0..25, |idx| {
            let x = idx / 5;
            let y = idx % 5;
            self.bv.assert_eq("state_eq", &a[x][y], &b[x][y])
        })
    }

    pub fn assert_keccak_f_1600(&self, states: &[State<L>]) -> L::Assertions {
        assert_eq!(states.len(), 25);
        let boolean = circuits_boolean::Boolean::new(self.logic);
        self.logic.assert_mapi("assert_keccak_f_1600", 0..24, |t| {
            let next_expected_without_iota = self.round_without_iota(&states[t]);
            let mut rhs = states[t + 1].clone();
            let rc = ROUNDC[t];
            rhs[0][0] = self.bv.from_fn(|idx| {
                let bit = states[t + 1][0][0].bit(idx);
                if (rc.checked_shr(idx as u32).unwrap_or(0) & 1) != 0 {
                    boolean.notb(bit)
                } else {
                    bit.clone()
                }
            });
            self.assert_eq_state(&next_expected_without_iota, &rhs)
        })
    }

    pub fn assert_keccak_f_1600_sliced(
        &self,
        a_init: &State<L>,
        a_intermediates: &[Option<State<L>>],
    ) -> (State<L>, L::Assertions) {
        assert_eq!(a_intermediates.len(), 24);
        let mut curr = std::array::from_fn(|x| {
            std::array::from_fn(|y| self.bv.from_fn(|idx| self.bv.b(a_init[x][y].bit(idx))))
        });
        let boolean = circuits_boolean::Boolean::new(self.logic);
        let assertion = self
            .logic
            .assert_mapi("assert_keccak_f_1600_sliced", 0..24, |t| {
                let next_expected_without_iota = self.round_without_iota(&curr);
                if let Some(ref slice) = a_intermediates[t] {
                    let mut rhs = slice.clone();
                    let rc = ROUNDC[t];
                    rhs[0][0] = self.bv.from_fn(|idx| {
                        let bit = slice[0][0].bit(idx);
                        if (rc.checked_shr(idx as u32).unwrap_or(0) & 1) != 0 {
                            boolean.notb(bit)
                        } else {
                            bit.clone()
                        }
                    });
                    let assertion = self.assert_eq_state(&next_expected_without_iota, &rhs);
                    curr = slice.clone();
                    assertion
                } else {
                    curr = self.iota(t, &next_expected_without_iota);
                    self.logic.ok()
                }
            });
        (curr, assertion)
    }

    pub fn assert_circuit(&self, given: &Given<L>, derived: &Derived<L>) -> L::Assertions {
        let mut states = Vec::with_capacity(25);
        states.push(given.initial_state.clone());
        for s in &derived.intermediate_states {
            states.push(s.clone());
        }
        self.assert_keccak_f_1600(&states)
    }
}
