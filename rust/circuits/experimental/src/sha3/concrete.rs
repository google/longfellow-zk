use super::constants::{ROTC, ROUNDC};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcreteGiven {
    pub initial_state: [[u64; 5]; 5],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcreteDerived {
    pub intermediate_states: Vec<[[u64; 5]; 5]>,
}

/// Simulates the Keccak-f[1600] permutation using native Rust u64 arithmetic,
/// returning the complete 25-state trajectory.
#[must_use]
pub fn keccak_f_1600_trajectory(mut state: [[u64; 5]; 5]) -> [[[u64; 5]; 5]; 25] {
    let mut states = [[[0u64; 5]; 5]; 25];
    states[0] = state;
    for t in 0..24 {
        // 1. Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        let mut theta_state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                theta_state[x][y] = state[x][y] ^ d[x];
            }
        }

        // 2. Rho & Pi
        let mut rho_pi_state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                let r = ROTC[x][y];
                rho_pi_state[y][(2 * x + 3 * y) % 5] = theta_state[x][y].rotate_left(r as u32);
            }
        }

        // 3. Chi
        let mut chi_state = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                chi_state[x][y] = rho_pi_state[x][y]
                    ^ ((!rho_pi_state[(x + 1) % 5][y]) & rho_pi_state[(x + 2) % 5][y]);
            }
        }

        // 4. Iota
        chi_state[0][0] ^= ROUNDC[t];

        state = chi_state;
        states[t + 1] = state;
    }
    states
}

#[must_use]
pub fn given(initial_state: [[u64; 5]; 5]) -> ConcreteGiven {
    ConcreteGiven { initial_state }
}

#[must_use]
pub fn derived(given: &ConcreteGiven) -> ConcreteDerived {
    let all_states = keccak_f_1600_trajectory(given.initial_state);
    ConcreteDerived {
        intermediate_states: all_states[1..25].to_vec(),
    }
}

impl ConcreteGiven {
    #[cfg(feature = "testonly")]
    pub fn push_wires<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        dest: &mut Vec<FR::E>,
    ) {
        for x in 0..5 {
            for y in 0..5 {
                circuits_bitvec::concrete::push_bitvec_u64(fr, self.initial_state[x][y], 64, dest);
            }
        }
    }

    #[cfg(feature = "testonly")]
    pub fn push_elements<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        mut push: impl FnMut(FR::E),
    ) {
        let mut dest = Vec::new();
        self.push_wires(fr, &mut dest);
        for e in dest {
            push(e);
        }
    }
}

impl ConcreteDerived {
    #[cfg(feature = "testonly")]
    pub fn push_wires<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        dest: &mut Vec<FR::E>,
    ) {
        for state in &self.intermediate_states {
            for row in state {
                for &val in row {
                    circuits_bitvec::concrete::push_bitvec_u64(fr, val, 64, dest);
                }
            }
        }
    }

    #[cfg(feature = "testonly")]
    pub fn push_elements<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        mut push: impl FnMut(FR::E),
    ) {
        let mut dest = Vec::new();
        self.push_wires(fr, &mut dest);
        for e in dest {
            push(e);
        }
    }
}
