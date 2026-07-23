// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use runtime_algebra::{Subfield, SupportsSampling};

pub mod transcript;
pub use transcript::Transcript;

/// Trait defining operations for seedable/pseudorandom challenge engines.
pub trait RandomEngine {
    /// Generates raw pseudorandom bytes of the specified length.
    fn bytes(&mut self, len: usize) -> Vec<u8>;

    /// Generates a random field element.
    fn elt_field<const W: usize, F: SupportsSampling<W>>(&mut self, f: &F) -> F::E {
        f.sample(|len| self.bytes(len))
    }

    /// Generates a random subfield element.
    fn elt_subfield<SF: Subfield>(&mut self, sf: &SF) -> SF::E {
        sf.sample(|len| self.bytes(len))
    }

    /// Generates a slice of field elements with random values.
    fn elt_field_slice<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        len: usize,
        f: &F,
    ) -> Vec<F::E> {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(self.elt_field(f));
        }
        v
    }

    /// Generates a random u128.
    fn u128(&mut self) -> u128 {
        let buf = self.bytes(16);
        u128::from_le_bytes(buf.try_into().unwrap())
    }

    /// Generates a random integer in `[0, n)`.
    fn nat(&mut self, n: usize) -> usize {
        assert!(n > 0, "nat(0) is undefined");
        let mut nn = n;
        let mut l = 0;
        while nn != 0 {
            nn >>= 8;
            l += 1;
        }
        assert!(l <= std::mem::size_of::<usize>());

        let msk = self.mask(n);

        loop {
            let buf = self.bytes(l);
            let mut r = 0usize;
            for i in (0..l).rev() {
                r = (r << 8) | (buf[i] as usize);
            }
            r &= msk;
            if r < n {
                return r;
            }
        }
    }

    /// Chooses `k` unique indices from `[0, n)` randomly.
    fn choose(&mut self, res: &mut [usize], n: usize, k: usize) {
        if n == 0 || k == 0 {
            return;
        }
        assert!(n >= k && res.len() >= k);
        let mut a: Vec<usize> = (0..n).collect();
        let res_slice = &mut res[..k];
        let a_slice = &mut a[..n];
        for i in 0..k {
            let j = (i + self.nat(n - i)) % n;
            a_slice.swap(i, j);
            res_slice[i] = a_slice[i];
        }
    }

    /// Computes the bit mask for a value `n`.
    fn mask(&self, n: usize) -> usize {
        let mut msk = 0usize;
        while (n & msk) != n {
            msk = (msk << 1) | 1;
        }
        msk
    }
}

pub mod secure;
pub use secure::SecureRandomEngine;

#[cfg(feature = "testonly")]
pub mod deterministic;
#[cfg(feature = "testonly")]
pub use deterministic::DeterministicRng;
