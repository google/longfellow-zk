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

use circuits_analog_decoder::{AnalogDecoder, BinaryDecoder};
use circuits_bitvec::Bitvec;
use compile_logic::{Eltw, Logic};

pub struct BitPlucker<'a, L: Logic, const LOGN: usize> {
    decoder: BinaryDecoder<'a, L>,
}

impl<'a, L: Logic, const LOGN: usize> BitPlucker<'a, L, LOGN> {
    pub fn new(logic: &'a L) -> Self {
        let analog_decoder = AnalogDecoder::new(logic);
        let decoder = analog_decoder.binary(LOGN);
        Self { decoder }
    }

    /// Extracts a LOGN-bit vector from an encoded field element.
    ///
    /// # Soundness Note
    /// Delegates to `BinaryDecoder::decode`, which evaluates table lookup polynomials for each bit
    /// position and enforces boolean constraints `v * (1 - v) = 0` on every extracted bit.
    pub fn pluck(&self, e: &Eltw<L>) -> Bitvec<L, LOGN> {
        let bits = self.decoder.decode(e);
        Bitvec::new(bits)
    }

    pub fn unpack<const OUT_BITS: usize>(&self, v: &[Eltw<L>]) -> Bitvec<L, OUT_BITS> {
        let mut bits = Vec::with_capacity(OUT_BITS);
        for (i, packed_elt) in v.iter().enumerate() {
            let b = self.pluck(packed_elt);
            for j in 0..LOGN {
                let idx = LOGN * i + j;
                if idx < OUT_BITS {
                    bits.push(b.bit(j).clone());
                }
            }
        }
        Bitvec::new(bits)
    }
}
