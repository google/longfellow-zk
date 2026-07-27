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

use circuits_sha256::concrete::{
    derived as sha256_generate_derived, ConcreteDerived as Sha256ConcreteDerived,
    ConcreteGiven as Sha256ConcreteGiven,
};

#[derive(Clone, Debug)]
pub struct ConcreteGiven {
    pub padded_preimage: Vec<u8>,
    pub nblocks: usize,
    pub length_bytes: u64,
    pub expected_hash: [u32; 8],
}

#[derive(Clone, Debug)]
pub struct ConcreteDerived {
    pub sha_derived: Vec<Sha256ConcreteDerived>,
}

pub fn given(
    preimage: &[u8],
    expected_hash: &[u32; 8],
    max_blocks: usize,
) -> Result<ConcreteGiven, String> {
    let (nblocks, length_bytes, padded_preimage) = pad_sha256_message(preimage, max_blocks)?;
    let sha_derived = sha256_msg_derived(&padded_preimage, expected_hash, max_blocks);
    let final_expected_hash = if nblocks > 0 {
        sha_derived[nblocks - 1].h1
    } else {
        *expected_hash
    };
    Ok(ConcreteGiven {
        padded_preimage,
        nblocks,
        length_bytes,
        expected_hash: final_expected_hash,
    })
}

pub fn pad_sha256_message(
    preimage: &[u8],
    max_blocks: usize,
) -> Result<(usize, u64, Vec<u8>), String> {
    let mut padded_preimage: Vec<u8> = preimage.to_vec();
    padded_preimage.push(0x80);
    let mut nblocks = (padded_preimage.len() + 8).div_ceil(64);
    if nblocks > max_blocks {
        return Err(format!(
            "preimage length {} requires {} blocks, which exceeds max_blocks={}",
            preimage.len(),
            nblocks,
            max_blocks
        ));
    }
    if nblocks == 0 {
        nblocks = 1;
    }
    let target_len = nblocks * 64 - 8;
    while padded_preimage.len() < target_len {
        padded_preimage.push(0);
    }

    let length_bits = (preimage.len() as u64) * 8;
    for &byte in &length_bits.to_be_bytes() {
        padded_preimage.push(byte);
    }
    assert_eq!(padded_preimage.len(), nblocks * 64);
    assert!(padded_preimage.len() <= max_blocks * 64);
    padded_preimage.resize(max_blocks * 64, 0);
    let length_bytes = (preimage.len() as u64).to_le();
    Ok((nblocks, length_bytes, padded_preimage))
}

#[must_use]
pub fn sha256_msg_derived(
    padded_preimage: &[u8],
    initial_state: &[u32; 8],
    max_blocks: usize,
) -> Vec<Sha256ConcreteDerived> {
    let mut intermediate_state = *initial_state;
    let mut sha_derived = Vec::with_capacity(max_blocks);
    let nblocks = padded_preimage.len() / 64;
    for i in 0..max_blocks {
        let block: &[u8] = if i < nblocks {
            &padded_preimage[i * 64..(i + 1) * 64]
        } else {
            &[0u8; 64]
        };
        let mut input_block = [0u32; 16];
        for (j, item) in input_block.iter_mut().enumerate() {
            let be = [
                block[j * 4],
                block[j * 4 + 1],
                block[j * 4 + 2],
                block[j * 4 + 3],
            ];
            *item = u32::from_be_bytes(be);
        }
        let given_block = Sha256ConcreteGiven {
            input_block,
            h0: intermediate_state,
        };
        let derived_block = sha256_generate_derived(&given_block);
        intermediate_state = derived_block.h1;
        sha_derived.push(derived_block);
    }
    sha_derived
}

#[must_use]
pub fn derived(given: &ConcreteGiven, max_blocks: usize) -> ConcreteDerived {
    ConcreteDerived {
        sha_derived: sha256_msg_derived(
            &given.padded_preimage,
            &circuits_sha256::constants::INITIAL,
            max_blocks,
        ),
    }
}

impl ConcreteGiven {
    #[cfg(feature = "testonly")]
    pub fn push_elements<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        max_blocks: usize,
        mut push: impl FnMut(FR::E),
    ) {
        // 1. nblocks as bitvec of length max_blocks
        for i in 0..max_blocks {
            let bit = (self.nblocks >> i) & 1 == 1;
            push(if bit { fr.one() } else { fr.zero() });
        }

        // 2. length_bytes as V64
        for i in 0..64 {
            let bit = (self.length_bytes >> i) & 1 == 1;
            push(if bit { fr.one() } else { fr.zero() });
        }

        // 3. padded_preimage (max_blocks * 64 bytes)
        for &byte in &self.padded_preimage {
            for i in 0..8 {
                let bit = (byte >> i) & 1 == 1;
                push(if bit { fr.one() } else { fr.zero() });
            }
        }

        // 4. expected_hash (256 bits)
        for &word in self.expected_hash.iter().rev() {
            for i in 0..32 {
                let bit = (word >> i) & 1 == 1;
                push(if bit { fr.one() } else { fr.zero() });
            }
        }
    }
}

impl ConcreteDerived {
    #[cfg(feature = "testonly")]
    pub fn push_derived<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        mut push: impl FnMut(FR::E),
    ) {
        for wit in &self.sha_derived {
            wit.push_derived(fr, &mut push);
        }
    }

    #[cfg(feature = "testonly")]
    pub fn push_elements<const W: usize, FR: runtime_algebra::field::RuntimeField<W>>(
        &self,
        fr: &FR,
        push: impl FnMut(FR::E),
    ) {
        self.push_derived(fr, push);
    }
}
