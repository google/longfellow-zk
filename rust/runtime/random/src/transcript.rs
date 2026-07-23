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

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use core_algebra::{ElementOf, SerializableField};
use sha2::{Digest, Sha256};

use crate::RandomEngine;

/// The tag for raw byte arrays/strings in transcript formatting.
const TAG_BSTR: u8 = 0;

/// The tag for field elements in transcript formatting.
const TAG_FIELD_ELEM: u8 = 1;

/// The tag for array elements in transcript formatting.
const TAG_ARRAY: u8 = 2;

/// The maximum number of PRF blocks that can be generated (2^40 blocks).
const MAX_PRF_BLOCKS: u64 = 0x10000000000;

/// A transcript accumulator for Fiat-Shamir non-interactive proofs.
///
/// It digests all prover messages sequentially using a SHA-256 hasher,
/// prepending each input with a tag and a length prefix. This structured format
/// prevents length-extension attacks and ensures canonical serialization.
///
/// It also implements `RandomEngine` to act as a cryptographically secure
/// pseudorandom generator, seeding itself with the accumulated hash state.
pub struct Transcript {
    /// SHA-256 hasher holding the current transcript state.
    hash_accumulator: Sha256,
    /// Cached pseudorandom generator instantiated from the transcript hash.
    /// Resets/invalidated on every subsequent write.
    pseudorandom_generator: Option<FsPrf>,
}

impl Transcript {
    /// Instantiates a new transcript initialized with a prefix byte slice.
    #[must_use]
    pub fn new(init: &[u8]) -> Self {
        let mut t = Self {
            hash_accumulator: Sha256::new(),
            pseudorandom_generator: None,
        };
        t.write_bytes(init);
        t
    }

    /// Computes and returns the 32-byte hash digest of the current transcript
    /// state.
    fn get_hash(&self) -> [u8; 32] {
        let tmp_hash = self.hash_accumulator.clone();
        let digest = tmp_hash.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }

    /// Appends a raw byte slice to the transcript with a byte-string tag and
    /// length prefix.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.tag(TAG_BSTR);
        self.length(data.len());
        self.write_untyped(data);
    }

    /// Appends a series of zero bytes of the specified length.
    pub fn write0(&mut self, mut n: usize) {
        self.tag(TAG_BSTR);
        self.length(n);
        const BUF_SIZE: usize = 8192;
        let data = [0u8; BUF_SIZE];
        while n >= BUF_SIZE {
            self.write_untyped(&data);
            n -= BUF_SIZE;
        }
        if n > 0 {
            self.write_untyped(&data[..n]);
        }
    }

    /// Appends a single field element to the transcript.
    pub fn write_elt_field<F: SerializableField>(&mut self, e: &ElementOf<F>, f: &F) {
        self.tag(TAG_FIELD_ELEM);
        self.write_untyped_elt(e, f);
    }

    /// Appends a slice of field elements to the transcript.
    pub fn write_elt_field_slice<F: SerializableField>(&mut self, e: &[ElementOf<F>], f: &F) {
        let n = e.len();
        self.tag(TAG_ARRAY);
        self.length(n);
        for elt in e {
            self.write_untyped_elt(elt, f);
        }
    }

    /// Appends a structural tag to the transcript.
    fn tag(&mut self, t: u8) {
        self.write_untyped(&[t]);
    }

    /// Appends a little-endian length prefix to the transcript.
    fn length(&mut self, x: usize) {
        self.write_untyped(&(x as u64).to_le_bytes());
    }

    /// Updates the hasher directly, invalidating the cached PRF generator.
    fn write_untyped(&mut self, data: &[u8]) {
        self.pseudorandom_generator = None;
        self.hash_accumulator.update(data);
    }

    /// Serializes a field element and updates the hasher.
    fn write_untyped_elt<F: SerializableField>(&mut self, e: &ElementOf<F>, f: &F) {
        let len = f.serialized_size_bytes();
        let mut buf = [0u8; 128];
        f.to_bytes_into(e, &mut buf[..len]);
        self.write_untyped(&buf[..len]);
    }
}

impl Clone for Transcript {
    /// Clones the transcript state, preserving any active PRNG state.
    fn clone(&self) -> Self {
        Self {
            hash_accumulator: self.hash_accumulator.clone(),
            pseudorandom_generator: self.pseudorandom_generator.clone(),
        }
    }
}

impl RandomEngine for Transcript {
    /// Generates pseudorandom bytes from the current transcript hash.
    /// If the transcript is modified, the PRF engine will be re-seeded.
    ///
    /// # Soundness & Fiat-Shamir Design Note
    /// Under the standard Fiat-Shamir transform, random challenges are derived deterministically as
    /// a hash of public inputs and all preceding prover messages. Generated challenge bytes do not
    /// need to be re-absorbed into the hash accumulator because challenge output is already a
    /// deterministic function of prior prover state.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        if self.pseudorandom_generator.is_none() {
            let key = self.get_hash();
            self.pseudorandom_generator = Some(FsPrf::new(&key));
        }
        self.pseudorandom_generator.as_mut().unwrap().bytes(len)
    }
}

/// AES-256 block cipher pseudorandom function.
#[derive(Clone)]
struct Prf {
    aes_cipher: Aes256,
}

impl Prf {
    /// Instantiates a new PRF from a 32-byte key.
    fn new(key: &[u8; 32]) -> Self {
        let key_array = GenericArray::from_slice(key);
        let aes_cipher = Aes256::new(key_array);
        Self { aes_cipher }
    }

    /// Evaluates the PRF on a 16-byte input block.
    fn eval(&self, out: &mut [u8; 16], inp: &[u8; 16]) {
        let mut block = GenericArray::clone_from_slice(inp);
        self.aes_cipher.encrypt_block(&mut block);
        out.copy_from_slice(&block);
    }
}

/// Fiat-Shamir pseudorandom function generator.
#[derive(Clone)]
struct FsPrf {
    cipher_engine: Prf,
    block_counter: u64,
    read_pointer: usize,
    output_buffer: [u8; 16],
}

impl FsPrf {
    /// Instantiates a new generator from a 32-byte key.
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher_engine: Prf::new(key),
            block_counter: 0,
            read_pointer: 16,
            output_buffer: [0u8; 16],
        }
    }

    /// Fills the output buffer with pseudorandom bytes.
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            if self.read_pointer == 16 {
                self.refill();
            }
            buf.push(self.output_buffer[self.read_pointer]);
            self.read_pointer += 1;
        }
        buf
    }

    /// Refills the internal buffer of random bytes by evaluating the PRF on the
    /// next block number.
    fn refill(&mut self) {
        assert!(self.block_counter < MAX_PRF_BLOCKS, "too many blocks");
        let mut inp = [0u8; 16];
        inp[..8].copy_from_slice(&self.block_counter.to_le_bytes());
        self.cipher_engine.eval(&mut self.output_buffer, &inp);
        self.block_counter += 1;
        self.read_pointer = 0;
    }
}
