#![allow(clippy::needless_range_loop)]
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use sha2::{Digest, Sha256};

use crate::algebra::{Field, Rng};

// ==============================================================================
// FsPrf (AES-256 ECB keystream generator) Implementation
// ==============================================================================

#[derive(Clone)]
pub struct FsPrf {
    _key: [u8; 32],
    cipher: Aes256,
    block_counter: u64,
    read_pointer: usize,
    output_buffer: [u8; 16],
}

impl FsPrf {
    pub fn new(key: [u8; 32]) -> Self {
        let key_arr = GenericArray::from(key);
        let cipher = Aes256::new(&key_arr);
        Self {
            _key: key,
            cipher,
            block_counter: 0,
            read_pointer: 16, /* Force refill on first read (16 instead of Julia's 17 to match
                               * 0-indexed bounds) */
            output_buffer: [0u8; 16],
        }
    }

    fn refill(&mut self) {
        // block_counter is less than MAX_PRF_BLOCKS (0x10000000000)
        assert!(self.block_counter < 0x10000000000);
        let mut inp = [0u8; 16];
        for i in 0..8 {
            inp[i] = ((self.block_counter >> (8 * i)) & 0xff) as u8;
        }
        let mut block = GenericArray::from(inp);
        self.cipher.encrypt_block(&mut block);
        self.output_buffer.copy_from_slice(&block);
        self.block_counter += 1;
        self.read_pointer = 0;
    }

    pub fn get_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            if self.read_pointer >= 16 {
                self.refill();
            }
            buf.push(self.output_buffer[self.read_pointer]);
            self.read_pointer += 1;
        }
        buf
    }
}

// ==============================================================================
// Transcript Implementation
// ==============================================================================

const TAG_BSTR: u8 = 0x00;
const TAG_FIELD_ELEM: u8 = 0x01;
const TAG_ARRAY: u8 = 0x02;

#[derive(Clone)]
pub struct Transcript {
    hash_accumulator: Sha256,
    pseudorandom_generator: Option<FsPrf>,
}

impl Transcript {
    pub fn new(init: &[u8]) -> Self {
        let mut t = Self {
            hash_accumulator: Sha256::new(),
            pseudorandom_generator: None,
        };
        t.write_bytes(init);
        t
    }

    pub fn get_hash(&self) -> [u8; 32] {
        let h = self.hash_accumulator.clone();
        let digest = h.finalize();
        let mut res = [0u8; 32];
        res.copy_from_slice(&digest);
        res
    }

    pub fn write_untyped(&mut self, data: &[u8]) {
        self.pseudorandom_generator = None;
        self.hash_accumulator.update(data);
    }

    pub fn tag(&mut self, tg: u8) {
        self.write_untyped(&[tg]);
    }

    pub fn write_length(&mut self, x: usize) {
        let x_u64 = x as u64;
        let mut len_bytes = [0u8; 8];
        for i in 0..8 {
            len_bytes[i] = ((x_u64 >> (8 * i)) & 0xff) as u8;
        }
        self.write_untyped(&len_bytes);
    }

    pub fn write_bytes(&mut self, data: &[u8]) {
        self.tag(TAG_BSTR);
        self.write_length(data.len());
        self.write_untyped(data);
    }

    pub fn write0(&mut self, n: usize) {
        self.tag(TAG_BSTR);
        self.write_length(n);
        let data = vec![0x00; n];
        self.write_untyped(&data);
    }

    pub fn write_untyped_elt<F: Field>(&mut self, e: F) {
        let b = e.to_bytes();
        self.write_untyped(&b);
    }

    pub fn write_elt_field<F: Field>(&mut self, e: F) {
        self.tag(TAG_FIELD_ELEM);
        self.write_untyped_elt(e);
    }

    pub fn write_elt_field_slice<F: Field>(&mut self, e: &[F]) {
        self.tag(TAG_ARRAY);
        self.write_length(e.len());
        for elt in e {
            self.write_untyped_elt(*elt);
        }
    }

    pub fn get_random_bytes(&mut self, len: usize) -> Vec<u8> {
        if self.pseudorandom_generator.is_none() {
            let key = self.get_hash();
            self.pseudorandom_generator = Some(FsPrf::new(key));
        }
        self.pseudorandom_generator.as_mut().unwrap().get_bytes(len)
    }

    pub fn get_elt_field<F: Field + 'static>(&mut self) -> F {
        F::sample(self)
    }

    pub fn choose(&mut self, n: usize, k: usize) -> Vec<usize> {
        if n == 0 || k == 0 {
            return Vec::new();
        }
        assert!(n >= k);
        let mut a: Vec<usize> = (0..n).collect();
        let mut res = vec![0; k];
        for i in 0..k {
            let val = self.nat(n - i);
            let j = i + val;
            a.swap(i, j);
            res[i] = a[i];
        }
        res
    }

    pub fn nat(&mut self, n: usize) -> usize {
        assert!(n > 0, "nat(0) is undefined");
        let mut nn = n;
        let mut l = 0;
        while nn != 0 {
            nn >>= 8;
            l += 1;
        }
        let mut msk = 0;
        while (n & msk) != n {
            msk = (msk << 1) | 1;
        }

        loop {
            let b = self.bytes(l);
            let mut r = 0usize;
            for i in (0..l).rev() {
                r = (r << 8) | (b[i] as usize);
            }
            r &= msk;
            if r < n {
                return r;
            }
        }
    }
}

impl Rng for Transcript {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        self.get_random_bytes(len)
    }
}
