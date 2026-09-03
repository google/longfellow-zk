The Fiat-Shamir transform is a method for generating a verifier's public-coin challenges by processing the concatenation of all preceding prover messages. The transform is proven to be sound when applied to an interactive protocol that is round-by-round sound and when the oracle is implemented with a hash function satisfying correlation-intractability with respect to the relation's verification state function (see [@rbr]).

While standard Sigma protocols operate in a single round with scalar challenges, Interactive Oracle Proofs (IOPs) such as Longfellow require structured, multi-round transcripts with typed messages (byte strings, field elements, arrays of field elements) and multi-challenge extractions (such as combinations without replacement for column queries and subfield elements).


<reference anchor='rbr' target='https://eprint.iacr.org/2018/1004'>
    <front>
        <title>Fiat-Shamir From Simpler Assumptions</title>
        <author initials='R.' surname='Canetti' fullname='Ran Canetti'>
        </author>
        <author initials='Y.' surname='Chen' fullname='Yilei Chen'>
        </author>
        <author initials='J.' surname='Holmgren' fullname='Justin Holmgren'>
        </author>
        <author initials='A.' surname='Lombardi' fullname='Alex Lombardi'>
        </author>
        <author initials='G.' surname='Rothblum' fullname='Guy N. Rothblum'>
        </author>
        <author initials='R.' surname='Rothblum' fullname='Ron D. Rothblum'>
        </author>
        <date year='2018'/>
    </front>
</reference>

## The Hash-and-Expand Duplex Sponge Instantiation {#suite-hash-and-expand}

The transcript is modeled as a stateful object maintaining an internal string `tr` (or incrementally updated hash state) and a pseudorandom stream generator. In the `SHA256-AES256CTR` ciphersuite:

1. Absorb: Prover messages are appended to `tr` using the Universal ZK TLV Codec.
2. Squeeze: When a verifier challenge is requested, the transcript derives a 32-byte key $\text{SEED} = H(\text{tr})$ using SHA-256. This seed initializes a Fiat-Shamir Pseudorandom Function (`FsPrf`) running AES-256 in counter mode.

### The FSPRF Keystream Generator

The `FsPrf` object generates an infinite sequence of pseudorandom bytes organized into 16-byte blocks. Block $i$ (for $i \ge 0$) is computed as:
```
  Block[i] = AES256(SEED, ID(i))
```
where `SEED` is the 32-byte hash digest $H(\text{tr})$, and `ID(i)` is the 16-byte little-endian encoding of integer $i$.

``` rust
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use sha2::{Digest, Sha256};
use crate::algebra::{Field, Rng};

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
            read_pointer: 16, // Force refill on first read
            output_buffer: [0u8; 16],
        }
    }

    fn refill(&mut self) {
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
```

## Universal ZK TLV Codec {#encoding-tlv}

To ensure prefix-free and unambiguous parsing of multi-round interactive oracle proofs, all prover messages absorbed by the transcript are framed with explicit type tags:

* Byte Array (`TAG_BSTR = 0x00`): Serialized as the 1-byte tag `0x00`, followed by an 8-byte little-endian length prefix, followed by the raw bytes:
  ```
  0x00 || len_le_u64 || bytes
  ```

* Field Element (`TAG_FIELD_ELEM = 0x01`): Serialized as the 1-byte tag `0x01`, followed directly by the canonical byte serialization of the field element (length is fixed by the field definition):
  ```
  0x01 || canonical_field_bytes
  ```

* Field Element Array (`TAG_ARRAY = 0x02`): Serialized as the 1-byte tag `0x02`, followed by an 8-byte little-endian count prefix, followed by the concatenated canonical byte serializations of all field elements:
  ```
  0x02 || count_le_u64 || elt_0_bytes || ... || elt_{n-1}_bytes
  ```

``` rust
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
}
```

## Correlation-Intractability and Computational Depth {#correlation-intractability}

The security of the Fiat-Shamir transformation relies on correlation intractability. When proving arbitrary circuit satisfiability or recursive statements, a malicious prover might attempt self-referential attacks if the circuit's complexity exceeds the depth required to compute the random oracle.

To prevent self-referential attacks (see [@krs]), the first prover message in Longfellow enforces that the oracle's computational depth exceeds the verification logic of circuit $C$:

1. Absorb the initial prover commitment (`session_id` and initial matrix commitment root).
2. Absorb the statement encoding: circuit identifier `id`, public inputs, and outputs.
3. Absorb $0^{|C|}$ via `write0(|C|)` (a byte array of $|C|$ zero bytes, where $|C|$ is the gate count of the circuit).

<reference anchor='krs' target='https://eprint.iacr.org/2025/118'>
    <front>
        <title>How to Prove False Statements: Practical Attacks on Fiat-Shamir</title>
        <author initials='D.' surname='Khovratovich' fullname='Dmitry Khovratovich'>
        </author>
        <author initials='R. D.' surname='Rothblum' fullname='Ron D. Rothblum'>
        </author>
        <author initials='L.' surname='Soukhanov' fullname='Lev Soukhanov'>
        </author>
        <date year='2025'/>
    </front>
</reference>

## Challenge Extraction Methods {#decoding}

In the CFRG Fiat-Shamir framework ([@I-D.irtf-cfrg-fiat-shamir#03]), challenge extraction is formalized as the decoding component of a *codec*. While the codec's `prover_message` procedure serializes and absorbs prover messages into the sponge state, its `verifier_challenge` procedure squeezes uniformly distributed pseudorandom bytes and decodes them into the verifier's target challenge domain.

For Interactive Oracle Proofs, the codec defines four decoding procedures that translate the raw byte stream into structured verifier challenges:

### 1. Bounded Natural Numbers (`generate_nat` / `nat`) {#decoding-bounded-uint}

Samples a uniformly distributed integer in $[0, m - 1]$ via minimal bitmask rejection sampling:

``` rust
impl Transcript {
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
```

### 2. Combinations Without Replacement (`generate_nats_wo_replacement` / `choose`) {#decoding-sample-distinct}

Samples $k$ distinct natural numbers uniformly from $[0, n - 1]$ without replacement (used for Ligero column query indices) using an in-place Fisher-Yates shuffle:

``` rust
impl Transcript {
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
}
```

### 3. Field Elements and Vectors (`generate_field` / `generate_challenge`) {#decoding-field}

* Prime Fields (e.g. NIST P-256 scalar field $\mathbb{F}_p$): Samples 32 bytes from `bytes(32)` and rejects if the integer value $\ge p$.
* Binary Extension Fields (e.g. $\text{GF}(2^{128})$): Samples 16 bytes directly from `bytes(16)` and interprets them as the polynomial coefficients in $\text{GF}(2)[X]/(X^{128} + X^7 + X^2 + X + 1)$. Subfield elements in $\text{GF}(2^{16})$ sample 2 bytes from `bytes(2)` and map to the subfield basis.

``` rust
impl Transcript {
    pub fn get_elt_field<F: Field + 'static>(&mut self) -> F {
        F::sample(self)
    }

    pub fn generate_challenge<F: Field + 'static>(&mut self, n: usize) -> Vec<F> {
        (0..n).map(|_| self.get_elt_field::<F>()).collect()
    }
}

impl Rng for Transcript {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        self.get_random_bytes(len)
    }
}
```