use std::cell::Cell;

use core_algebra::SerializableField;
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
use runtime_algebra::{
    gf2_128::Gf2_128RuntimeField, lch14_reed_solomon::Lch14InterpolatorFactory,
    subfield::BinarySubfield, ElementOf, Interpolator, RuntimeField, Subfield, SupportsSampling,
};
use runtime_ligero::{
    LigeroCommitment, LigeroConfig, LigeroError, LigeroLinearConstraint, LigeroParam, LigeroProof,
    LigeroProver, LigeroQuadraticConstraint, LigeroVerifier,
};
use runtime_merkle::Digest;
use runtime_random::{RandomEngine, Transcript};

struct SimpleRng {
    state: u64,
}
impl RandomEngine for SimpleRng {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            buf.push((self.state >> 32) as u8);
        }
        buf
    }
}

struct BadInterpolator<I> {
    real: I,
    should_fail: bool,
    n: usize,
    m: usize,
}

impl<const W: usize, F: RuntimeField<W>, I: Interpolator<W, F>> Interpolator<W, F>
    for BadInterpolator<I>
{
    fn interpolate(&self, y: &mut [F::E]) {
        self.real.interpolate(y);
        if self.should_fail && self.m > self.n {
            let first = y[self.n].clone();
            for i in self.n..self.m - 1 {
                y[i] = y[i + 1].clone();
            }
            y[self.m - 1] = first;
        }
    }
}
struct BadInterpolatorFactory<'a, IF> {
    real: &'a IF,
    calls: std::cell::Cell<usize>,
    should_fail_at: usize,
}

impl<
        const W: usize,
        F: RuntimeField<W>,
        IF: runtime_algebra::interpolator::InterpolatorFactory<W, F>,
    > runtime_algebra::interpolator::InterpolatorFactory<W, F> for BadInterpolatorFactory<'_, IF>
{
    type Interpolator = BadInterpolator<IF::Interpolator>;

    fn make(&self, n: usize, m: usize) -> Self::Interpolator {
        let real = self.real.make(n, m);
        self.calls.set(self.calls.get() + 1);
        let should_fail = self.calls.get() == self.should_fail_at;
        BadInterpolator {
            real,
            should_fail,
            n,
            m,
        }
    }

    fn can_encode(&self, ylen: usize, block_enc: usize) -> bool {
        self.real.can_encode(ylen, block_enc)
    }
}
struct SlowConvolver<'a, const W: usize, F: RuntimeField<W>> {
    f: &'a F,
    y: Vec<F::E>,
}

impl<const W: usize, F: RuntimeField<W>> runtime_algebra::convolution::Convolver<W, F>
    for SlowConvolver<'_, W, F>
{
    fn convolution(&self, x: &[F::E], z: &mut [F::E]) {
        let n = x.len();
        for (k, z_val) in z.iter_mut().enumerate() {
            let s = (0..n).fold(self.f.zero(), |acc, i| {
                if k >= i && (k - i) < self.y.len() {
                    let term = self.f.mulf(&x[i], &self.y[k - i]);
                    self.f.addf(&acc, &term)
                } else {
                    acc
                }
            });
            *z_val = s;
        }
    }
}

struct SlowInterpolator<
    'a,
    const W: usize,
    F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
> {
    rs: runtime_algebra::reed_solomon::ReedSolomon<'a, W, F, SlowConvolver<'a, W, F>>,
}

impl<const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions> Interpolator<W, F>
    for SlowInterpolator<'_, W, F>
{
    fn interpolate(&self, y: &mut [F::E]) {
        self.rs.interpolate(y);
    }
}
struct SlowInterpolatorFactory<
    'a,
    const W: usize,
    F: RuntimeField<W> + core_algebra::SupportsU64Conversions,
> {
    f: &'a F,
}

impl<'a, const W: usize, F: RuntimeField<W> + core_algebra::SupportsU64Conversions>
    runtime_algebra::interpolator::InterpolatorFactory<W, F> for SlowInterpolatorFactory<'a, W, F>
{
    type Interpolator = SlowInterpolator<'a, W, F>;

    fn make(&self, n: usize, m: usize) -> Self::Interpolator {
        let rs = runtime_algebra::reed_solomon::ReedSolomon::new(n, m, self.f, |inverses| {
            SlowConvolver {
                f: self.f,
                y: inverses.to_vec(),
            }
        });
        SlowInterpolator { rs }
    }

    fn can_encode(&self, _ylen: usize, _block_enc: usize) -> bool {
        true
    }
}
#[allow(clippy::too_many_arguments)]
fn ligero_test<
    const W: usize,
    F: RuntimeField<W> + SerializableField + SupportsSampling<W>,
    IF: runtime_algebra::interpolator::InterpolatorFactory<W, F>,
    SF: Subfield<E = ElementOf<F>>,
>(
    make_interpolator: &IF,
    f: &F,
    sf: &SF,
    nw: usize,
    nq: usize,
    nreq: usize,
    nl: usize,
    block_enc: usize,
) {
    let param = LigeroParam::new(
        nw,
        nq,
        LigeroConfig {
            rateinv: 4,
            nreq,
            block_enc,
        },
        &make_interpolator,
    );

    let mut rng = SimpleRng { state: 42 };

    let mut w = vec![f.zero(); nw];
    let mut a = vec![f.zero(); nw];
    for i in 0..nw {
        w[i] = f.sample(|buf| rng.bytes(buf));
        a[i] = f.sample(|buf| rng.bytes(buf));
    }

    let mut lqc = vec![LigeroQuadraticConstraint { x: 0, y: 0, z: 0 }; nq];
    for i in 0..nq {
        lqc[i].z = 2 * i + 1;
        lqc[i].x = 2 * (((rng.state as usize) % nw) / 2);
        rng.state = rng.state.wrapping_add(1);
        lqc[i].y = 2 * (((rng.state as usize) % nw) / 2);
        rng.state = rng.state.wrapping_add(1);
        w[lqc[i].z] = f.mulf(&w[lqc[i].x], &w[lqc[i].y]);
    }

    let mut llterm = Vec::new();
    let mut b = vec![f.zero(); nl];
    for w_idx in 0..nw {
        let term = LigeroLinearConstraint {
            c: w_idx % nl,
            w: w_idx,
            k: a[w_idx].clone(),
        };
        llterm.push(term);
        b[w_idx % nl] = f.subf(&b[w_idx % nl], &f.mulf(&w[w_idx], &a[w_idx]));
    }

    let mut ts_prover = Transcript::new(b"test");
    let (prover, commitment) = LigeroProver::commit(
        0,
        &w,
        param,
        &mut ts_prover,
        &lqc,
        &make_interpolator,
        &mut rng,
        f,
        sf,
    );

    let hash_of_ligero_statement = Digest {
        data: [
            0xba, 0xad, 0xf0, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ],
    };
    let proof = prover.prove(
        &b,
        &mut ts_prover,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        f,
    );

    let mut ts_verifier = Transcript::new(b"test");
    let mut verifier = LigeroVerifier::new(&mut ts_verifier, &param);
    verifier.receive_commitment(&commitment);
    let verify_res = verifier.verify(
        &b,
        &commitment,
        &proof,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        f,
    );
    assert_eq!(verify_res, Ok(()));

    let buf_prover = ts_prover.bytes(256);
    let buf_verifier = ts_verifier.bytes(256);
    assert_eq!(
        buf_prover, buf_verifier,
        "Prover and verifier transcripts differ!"
    );

    let serialized = proof
        .write(&param.geom, f, sf)
        .expect("Failed to serialize LigeroProof");
    let mut r_slice = serialized.as_slice();
    let proof_back = LigeroProof::read(&mut r_slice, &param.geom, f, sf)
        .expect("Failed to deserialize LigeroProof");
    assert!(r_slice.is_empty());

    let mut ts_verifier_back = Transcript::new(b"test");
    let mut verifier_back = LigeroVerifier::new(&mut ts_verifier_back, &param);
    verifier_back.receive_commitment(&commitment);
    let verify_res_back = verifier_back.verify(
        &b,
        &commitment,
        &proof_back,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        f,
    );
    assert_eq!(verify_res_back, Ok(()));

    let buf_verifier_back = ts_verifier_back.bytes(256);
    assert_eq!(
        buf_prover, buf_verifier_back,
        "Prover and verifier_back transcripts differ!"
    );
}

fn test_ligero_verifier_failures_generic<
    const W: usize,
    F: RuntimeField<W> + SerializableField + SupportsSampling<W>,
    IF: runtime_algebra::interpolator::InterpolatorFactory<W, F>,
    SF: Subfield<E = ElementOf<F>>,
>(
    make_interpolator: &IF,
    f: &F,
    sf: &SF,
) {
    let nw = 300;
    let nq = 30;
    let nreq = 18;
    let nl = 7;
    let param = LigeroParam::new(
        nw,
        nq,
        LigeroConfig {
            rateinv: 4,
            nreq,
            block_enc: 256,
        },
        &make_interpolator,
    );

    let mut rng = SimpleRng { state: 100 };

    let mut w = vec![f.zero(); nw];
    let mut a = vec![f.zero(); nw];
    for i in 0..nw {
        w[i] = f.sample(|buf| rng.bytes(buf));
        a[i] = f.sample(|buf| rng.bytes(buf));
    }

    let mut lqc = vec![LigeroQuadraticConstraint { x: 0, y: 0, z: 0 }; nq];
    for i in 0..nq {
        lqc[i].z = 3 * i + 2;
        lqc[i].x = 3 * i;
        lqc[i].y = 3 * i + 1;
        w[lqc[i].z] = f.mulf(&w[lqc[i].x], &w[lqc[i].y]);
    }

    let mut llterm = Vec::new();
    let mut b = vec![f.zero(); nl];
    for w_idx in 0..nw {
        let term = LigeroLinearConstraint {
            c: w_idx % nl,
            w: w_idx,
            k: a[w_idx].clone(),
        };
        llterm.push(term);
        b[w_idx % nl] = f.subf(&b[w_idx % nl], &f.mulf(&w[w_idx], &a[w_idx]));
    }

    let mut ts_prover = Transcript::new(b"test");
    let (prover, commitment) = LigeroProver::commit(
        0,
        &w,
        param,
        &mut ts_prover,
        &lqc,
        &make_interpolator,
        &mut rng,
        f,
        sf,
    );

    let hash_of_ligero_statement = Digest {
        data: [
            0xba, 0xad, 0xf0, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ],
    };
    let proof = prover.prove(
        &b,
        &mut ts_prover,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        f,
    );

    // 1. merkle_check failed
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        let mut bad_comm = commitment.clone();
        bad_comm.root.data[0] ^= 1;
        verifier.receive_commitment(&bad_comm);
        let verify_res = verifier.verify(
            &b,
            &bad_comm,
            &proof,
            &llterm,
            &hash_of_ligero_statement,
            &lqc,
            &make_interpolator,
            f,
        );
        assert!(matches!(verify_res, Err(LigeroError::MerkleCheckFailed(_))));
    }

    // 2. wrong dot product
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let mut bad_b = b.clone();
        bad_b[0] = f.addf(&bad_b[0], &f.one());
        let verify_res = verifier.verify(
            &bad_b,
            &commitment,
            &proof,
            &llterm,
            &hash_of_ligero_statement,
            &lqc,
            &make_interpolator,
            f,
        );
        assert_eq!(verify_res, Err(LigeroError::LinearInnerProductMismatch));
    }

    // 3. dot_check failed
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let mut bad_llterm = llterm.clone();
        bad_llterm[0].k = f.addf(&bad_llterm[0].k, &f.one());
        let verify_res = verifier.verify(
            &b,
            &commitment,
            &proof,
            &bad_llterm,
            &hash_of_ligero_statement,
            &lqc,
            &make_interpolator,
            f,
        );
        assert_eq!(verify_res, Err(LigeroError::DotCheckFailed));
    }

    // 4. low_degree_check failed
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let bad_interpolator = BadInterpolatorFactory {
            real: make_interpolator,
            calls: Cell::new(0),
            should_fail_at: 1,
        };
        let verify_res = verifier.verify(
            &b,
            &commitment,
            &proof,
            &llterm,
            &hash_of_ligero_statement,
            &lqc,
            &bad_interpolator,
            f,
        );
        assert_eq!(verify_res, Err(LigeroError::LowDegreeCheckFailed));
    }

    // 5. quadratic_check failed
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let bad_interpolator = BadInterpolatorFactory {
            real: make_interpolator,
            calls: Cell::new(0),
            should_fail_at: 4,
        };
        let verify_res = verifier.verify(
            &b,
            &commitment,
            &proof,
            &llterm,
            &hash_of_ligero_statement,
            &lqc,
            &bad_interpolator,
            f,
        );
        assert_eq!(verify_res, Err(LigeroError::QuadraticCheckFailed));
    }

    // 6. out of bounds linear constraint fails cleanly without panicking
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let mut bad_llterm = llterm.clone();
        bad_llterm[0].w = nw + 100;
        let verify_res = verifier.verify(
            &b,
            &commitment,
            &proof,
            &bad_llterm,
            &hash_of_ligero_statement,
            &lqc,
            make_interpolator,
            f,
        );
        assert!(matches!(verify_res, Err(LigeroError::InvalidProof(_))));
    }

    // 7. out of bounds quadratic constraint fails cleanly without panicking
    {
        let mut ts = Transcript::new(b"test");
        let mut verifier = LigeroVerifier::new(&mut ts, &param);
        verifier.receive_commitment(&commitment);
        let mut bad_lqc = lqc.clone();
        bad_lqc[0].x = nw + 100;
        let verify_res = verifier.verify(
            &b,
            &commitment,
            &proof,
            &llterm,
            &hash_of_ligero_statement,
            &bad_lqc,
            make_interpolator,
            f,
        );
        assert!(matches!(verify_res, Err(LigeroError::InvalidProof(_))));
    }
}

#[test]
fn test_debug_try_new() {
    let nw_hash = 77998;
    let nq_hash = 20;
    let config_hash = runtime_ligero::param::LigeroConfig {
        rateinv: 7,
        nreq: 132,
        block_enc: 451,
    };
    let gf2_runtime = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let factory =
        runtime_algebra::lch14_reed_solomon::Lch14InterpolatorFactory::new(&gf2_runtime, &subfield);
    let res = runtime_ligero::param::LigeroParam::try_new(nw_hash, nq_hash, config_hash, &factory);
    println!("DEBUG TEST RES: {res:?}");
}

#[test]
fn test_ligero_gf2_128() {
    let f = Gf2_128RuntimeField::new();
    let sf = runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let make_interpolator = Lch14InterpolatorFactory::new(&f, &sf);
    ligero_test(&make_interpolator, &f, &sf, 3000, 300, 189, 7, 4096);
    test_ligero_verifier_failures_generic(&make_interpolator, &f, &sf);
}

#[test]
fn test_ligero_p256() {
    let f = runtime_algebra::p256::P256Field::new();
    let sf = runtime_algebra::p256::P256Subfield::new(&f);
    let make_slow_rs = SlowInterpolatorFactory { f: &f };
    ligero_test(&make_slow_rs, &f, &sf, 300, 30, 18, 7, 256);
    test_ligero_verifier_failures_generic(&make_slow_rs, &f, &sf);
}

#[test]
fn test_cpp_roundtrip_gf2_128() {
    let data = include_bytes!("ligero_test_vector.bin");
    let mut offset = 0;

    let read_u64 = |buf: &[u8], off: &mut usize| {
        let val = u64::from_le_bytes(buf[*off..*off + 8].try_into().unwrap());
        *off += 8;
        val as usize
    };

    let nw = read_u64(data, &mut offset);
    let nq = read_u64(data, &mut offset);
    let nreq = read_u64(data, &mut offset);
    let nl = read_u64(data, &mut offset);
    let subfield_boundary = read_u64(data, &mut offset);

    let f = Gf2_128RuntimeField::new();
    let subfield = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);

    // Read W
    let mut w = Vec::with_capacity(nw);
    for _ in 0..nw {
        let mut slice = &data[offset..];
        let val = runtime_proto::util::read_elt_field(&mut slice, &f).unwrap();
        offset += f.serialized_size_bytes();
        w.push(val);
    }

    // Read A
    let mut a = Vec::with_capacity(nw);
    for _ in 0..nw {
        let mut slice = &data[offset..];
        let val = runtime_proto::util::read_elt_field(&mut slice, &f).unwrap();
        offset += f.serialized_size_bytes();
        a.push(val);
    }

    // Read lqc
    let mut lqc = Vec::with_capacity(nq);
    for _ in 0..nq {
        let x = read_u64(data, &mut offset);
        let y = read_u64(data, &mut offset);
        let z = read_u64(data, &mut offset);
        lqc.push(LigeroQuadraticConstraint { x, y, z });
    }

    // Read llterm
    let llterm_size = read_u64(data, &mut offset);
    let mut llterm = Vec::with_capacity(llterm_size);
    for _ in 0..llterm_size {
        let c = read_u64(data, &mut offset);
        let w_idx = read_u64(data, &mut offset);
        let mut slice = &data[offset..];
        let val = runtime_proto::util::read_elt_field(&mut slice, &f).unwrap();
        offset += f.serialized_size_bytes();
        llterm.push(LigeroLinearConstraint {
            c,
            w: w_idx,
            k: val,
        });
    }

    // Read b
    let mut b = Vec::with_capacity(nl);
    for _ in 0..nl {
        let mut slice = &data[offset..];
        let val = runtime_proto::util::read_elt_field(&mut slice, &f).unwrap();
        offset += f.serialized_size_bytes();
        b.push(val);
    }

    // Read hash_of_ligero_statement
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let hash_of_ligero_statement = Digest { data: hash_bytes };

    // Read commitment root
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let commitment = LigeroCommitment {
        root: Digest { data: root_bytes },
    };

    // Read proof
    let proof_len = read_u64(data, &mut offset);
    let cpp_proof_bytes = &data[offset..offset + proof_len];
    let make_interpolator = Lch14InterpolatorFactory::new(&f, &subfield);
    let param = LigeroParam::new(
        nw,
        nq,
        LigeroConfig {
            rateinv: 4,
            nreq,
            block_enc: 4096,
        },
        &make_interpolator,
    );

    let sf = runtime_algebra::subfield::BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    // 1. Deserialize C++ proof using Rust's reader
    let mut r_slice = cpp_proof_bytes;
    let cpp_proof = LigeroProof::read(&mut r_slice, &param.geom, &f, &sf)
        .expect("Failed to deserialize C++ proof");
    assert!(r_slice.is_empty());

    // 2. Verify the C++ proof using Rust verifier
    let mut ts_verifier = Transcript::new(b"test");
    let mut verifier = LigeroVerifier::new(&mut ts_verifier, &param);
    verifier.receive_commitment(&commitment);
    let verify_res = verifier.verify(
        &b,
        &commitment,
        &cpp_proof,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        &f,
    );
    assert_eq!(verify_res, Ok(()));

    // 3. Generate the proof locally in Rust with same seed (100) and check byte compatibility!
    let mut rng = SimpleRng { state: 100 };
    let mut ts_prover = Transcript::new(b"test");
    let (prover, commitment_rust) = LigeroProver::commit(
        subfield_boundary,
        &w,
        param,
        &mut ts_prover,
        &lqc,
        &make_interpolator,
        &mut rng,
        &f,
        &sf,
    );

    assert_eq!(
        commitment_rust.root.data, commitment.root.data,
        "Commitment roots do not match!"
    );

    let proof_rust = prover.prove(
        &b,
        &mut ts_prover,
        &llterm,
        &hash_of_ligero_statement,
        &lqc,
        &make_interpolator,
        &f,
    );

    let rust_proof_bytes = proof_rust
        .write(&param.geom, &f, &sf)
        .expect("Failed to serialize Rust proof");

    assert_eq!(
        rust_proof_bytes, cpp_proof_bytes,
        "Rust proof bytes do not match C++ proof bytes!"
    );
}
