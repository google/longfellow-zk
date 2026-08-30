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

use std::{
    fs::File,
    io::{BufReader, Cursor},
    path::PathBuf,
};

use reference::{
    algebra::{Field, Gf2_128},
    circuit::{parse_lfc2_bytes, Circuit},
    ligero::{read_ligero_proof, LigeroConfig, LigeroGeometry},
};

fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

fn header_nv(nv: u64, nl: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"LFC2");
    b.extend(uleb(2)); // field_id
    b.extend(uleb(nv)); // nv
    b.extend(uleb(0)); // discarded
    b.extend(uleb(0)); // npub_in
    b.extend(uleb(0)); // subfield_boundary
    b.extend(uleb(0)); // ninput
    b.extend(uleb(nl)); // nl
    b
}

fn header(nl: u64) -> Vec<u8> {
    header_nv(2, nl)
}

fn parse(bytes: &[u8]) -> std::io::Result<Circuit<Gf2_128>> {
    let mut cur: &[u8] = bytes;
    parse_lfc2_bytes::<Gf2_128, _>(&mut cur)
}

// An unbounded constant count fed to Vec::with_capacity is rejected instead of aborting.
#[test]
fn unbounded_constant_count_rejected() {
    let mut b = header(0);
    b.extend(uleb(u64::MAX));
    assert!(parse(&b).is_err());
}

// A token indexing segments out of range is rejected instead of panicking.
#[test]
fn out_of_range_token_index_rejected() {
    let mut b = header(1);
    b.extend(uleb(0)); // num_const
    b.extend(uleb(1)); // logw
    b.extend(uleb(2)); // nw
    b.extend(uleb(0)); // num_deltas
    b.extend(uleb(1)); // num_segments
    b.extend(uleb(0)); //   seg_len
    b.extend(uleb(1)); // token_len
    b.extend(uleb(5)); //   token = 5 -> segments[5]
    assert!(parse(&b).is_err());
}

// A segment entry indexing deltas out of range is rejected instead of panicking.
#[test]
fn out_of_range_delta_index_rejected() {
    let mut b = header(1);
    b.extend(uleb(0)); // num_const
    b.extend(uleb(1)); // logw
    b.extend(uleb(2)); // nw
    b.extend(uleb(1)); // num_deltas = 1
    b.extend(uleb(0)); // g
    b.extend(uleb(0)); // h0
    b.extend(uleb(0)); // h1
    b.extend(uleb(0)); // k_index
    b.extend(uleb(1)); // num_segments = 1
    b.extend(uleb(1)); //   seg_len = 1
    b.extend(uleb(9)); //     seg[0] = 9 -> deltas[9]
    b.extend(uleb(1)); // token_len = 1
    b.extend(uleb(0)); //   token = 0
    assert!(parse(&b).is_err());
}

// A delta k_index indexing constants out of range is rejected instead of panicking.
#[test]
fn out_of_range_constant_index_rejected() {
    let mut b = header(1);
    b.extend(uleb(1)); // num_const = 1
    b.extend(vec![0u8; Gf2_128::serialized_size()]); // one zero constant
    b.extend(uleb(1)); // logw
    b.extend(uleb(2)); // nw
    b.extend(uleb(1)); // num_deltas = 1
    b.extend(uleb(0)); // g
    b.extend(uleb(0)); // h0
    b.extend(uleb(0)); // h1
    b.extend(uleb(7)); // k_index = 7
    b.extend(uleb(1)); // num_segments = 1
    b.extend(uleb(1)); //   seg_len = 1
    b.extend(uleb(0)); //     seg[0] = 0
    b.extend(uleb(1)); // token_len = 1
    b.extend(uleb(0)); //   token = 0 -> constants[7]
    assert!(parse(&b).is_err());
}

// An output count whose ceil_lg2 exceeds MAX_LOGW is rejected at parse instead of panicking
// downstream on the fixed-size challenge vector.
#[test]
fn oversized_output_count_rejected() {
    let b = header_nv((1u64 << 40) + 1, 0);
    assert!(parse(&b).is_err());
}

// Bad magic header is rejected instead of panicking.
#[test]
fn magic_header_rejected() {
    assert!(parse(b"XXXX").is_err());
}

// Overlong ULEB128 (shift past 64 bits) is rejected instead of panicking/wrapping.
#[test]
fn uleb128_overlong_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(b"LFC2");
    b.extend(std::iter::repeat(0x80u8).take(11)); // field_id: 11 continuation bytes
    assert!(parse(&b).is_err());
}

// Per-layer logw > MAX_LOGW is rejected instead of overflowing fixed-size arrays downstream.
#[test]
fn layer_logw_rejected() {
    let mut b = header(1);
    b.extend(uleb(0)); // num_const
    b.extend(uleb(41)); // logw = MAX_LOGW + 1
    assert!(parse(&b).is_err());
}

// An input count over MAX_WIRES is rejected instead of feeding an unbounded Vec::with_capacity.
#[test]
fn oversized_input_count_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(b"LFC2");
    b.extend(uleb(2)); // field_id
    b.extend(uleb(2)); // nv
    b.extend(uleb(0)); // discarded
    b.extend(uleb(0)); // npub_in
    b.extend(uleb(0)); // subfield_boundary
    b.extend(uleb(5_000_001)); // ninput = MAX_WIRES + 1
    assert!(parse(&b).is_err());
}

// npublic_input > ninput is rejected instead of underflowing ninput - npublic_input.
#[test]
fn npublic_input_gt_ninput_rejected() {
    let mut b = Vec::new();
    b.extend_from_slice(b"LFC2");
    b.extend(uleb(2)); // field_id
    b.extend(uleb(2)); // nv
    b.extend(uleb(0)); // discarded
    b.extend(uleb(5)); // npub_in
    b.extend(uleb(0)); // subfield_boundary
    b.extend(uleb(0)); // ninput = 0 < npub_in
    assert!(parse(&b).is_err());
}

// Expanded term count is bounded, so a small circuit cannot expand to an OOM.
// Reaching the cap allocates ~1 GiB; run explicitly with `cargo test -- --ignored`.
#[test]
#[ignore]
fn expanded_terms_rejected() {
    let mut b = header(1);
    b.extend(uleb(1)); // num_const = 1
    b.extend(vec![0u8; Gf2_128::serialized_size()]); // one zero constant
    b.extend(uleb(1)); // logw
    b.extend(uleb(2)); // nw
    b.extend(uleb(1)); // num_deltas = 1
    b.extend(uleb(0)); // g
    b.extend(uleb(0)); // h0
    b.extend(uleb(0)); // h1
    b.extend(uleb(0)); // k_index
    b.extend(uleb(1)); // num_segments = 1
    b.extend(uleb(1)); //   seg_len = 1
    b.extend(uleb(0)); //     seg[0] = 0
    let ntok: u64 = 20_000_001; // MAX_TERMS_PER_LAYER + 1 tokens all pointing at segment 0
    b.extend(uleb(ntok));
    for _ in 0..ntok {
        b.extend(uleb(0));
    }
    assert!(parse(&b).is_err());
}

// An attacker-controlled num_paths is rejected against the trusted geometry before allocating.
#[test]
fn unbounded_merkle_path_count_rejected() {
    let config = LigeroConfig::default();

    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/sha256_circuit.lfc2");
    let mut circuit_reader = BufReader::new(File::open(path).expect("open circuit"));
    let circuit =
        parse_lfc2_bytes::<Gf2_128, _>(&mut circuit_reader).expect("parse circuit");

    let sf = <Gf2_128 as Field>::Subfield::default();

    let witness_only_len = circuit.ninput - circuit.npublic_input;
    let mut pad_witness_len = 3 * circuit.layers.len();
    for layer in &circuit.layers {
        pad_witness_len += 4 * layer.logw;
    }
    let nw = witness_only_len + pad_witness_len;
    let nq = circuit.layers.len();
    let geom = LigeroGeometry::new(&config, nw, nq);

    let mut stream = Vec::new();
    for _ in 0..geom.block_len {
        stream.extend_from_slice(&[0u8; 16]);
    }
    for _ in 0..geom.dblock_len {
        stream.extend_from_slice(&[0u8; 16]);
    }
    for _ in 0..geom.num_queries {
        stream.extend_from_slice(&[0u8; 16]);
    }
    for _ in 0..(geom.dblock_len - geom.block_len) {
        stream.extend_from_slice(&[0u8; 16]);
    }
    for _ in 0..geom.num_queries {
        stream.extend_from_slice(&[0u8; 32]);
    }

    // One RLE run covering every requested element, so the reader reaches num_paths.
    let total_req_elts = geom.total_rows * geom.num_queries;
    stream.extend_from_slice(&(total_req_elts as u32).to_le_bytes());
    for _ in 0..total_req_elts {
        stream.extend_from_slice(&[0u8; 16]);
    }

    // num_paths = u32::MAX must be rejected before Vec::with_capacity.
    stream.extend_from_slice(&u32::MAX.to_le_bytes());

    let mut cursor = Cursor::new(stream);
    let result = read_ligero_proof::<Gf2_128, _>(&mut cursor, &config, &circuit, &sf);
    assert!(result.is_err());
}
