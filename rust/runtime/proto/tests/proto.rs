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

use core_algebra::{AlgebraicField, SupportsU64Conversions};
use runtime_algebra::p256::P256Field;
use runtime_proto::{
    ligero::{LigeroCommitment, LigeroGeometry, LigeroProof},
    merkle::{Digest, MerkleNonce, MerkleProof},
    sumcheck::{LayerProof, RoundPoly, SumcheckProof, SumcheckProofGeometry},
    util::{
        read_elt_field, read_size_4bytes, read_subfield_elt, write_elt_field, write_size_4bytes,
        write_subfield_elt, zero_field_element,
    },
    zk::{ZkProof, ZkProofGeometry},
};

#[test]
fn test_util_read_write_elt_field() {
    let f = P256Field::new();
    let val = f.u64_to_element(123456789u64);

    let mut buf = Vec::new();
    write_elt_field(&mut buf, &val, &f);
    let mut r_slice = buf.as_slice();
    let decoded = read_elt_field(&mut r_slice, &f).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, val);
}

#[test]
fn test_util_read_write_size_4bytes() {
    let mut buf = Vec::new();
    write_size_4bytes(&mut buf, 123456);
    let mut r_slice = buf.as_slice();
    let decoded = read_size_4bytes(&mut r_slice).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, 123456);
}

#[test]
fn test_util_read_write_subfield_elt() {
    let f = P256Field::new();
    let sf = runtime_algebra::p256::P256Subfield::new(&f);
    let val = f.u64_to_element(987654321u64);

    let mut buf = Vec::new();
    write_subfield_elt(&mut buf, &val, &sf).unwrap();
    let mut r_slice = buf.as_slice();
    let decoded = read_subfield_elt(&mut r_slice, &sf).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, val);
}

#[test]
fn test_util_zero_field_element() {
    let f = P256Field::new();
    let zero = zero_field_element(&f).unwrap();
    assert_eq!(zero, f.zero());
}

#[test]
fn test_merkle_proof_read_write() {
    let proof = MerkleProof {
        nonce: vec![
            MerkleNonce { bytes: [1u8; 32] },
            MerkleNonce { bytes: [2u8; 32] },
        ],
        path: vec![
            Digest { data: [3u8; 32] },
            Digest { data: [4u8; 32] },
            Digest { data: [5u8; 32] },
            Digest { data: [6u8; 32] },
        ],
    };

    let mut buf = Vec::new();
    proof.write_nonces(&mut buf);
    proof.write_path(&mut buf);

    let mut r_slice = buf.as_slice();
    let nonce = MerkleProof::read_nonces(&mut r_slice, 2).unwrap();
    let path = MerkleProof::read_path(&mut r_slice, 2, 2).unwrap();
    assert!(r_slice.is_empty());
    let decoded = MerkleProof { nonce, path };
    assert_eq!(decoded, proof);
}

#[test]
fn test_sumcheck_proof_read_write() {
    let f = runtime_algebra::p256::P256Field::new();
    let geom = SumcheckProofGeometry {
        logw_layers: vec![2, 4],
    };

    let poly0_0 = RoundPoly {
        evaluations: [f.zero(), f.zero()],
    };
    let poly0_1 = RoundPoly {
        evaluations: [f.one(), f.one()],
    };
    let layer0: LayerProof<3, _> = LayerProof {
        hp: [
            vec![poly0_0.clone(), poly0_0],
            vec![poly0_1.clone(), poly0_1],
        ],
        claims: [f.zero(), f.one()],
    };

    let poly1_0 = RoundPoly {
        evaluations: [f.zero(), f.one()],
    };
    let poly1_1 = RoundPoly {
        evaluations: [f.one(), f.zero()],
    };
    let layer1: LayerProof<3, _> = LayerProof {
        hp: [
            vec![poly1_0.clone(), poly1_0.clone(), poly1_0.clone(), poly1_0],
            vec![poly1_1.clone(), poly1_1.clone(), poly1_1.clone(), poly1_1],
        ],
        claims: [f.zero(), f.one()],
    };

    let proof: SumcheckProof<3, _> = SumcheckProof {
        layers: vec![layer0, layer1],
    };

    let serialized = proof.write(&geom, &f).unwrap();
    let mut r_slice = serialized.as_slice();
    let decoded = SumcheckProof::read(&mut r_slice, &geom, &f).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, proof);
}

#[test]
fn test_ligero_proof_read_write() {
    use core_algebra::SupportsU64Conversions;
    let f = runtime_algebra::p256::P256Field::new();

    let geom = LigeroGeometry {
        block: 2,
        dblock: 4,
        r: 1,
        block_enc: 8,
        nrow: 4,
        nreq: 2,
        mc_pathlen: 2,
    };

    let proof = LigeroProof {
        y_ldt: vec![f.u64_to_element(1), f.u64_to_element(2)],
        y_dot: vec![
            f.u64_to_element(3),
            f.u64_to_element(4),
            f.u64_to_element(5),
            f.u64_to_element(6),
        ],
        y_quad_0: vec![f.u64_to_element(7)],
        y_quad_2: vec![f.u64_to_element(8), f.u64_to_element(9)],
        req: vec![
            f.u64_to_element(10),
            f.u64_to_element(11),
            f.u64_to_element(12),
            f.u64_to_element(13),
            f.u64_to_element(14),
            f.u64_to_element(15),
            f.u64_to_element(16),
            f.u64_to_element(17),
        ],
        merkle: MerkleProof {
            nonce: vec![
                MerkleNonce { bytes: [1u8; 32] },
                MerkleNonce { bytes: [2u8; 32] },
            ],
            path: vec![
                Digest { data: [3u8; 32] },
                Digest { data: [4u8; 32] },
                Digest { data: [5u8; 32] },
                Digest { data: [6u8; 32] },
            ],
        },
    };

    let sf = runtime_algebra::p256::P256Subfield::new(&f);
    let serialized = proof.write(&geom, &f, &sf).unwrap();
    let mut r_slice = serialized.as_slice();
    let decoded = LigeroProof::read(&mut r_slice, &geom, &f, &sf).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, proof);
}

#[test]
fn test_ligero_proof_rle_roundtrip_with_gf2_128() {
    use core_algebra::SupportsU128Conversions;
    use runtime_algebra::{gf2_128::Gf2_128Field, subfield::BinarySubfield};

    let f = Gf2_128Field::new();

    let geom = LigeroGeometry {
        block: 2,
        dblock: 4,
        r: 1,
        block_enc: 8,
        nrow: 4,
        nreq: 2,
        mc_pathlen: 2,
    };

    let proof = LigeroProof {
        y_ldt: vec![f.u128_to_element(1), f.u128_to_element(2)],
        y_dot: vec![
            f.u128_to_element(3),
            f.u128_to_element(4),
            f.u128_to_element(5),
            f.u128_to_element(6),
        ],
        y_quad_0: vec![f.u128_to_element(7)],
        y_quad_2: vec![f.u128_to_element(8), f.u128_to_element(9)],
        req: vec![
            f.u128_to_element(10),
            f.u128_to_element(11),
            f.u128_to_element(12),
            f.u128_to_element(13),
            f.u128_to_element(14),
            f.u128_to_element(15),
            f.u128_to_element(16),
            f.u128_to_element(17),
        ],
        merkle: MerkleProof {
            nonce: vec![
                MerkleNonce { bytes: [1u8; 32] },
                MerkleNonce { bytes: [2u8; 32] },
            ],
            path: vec![Digest { data: [3u8; 32] }, Digest { data: [4u8; 32] }],
        },
    };

    let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let sub_val = sf.embed(10);
    let field_val = f.u128_to_element(11);
    assert!(sf.contains(&sub_val), "sub_val should be in subfield");
    assert!(
        !sf.contains(&field_val),
        "field_val should NOT be in subfield"
    );

    let serialized = proof.write(&geom, &f, &sf).unwrap();
    let mut r_slice = serialized.as_slice();
    let decoded: LigeroProof<2, Gf2_128Field> =
        LigeroProof::read(&mut r_slice, &geom, &f, &sf).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded.y_ldt, proof.y_ldt);
    assert_eq!(decoded.y_dot, proof.y_dot);
    assert_eq!(decoded.y_quad_0, proof.y_quad_0);
    assert_eq!(decoded.y_quad_2, proof.y_quad_2);
    assert_eq!(decoded.req, proof.req);
    assert_eq!(decoded.merkle, proof.merkle);
}

#[test]
fn test_zk_proof_read_write() {
    use core_algebra::SupportsU64Conversions;
    let f = runtime_algebra::p256::P256Field::new();
    let sf = runtime_algebra::p256::P256Subfield::new(&f);

    let geom = LigeroGeometry {
        block: 4,
        dblock: 8,
        r: 3,
        block_enc: 16,
        nrow: 4,
        nreq: 2,
        mc_pathlen: 5,
    };

    let make_poly2 = |v0, v2| RoundPoly {
        evaluations: [f.u64_to_element(v0), f.u64_to_element(v2)],
    };

    // ZK Sumcheck proof has logc = 0
    let sc_proof: SumcheckProof<4, P256Field> = SumcheckProof {
        layers: vec![LayerProof {
            hp: [
                vec![make_poly2(9, 11), make_poly2(12, 14)],
                vec![make_poly2(18, 20), make_poly2(21, 23)],
            ],
            claims: [f.u64_to_element(27), f.u64_to_element(28)],
        }],
    };

    let com_proof: LigeroProof<4, P256Field> = LigeroProof {
        y_ldt: vec![
            f.u64_to_element(1),
            f.u64_to_element(2),
            f.u64_to_element(3),
            f.u64_to_element(4),
        ],
        y_dot: vec![
            f.u64_to_element(5),
            f.u64_to_element(6),
            f.u64_to_element(7),
            f.u64_to_element(8),
            f.u64_to_element(9),
            f.u64_to_element(10),
            f.u64_to_element(11),
            f.u64_to_element(12),
        ],
        y_quad_0: vec![
            f.u64_to_element(13),
            f.u64_to_element(14),
            f.u64_to_element(15),
        ],
        y_quad_2: vec![
            f.u64_to_element(16),
            f.u64_to_element(17),
            f.u64_to_element(18),
            f.u64_to_element(19),
        ],
        req: vec![
            f.u64_to_element(100),
            f.u64_to_element(101),
            f.u64_to_element(102),
            f.u64_to_element(103),
            f.u64_to_element(104),
            f.u64_to_element(105),
            f.u64_to_element(106),
            f.u64_to_element(107),
        ],
        merkle: MerkleProof {
            nonce: vec![
                MerkleNonce { bytes: [9u8; 32] },
                MerkleNonce { bytes: [10u8; 32] },
            ],
            path: vec![Digest { data: [11u8; 32] }, Digest { data: [12u8; 32] }],
        },
    };

    let zk_proof: ZkProof<4, P256Field> = ZkProof {
        sumcheck_proof: sc_proof,
        com: LigeroCommitment {
            root: Digest { data: [42u8; 32] },
        },
        com_proof,
    };

    // Serialize
    let zk_geom = ZkProofGeometry {
        sc_geom: SumcheckProofGeometry {
            logw_layers: vec![2],
        },
        com_geom: geom,
    };
    let serialized = zk_proof.write(&zk_geom, &f, &sf).unwrap();

    let mut r_slice = serialized.as_slice();
    let decoded = ZkProof::read(&mut r_slice, &zk_geom, &f, &sf).unwrap();
    assert!(r_slice.is_empty());
    assert_eq!(decoded, zk_proof);
}
