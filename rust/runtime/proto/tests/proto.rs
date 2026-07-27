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

use std::io::ErrorKind;

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
fn test_util_rejects_noncanonical_subfield_elt() {
    use runtime_algebra::{gf2_128::Gf2_128, Subfield};

    struct AliasedSubfield;

    impl Subfield for AliasedSubfield {
        type E = Gf2_128;

        fn to_bytes_into(&self, _e: &Self::E, dst: &mut [u8]) {
            assert_eq!(dst.len(), 1);
            dst[0] = 0;
        }

        fn contains(&self, _e: &Self::E) -> bool {
            true
        }

        fn serialized_size_bytes(&self) -> usize {
            1
        }

        fn bytes_to_element(&self, bytes: &[u8]) -> Result<Self::E, String> {
            if bytes.len() != 1 {
                return Err("Invalid size".to_string());
            }
            Ok(Gf2_128::from(0))
        }

        fn sample<R: FnMut(usize) -> Vec<u8>>(&self, _rng: R) -> Self::E {
            Gf2_128::from(0)
        }
    }

    let sf = AliasedSubfield;

    let mut canonical = [0u8].as_slice();
    assert!(read_subfield_elt(&mut canonical, &sf).is_ok());

    let mut aliased = [1u8].as_slice();
    let err = read_subfield_elt(&mut aliased, &sf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "Non-canonical subfield element encoding");
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
fn test_ligero_proof_read_allows_zero_length_merkle_path() {
    use core_algebra::SupportsU64Conversions;
    let f = runtime_algebra::p256::P256Field::new();
    let sf = runtime_algebra::p256::P256Subfield::new(&f);

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
            path: Vec::new(),
        },
    };

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
fn test_ligero_proof_rejects_noncanonical_rle_encodings() {
    use runtime_algebra::{gf2_128::Gf2_128Field, subfield::BinarySubfield, Subfield};

    let f = Gf2_128Field::new();
    let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
    let geom = LigeroGeometry {
        block: 0,
        dblock: 0,
        r: 0,
        block_enc: 2,
        nrow: 1,
        nreq: 1,
        mc_pathlen: 1,
    };
    let subfield_elt = sf.embed(1);

    // A leading empty non-subfield run is the unique canonical way to encode
    // a request sequence that begins with a subfield element.
    let mut canonical = vec![0; 32]; // nonce
    canonical.extend_from_slice(&0u32.to_le_bytes());
    canonical.extend_from_slice(&1u32.to_le_bytes());
    let mut subfield_bytes = vec![0; sf.serialized_size_bytes()];
    sf.to_bytes_into(&subfield_elt, &mut subfield_bytes);
    canonical.extend_from_slice(&subfield_bytes);
    canonical.extend_from_slice(&1u32.to_le_bytes());
    canonical.extend_from_slice(&[0; 32]); // one Merkle path digest

    let mut canonical_input = canonical.as_slice();
    assert!(LigeroProof::<2, _>::read(&mut canonical_input, &geom, &f, &sf).is_ok());

    // A second empty run is a semantically redundant representation that used
    // to make the parser spin indefinitely.
    let mut duplicate_empty_run = canonical[..36].to_vec();
    duplicate_empty_run.extend_from_slice(&0u32.to_le_bytes());
    duplicate_empty_run.extend_from_slice(&canonical[36..]);
    let mut duplicate_run_input = duplicate_empty_run.as_slice();
    let err = LigeroProof::<2, _>::read(&mut duplicate_run_input, &geom, &f, &sf).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(
        err.to_string(),
        "Non-canonical or invalid RLE run length in LigeroProof"
    );

    // The same subfield element must not be accepted in the full-field run.
    let mut full_field_encoding = vec![0; 32]; // nonce
    full_field_encoding.extend_from_slice(&1u32.to_le_bytes());
    let mut full_bytes = vec![0; core_algebra::SerializableField::serialized_size_bytes(&f)];
    core_algebra::SerializableField::to_bytes_into(&f, &subfield_elt, &mut full_bytes);
    full_field_encoding.extend_from_slice(&full_bytes);
    full_field_encoding.extend_from_slice(&1u32.to_le_bytes());
    full_field_encoding.extend_from_slice(&[0; 32]);
    let mut full_field_input = full_field_encoding.as_slice();
    let err_full_field = LigeroProof::<2, _>::read(&mut full_field_input, &geom, &f, &sf).unwrap_err();
    assert_eq!(err_full_field.kind(), ErrorKind::InvalidData);
    assert_eq!(
        err_full_field.to_string(),
        "Non-canonical field encoding of subfield element in LigeroProof"
    );
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
