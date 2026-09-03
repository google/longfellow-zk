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

use reference::{
    algebra::{Field, FieldError, Gf2_128, P256, Rng},
    circuit::{Circuit, CircuitLayer, Term},
    ligero::LigeroConfig,
    zk::{ZkProver, ZkVerifier},
    zk::symbolic_sumcheck_verifier::{Expression, Var},
};

#[test]
fn test_fiat_shamir_test_vectors() {
    use reference::transcript::Transcript;

    let mut t = Transcript::new(b"test");
    let arr: Vec<u8> = (0..100).map(|i| i as u8).collect();
    t.write_bytes(&arr);

    let expected_v1 = [
        "8b297f0bffd583c6c6b6796385d5fd20a08665733b833970ebdd1054bbbc1b14",
        "0667c08ad7f38efec5f30dc8aa4f20d749cdcf96d63a770f9810ac5c0ca8dcb1",
        "c8037fc12d4da00b5dc7597e3042f33f72a06f970cb71fb6b103ebb5419d8a6b",
        "fbbcfa1eac48728fbfdacc1c21e2f78119457e0846337e46140e38e62856c4c5",
        "5358ae603691cc759faeb572fb6642654ea1c3dbc8f81d00276dd8c4df95aa58",
        "5266158c3c895dede5a23b6ce85a9f564b8059ebfcd1741f54497ec58189873e",
        "3ecea4b2343c007fc32f2aff40dc7320945f101ecae5d52494db21ad326e9739",
        "6462dd575e6b874118607212feec7ce5417ae3bf0f2e86604596f35d48bbaea2",
        "6d56c703c369edea3595db6b958241580ae9b4a76fead961413ed9e9e5852dcd",
        "6d31073cee650212a71b7b13e9f951e00ef3b14a008a79dd95047b26a4a83d06",
        "1b9e2a6666da63c43e52227d91a8a7f0bd5311f63c2e3a18839133375639e6cb",
        "332ea49dd23dd4745631ecbb15696192b1fa127256baf7a0483fd27db6f09a48",
        "43e735927ccbdc4d5ce912675d638d6d3dc8eef3def34504304e938846f157d6",
        "dc4a8868ae75e733a7257a8589230392a98d78594836dfccd01304742b5b3ad5",
        "976353931711c634f2691e507b119fd7f6e653d419a2620676122db08db18765",
        "332729ab436dca654866a9382deaee0add6fb7e90a80261f1488e56598e8bc99",
    ];
    for exp in &expected_v1 {
        let b = t.bytes(32);
        let be: Vec<u8> = b.into_iter().rev().collect();
        let s: String = be.iter().map(|byte| format!("{:02x}", byte)).collect();
        assert_eq!(&s, exp);
    }

    t.write_elt_field(p256_val(7));

    let expected_v2 = [
        "609db3e9a8f548df038519fa46cef23eb8c6553d3c1f698604e60a51613a738e",
        "1cb69cb31999eb88e83c7586aac53f5e3286b084b0cf9e43619b48df01e0a310",
        "3bf36e3ddc690a1b12b417628c115959b373d056c90c42dc2417baf46f538868",
        "e336594f29dcda52e48896517b5cdb2d062ffd861ab02db5f8ca197aacc635f6",
        "c1f396a8bad16bb0f57da6d380402a25b571bd4691226d11449a741440e325c8",
        "5195336ec73751de066e3a8939b40c3c5555f1a513486dfc50dcf4c2d47e6ff2",
        "8dcf872f3ded2b7ed1d1ee9a2b125bedc6eacd3c09b3a4a5286d8fc2fc3a6634",
        "950dd2ef7be25eab686a6688497962ee4ad521da12b9ff3d8e56ad9435885b12",
        "e14389d1d8448678cac33fdbc9aab20dba019e75149d170dd2f353891cd4b84f",
        "e84906c09cd6423865baf64e48027cc598d52bdb90b17524c87ea892e53b5200",
        "493cea587f1ec5622c04221cd6e5a41c26c1c1c24c0375f7aaa367d9678d83bc",
        "5aca0010aced30bcb3b84a7f10ea39c4269ab7c92fcb6cff52958d8921ef2cc5",
        "4498fa8340f41467c0fa813bd0ca83ef6e1c4b85c7b1168a94339fd9e8296139",
        "f9a95b738a8e775421b1baa503abbeed2d283b236ebba25e1954b3c993d30a3d",
        "98178711d03a0b1204ebb56b37bd3a2724dfb08e4dc925609391768b126d21f2",
        "79251f49534f5c4b10b798b2dbf6e80a3b07593f616ce6a9617ccc61040aac78",
    ];
    for exp in &expected_v2 {
        let b = t.bytes(32);
        let be: Vec<u8> = b.into_iter().rev().collect();
        let s: String = be.iter().map(|byte| format!("{:02x}", byte)).collect();
        assert_eq!(&s, exp);
    }

    t.write_elt_field_slice(&[p256_val(8), p256_val(9)]);

    let expected_v3 = [
        "ae1a921288590205fc24543303ff527476359b8db4a983b2886a133b02f3217e",
        "8c5d52a04b295f9fdb45ab66100fa00ca32c9634aa87cbbdb2bc3e1912459feb",
        "12f82963b5b242156f6e9eb756eddee7652b60c7d6394403f7bd995e0b9bcd9c",
        "880aa50b049b3939055deb7933749d338bb3fb5f64a9adf95019e6cfc232995c",
        "f8558f693f0fa6df20a37147a898fb4c678831f566d80113bbe2cdcd18285da2",
        "bbcc8d9b46f88bc8c6cec0ad2d5e49508b7db91d548548eddc61800de1329e1c",
        "479a17244398caae8155a73438a22583df7de10a8a2e12ad53ddd3bc7305fac9",
        "9ba1917f1227932250288a843f64b4e7b7f47a5fbc16c111f6e1f76235ccf38c",
        "d1582138045d1636fb7f677c9e8a4a4143ce2b2bb54fb4f49fb0ad1fee5df6b4",
        "05331e5b8508f79c017a8dfbbb805f3f8c5e3e4bc417e44849b9212439646331",
        "b6b95862194ca52dcaa9ee651b7fc5b708f43feae108bb9a7f95213f4d069048",
        "e86b1602f0a54c4e237867ebaf05e7581464fd238e50f6ed9c3cea63909c8e60",
        "b7280439f3b21b113ff29cefe39292d5e2d137709c3d3cec36473a0f97a24e62",
        "beaa5e08257d232506fb3e46c6daa29e0859c34c7d0cd673bc6706ee261ae059",
        "0691ead55728cd087a1952b22b6628ba4e26fbefc8debeec5e6fbc3a16f637be",
        "47dc31f6d8bc9c44290781176df3e4b95ac8793a4a42fa5859c564d92d6d5af5",
    ];
    for exp in &expected_v3 {
        let b = t.bytes(32);
        let be: Vec<u8> = b.into_iter().rev().collect();
        let s: String = be.iter().map(|byte| format!("{:02x}", byte)).collect();
        assert_eq!(&s, exp);
    }

    t.write_bytes(b"nats");
    let ns = [
        1, 1, 1, 2, 2, 2, 7, 7, 7, 7, 32, 32, 32, 32, 256, 256, 256, 256, 1000, 10000, 60000,
        65535, 100000, 100000,
    ];
    let nats: Vec<usize> = ns.iter().map(|&n| t.nat(n)).collect();
    let expected_nats = vec![
        0, 0, 0, 0, 0, 0, 3, 0, 4, 5, 10, 30, 27, 22, 100, 189, 3, 92, 999, 3105, 40886, 51590,
        56367, 10678,
    ];
    assert_eq!(nats, expected_nats);

    t.write_bytes(b"choose");
    let expected_choices: Vec<(usize, Vec<usize>)> = vec![
        (31, vec![10, 29, 30, 11, 4, 15, 16, 28, 19, 21, 25, 18, 17, 3, 5, 23, 24, 22, 6, 1]),
        (32, vec![3, 17, 18, 8, 30, 7, 14, 19, 25, 23, 12, 4, 31, 16, 0, 6, 20, 27, 11, 10]),
        (63, vec![9, 56, 61, 45, 35, 53, 51, 3, 39, 32, 31, 6, 59, 58, 54, 22, 27, 62, 55, 19]),
        (64, vec![12, 52, 39, 17, 51, 38, 58, 2, 28, 27, 46, 63, 61, 50, 40, 55, 47, 13, 56, 32]),
        (1000, vec![157, 668, 572, 138, 913, 994, 797, 249, 440, 723, 489, 241, 383, 108, 710, 341, 406, 585, 42, 692]),
        (65535, vec![40745, 48408, 17108, 44500, 53993, 10008, 24910, 52200, 61265, 54989, 41237, 25958, 28697, 61187, 34729, 3525, 9005, 38627, 9724, 12169]),
    ];
    for (cs, exp) in expected_choices {
        let choices = t.choose(cs, 20);
        assert_eq!(choices, exp);
    }
}

#[test]
fn test_p256_from_bytes_range_check() {
    let valid_bytes = vec![0u8; 32];
    assert!(P256::from_bytes(&valid_bytes).is_ok());

    let invalid_bytes = vec![0xffu8; 32];
    assert_eq!(
        P256::from_bytes(&invalid_bytes),
        Err(FieldError::ValueOutOfRange)
    );
}

#[test]
#[should_panic(expected = "cannot invert zero")]
fn test_p256_inv_zero_panics() {
    let _ = P256::zero().inv();
}

#[test]
#[should_panic(expected = "cannot invert zero")]
fn test_gf2_128_inv_zero_panics() {
    let _ = Gf2_128::zero().inv();
}

#[test]
fn test_expression_auto_dedup() {
    let mut expr = Expression::<Gf2_128>::from(Gf2_128 { v: 5 });
    expr += Var(2) * Gf2_128 { v: 10 };
    expr += Var(0) * Gf2_128 { v: 3 };
    expr += Var(2) * Gf2_128 { v: 4 };
    expr += Var(1) * Gf2_128 { v: 7 };
    expr += Var(0) * Gf2_128 { v: 3 }; // 3 ^ 3 in GF(2^128) is 0

    // 0-term should be automatically removed (3 ^ 3 == 0)
    // 1-term: coeff 7
    // 2-term: coeff 10 ^ 4 = 14
    assert_eq!(expr.terms.len(), 2);
    assert_eq!(expr.terms.get(&1), Some(&Gf2_128 { v: 7 }));
    assert_eq!(
        expr.terms.get(&2),
        Some(&(Gf2_128 { v: 10 } + Gf2_128 { v: 4 }))
    );
}

#[test]
fn test_expression_operator_math() {
    // Test natural math expressions with operators: +, -, *
    let e1: Expression<Gf2_128> = Var::<Gf2_128>(0) * Gf2_128 { v: 3 } + Gf2_128 { v: 5 };
    let e2: Expression<Gf2_128> =
        Var::<Gf2_128>(0) * Gf2_128 { v: 2 } + Var::<Gf2_128>(1) * Gf2_128 { v: 4 };

    let diff = e1 - e2; // 3^2=1 for v=0, 4 for v=1, 5 for known
    assert_eq!(diff.known, Gf2_128 { v: 5 });
    assert_eq!(
        diff.terms.get(&0),
        Some(&(Gf2_128 { v: 3 } + Gf2_128 { v: 2 }))
    );
    assert_eq!(diff.terms.get(&1), Some(&Gf2_128 { v: 4 }));
}

#[test]
fn test_layer_pad_isomorphism() {
    use reference::sumcheck::LayerPad;

    let logw = 3;
    let mut base = 100;
    let idx_pad = LayerPad::generate_indices(logw, &mut base);

    assert_eq!(base, 100 + 4 * logw + 3);
    assert_eq!(idx_pad.rounds.len(), logw);
    assert_eq!(idx_pad.rounds[0].hp[0], [100, 101]);
    assert_eq!(idx_pad.rounds[0].hp[1], [102, 103]);
    assert_eq!(idx_pad.claims.c0, 112);
    assert_eq!(idx_pad.claims.c1, 113);
    assert_eq!(idx_pad.claims.cr, 114);
}

#[test]
fn test_ceil_lg2_works_as_intended() {
    use reference::algebra::ceil_lg2;

    assert_eq!(ceil_lg2(0), 0);
    assert_eq!(ceil_lg2(1), 0);
    assert_eq!(ceil_lg2(2), 1);
    assert_eq!(ceil_lg2(3), 2);
    assert_eq!(ceil_lg2(4), 2);
    assert_eq!(ceil_lg2(5), 3);
    assert_eq!(ceil_lg2(7), 3);
    assert_eq!(ceil_lg2(8), 3);
    assert_eq!(ceil_lg2(9), 4);
    assert_eq!(ceil_lg2(16), 4);
    assert_eq!(ceil_lg2(17), 5);
    assert_eq!(ceil_lg2(255), 8);
    assert_eq!(ceil_lg2(256), 8);
    assert_eq!(ceil_lg2(257), 9);
    assert_eq!(ceil_lg2(1024), 10);
    assert_eq!(ceil_lg2(6657), 13);
}

#[test]
fn test_zk_error_conversions() {
    use reference::{
        ZkError, algebra::FieldError, ligero::VerificationError, sumcheck::CircuitEvaluationError,
        zk::ZkVerificationError,
    };

    let field_err: ZkError = FieldError::ValueOutOfRange.into();
    assert!(format!("{}", field_err).contains("Field error"));

    let ligero_err: ZkError = VerificationError::MerkleProofInvalid.into();
    assert!(format!("{}", ligero_err).contains("Ligero error"));

    let zk_err: ZkError = ZkVerificationError::PublicInputLengthMismatch {
        expected: 2,
        actual: 4,
    }
    .into();
    assert!(format!("{}", zk_err).contains("ZK verification error"));

    let circuit_err: ZkError = CircuitEvaluationError::CircuitOutputNotZero.into();
    assert!(format!("{}", circuit_err).contains("Circuit evaluation error"));

    let io_err: ZkError = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF").into();
    assert!(format!("{}", io_err).contains("I/O error"));

    let custom_err = ZkError::InvalidData("test error".to_string());
    assert!(format!("{}", custom_err).contains("Invalid data error"));
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_merkle_test_vector_1() {
    use reference::merkle::{MerkleHeap, open_merkle_heap, verify_merkle_proof};

    let leaves = vec![
        hex_to_bytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
        hex_to_bytes("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"),
        hex_to_bytes("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
        hex_to_bytes("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71"),
        hex_to_bytes("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db"),
    ];

    let tree = MerkleHeap::new(&leaves);
    let expected_root =
        hex_to_bytes("f22f4501ffd3bdffcecc9e4cd6828a4479aeedd6aa484eb7c1f808ccf71c6e76");
    assert_eq!(tree.root, expected_root);

    // Test proof for leaves (0, 1)
    let proof_0_1 = open_merkle_heap(&tree, &[0, 1]).expect("Failed to open proof for (0, 1)");
    let expected_proof_0_1 = vec![
        hex_to_bytes("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
        hex_to_bytes("f03808f5b8088c61286d505e8e93aa378991d9889ae2d874433ca06acabcd493"),
    ];
    assert_eq!(proof_0_1, expected_proof_0_1);

    verify_merkle_proof(5, &tree.root, &[0, 1], &proof_0_1, |idx| {
        leaves[idx].clone()
    })
    .expect("Failed to verify proof for (0, 1)");

    // Test proof for leaves (1, 3)
    let proof_1_3 = open_merkle_heap(&tree, &[1, 3]).expect("Failed to open proof for (1, 3)");
    let expected_proof_1_3 = vec![
        hex_to_bytes("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db"),
        hex_to_bytes("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
        hex_to_bytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
    ];
    assert_eq!(proof_1_3, expected_proof_1_3);

    verify_merkle_proof(5, &tree.root, &[1, 3], &proof_1_3, |idx| {
        leaves[idx].clone()
    })
    .expect("Failed to verify proof for (1, 3)");
}

#[test]
fn test_merkle_soundness_and_negative_cases() {
    use reference::merkle::{MerkleHeap, open_merkle_heap, verify_merkle_proof};

    let leaves = vec![
        hex_to_bytes("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
        hex_to_bytes("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"),
        hex_to_bytes("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
        hex_to_bytes("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71"),
        hex_to_bytes("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db"),
    ];

    let tree = MerkleHeap::new(&leaves);
    let proof_0_1 = open_merkle_heap(&tree, &[0, 1]).unwrap();

    // 1. Out of bounds index in opening
    assert!(open_merkle_heap(&tree, &[5]).is_err());

    // 2. Duplicate index in opening
    assert!(open_merkle_heap(&tree, &[1, 1]).is_err());

    // 3. Out of bounds index in verify
    assert!(
        verify_merkle_proof(5, &tree.root, &[5], &proof_0_1, |idx| leaves[idx].clone()).is_err()
    );

    // 4. Duplicate index in verify
    assert!(
        verify_merkle_proof(5, &tree.root, &[0, 0], &proof_0_1, |idx| leaves[idx].clone())
            .is_err()
    );

    // 5. Wrong root
    let mut bad_root = tree.root.clone();
    bad_root[0] ^= 1;
    assert_eq!(
        verify_merkle_proof(5, &bad_root, &[0, 1], &proof_0_1, |idx| leaves[idx].clone()),
        Err("Merkle root mismatch")
    );

    // 6. Wrong leaf
    assert_eq!(
        verify_merkle_proof(5, &tree.root, &[0, 1], &proof_0_1, |idx| {
            let mut leaf = leaves[idx].clone();
            if idx == 0 {
                leaf[0] ^= 1;
            }
            leaf
        }),
        Err("Merkle root mismatch")
    );

    // 7. Truncated path
    let truncated_proof = vec![proof_0_1[0].clone()];
    assert_eq!(
        verify_merkle_proof(5, &tree.root, &[0, 1], &truncated_proof, |idx| leaves[idx]
            .clone()),
        Err("Missing path value in Merkle proof verification")
    );

    // 8. Extra path element
    let mut extra_proof = proof_0_1.clone();
    extra_proof.push(vec![0u8; 32]);
    assert_eq!(
        verify_merkle_proof(5, &tree.root, &[0, 1], &extra_proof, |idx| leaves[idx]
            .clone()),
        Err("Not all Merkle path elements were consumed")
    );
}

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl Rng for SimpleRng {
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = self.state;
        for _ in 0..len {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.push(((state >> 32) & 0xff) as u8);
        }
        self.state = state;
        out
    }
}

fn p256_val(x: i64) -> P256 {
    P256::new(num_bigint::BigInt::from(x))
}

/// Constructs the s-gonal circuit C(n, m, s) = 0 <=> (s - 2)*m^2 - (s - 4)*m - 2*n = 0 over P256.
fn create_sgonal_circuit_p256() -> Circuit<P256> {
    let layer1_terms = vec![
        Term {
            k: p256_val(1),
            g: 0,
            h: [0, 0],
        }, // u0 = 1
        Term {
            k: p256_val(1),
            g: 1,
            h: [2, 2],
        }, // u1 = m^2
        Term {
            k: p256_val(1),
            g: 2,
            h: [0, 3],
        }, // u2 += s
        Term {
            k: p256_val(-2),
            g: 2,
            h: [0, 0],
        }, // u2 -= 2
        Term {
            k: p256_val(1),
            g: 3,
            h: [2, 3],
        }, // u3 += s * m
        Term {
            k: p256_val(-4),
            g: 3,
            h: [0, 2],
        }, // u3 -= 4 * m
        Term {
            k: p256_val(2),
            g: 4,
            h: [0, 1],
        }, // u4 = 2 * n
    ];

    let layer0_terms = vec![
        Term {
            k: p256_val(1),
            g: 0,
            h: [1, 2],
        }, // y0 += u2 * u1 = (s-2)*m^2
        Term {
            k: p256_val(-1),
            g: 0,
            h: [0, 3],
        }, // y0 -= u3 * u0 = (s-4)*m
        Term {
            k: p256_val(-1),
            g: 0,
            h: [0, 4],
        }, // y0 -= u4 * u0 = 2*n
    ];

    Circuit {
        id: [0u8; 32],
        field_id: 2,
        noutput: 1,
        logv: 0,
        npublic_input: 1,
        subfield_boundary: 0,
        ninput: 4,
        layers: vec![
            CircuitLayer {
                logw: 3, // layer 0 inputs from layer 1 (nw=5), ceil_lg2(5) = 3
                nw: 5,   // input wire count to layer 0
                quad: layer0_terms,
            },
            CircuitLayer {
                logw: 2, // layer 1 inputs from circuit inputs (nw=4), ceil_lg2(4) = 2
                nw: 4,   // input wire count to layer 1
                quad: layer1_terms,
            },
        ],
    }
}

#[test]
fn test_sgonal_test_vector_p256() {
    let circuit = create_sgonal_circuit_p256();
    let config = LigeroConfig {
        rate_inv: 4,
        num_queries: 6,
        encoded_len: 64,
    };

    // W = [1, 45, 5, 6] for m=5, s=6 (hexagonal number 45 in P-256)
    let inputs = vec![
        p256_val(1),
        p256_val(45),
        p256_val(5),
        p256_val(6),
    ];

    let eval_res = reference::sumcheck::eval_circuit(&inputs, &circuit);
    assert!(eval_res.is_ok(), "Circuit evaluation failed: {:?}", eval_res.err());

    let label = "sgonal_test_vector_p256";
    let mut rng = SimpleRng::new(12345);

    let prover = ZkProver::new(circuit.clone(), config.clone());
    let commit = prover.commit(&inputs, &mut rng);
    let proof = prover.prove(&inputs, &commit, label);

    // Check commitment root hex
    let root_hex: String = commit.root.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(root_hex, "803aba51698a4bc4dddaa74b1d9971b8ec7c49c4847a7ff18e41dd476edf9b04");

    // Check complete serialized proof
    let mut proof_bytes = Vec::new();
    reference::zk::write_zk_proof(&mut proof_bytes, &proof, &reference::algebra::P256Subfield).unwrap();
    let proof_hex: String = proof_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(proof_bytes.len(), 5452);
    assert_eq!(&proof_hex[..64], "803aba51698a4bc4dddaa74b1d9971b8ec7c49c4847a7ff18e41dd476edf9b04");

    let verifier = ZkVerifier::new(circuit, config);
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(res.is_ok(), "ZK verification failed: {:?}", res.err());
}

fn create_sgonal_circuit_gf2_128() -> Circuit<Gf2_128> {
    let one = Gf2_128::one();
    let layer1_terms = vec![
        Term { k: one, g: 0, h: [0, 0] }, // u0 = 1
        Term { k: one, g: 1, h: [2, 2] }, // u1 = m^2
        Term { k: one, g: 2, h: [0, 3] }, // u2 += s
        Term { k: one, g: 2, h: [0, 0] }, // u2 += 1 (s + 1)
        Term { k: one, g: 3, h: [2, 3] }, // u3 += s * m
        Term { k: one, g: 3, h: [0, 2] }, // u3 += 1 * m
        Term { k: one, g: 4, h: [0, 1] }, // u4 = n
    ];

    let layer0_terms = vec![
        Term { k: one, g: 0, h: [1, 2] }, // y0 += u2 * u1 = (s+1)*m^2
        Term { k: one, g: 0, h: [0, 3] }, // y0 += u3 * u0 = (s+1)*m
        Term { k: one, g: 0, h: [0, 4] }, // y0 += u4 * u0 = n
    ];

    Circuit {
        id: [0u8; 32],
        field_id: 5,
        noutput: 1,
        logv: 0,
        npublic_input: 1,
        subfield_boundary: 0,
        ninput: 4,
        layers: vec![
            CircuitLayer {
                logw: 3,
                nw: 5,
                quad: layer0_terms,
            },
            CircuitLayer {
                logw: 2,
                nw: 4,
                quad: layer1_terms,
            },
        ],
    }
}

#[test]
fn test_sgonal_test_vector_gf2_128() {
    let circuit = create_sgonal_circuit_gf2_128();
    let config = LigeroConfig {
        rate_inv: 4,
        num_queries: 6,
        encoded_len: 64,
    };

    let m = Gf2_128 { v: 5 };
    let s = Gf2_128 { v: 6 };
    let s_plus_1 = s + Gf2_128::one();
    let n = (s_plus_1 * m * m) + (s_plus_1 * m);

    let inputs = vec![
        Gf2_128::one(),
        n,
        m,
        s,
    ];

    let eval_res = reference::sumcheck::eval_circuit(&inputs, &circuit);
    assert!(eval_res.is_ok(), "GF2_128 circuit evaluation failed: {:?}", eval_res.err());

    let label = "sgonal_test_vector_gf2_128";
    let mut rng = SimpleRng::new(12345);

    let prover = ZkProver::new(circuit.clone(), config.clone());
    let commit = prover.commit(&inputs, &mut rng);
    let proof = prover.prove(&inputs, &commit, label);

    // Check commitment root hex
    let root_hex: String = commit.root.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(root_hex, "30dafd53c4f2441bb8457cd84fa69b3a822fbda58a46527d5cec8ce1903bc504");

    // Check complete serialized proof
    let mut proof_bytes = Vec::new();
    reference::zk::write_zk_proof(&mut proof_bytes, &proof, &reference::algebra::BinarySubfield::default()).unwrap();
    let proof_hex: String = proof_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(proof_bytes.len(), 3048);
    assert_eq!(&proof_hex[..64], "30dafd53c4f2441bb8457cd84fa69b3a822fbda58a46527d5cec8ce1903bc504");

    let verifier = ZkVerifier::new(circuit, config);
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(res.is_ok(), "GF2_128 ZK verification failed: {:?}", res.err());
}
