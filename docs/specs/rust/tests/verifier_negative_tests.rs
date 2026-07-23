use std::{fs::File, io::BufReader, path::PathBuf};

use num_bigint::BigInt;
use reference::{
    algebra::{Field, Gf2_128, Rng},
    circuit::parse_lfc2_bytes,
    ligero::{LigeroConfig, VerificationError as LigeroVerificationError},
    zk::{ZkProver, ZkVerificationError, ZkVerifier},
};

pub struct TestRng {
    pub state: u64,
}

impl TestRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl Rng for TestRng {
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

fn get_testdata_path(relative_path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path)
}

fn setup_sha256_fixture() -> (
    ZkVerifier<Gf2_128>,
    Vec<Gf2_128>,
    reference::zk::ZkProof<Gf2_128>,
    &'static str,
) {
    let config = LigeroConfig::default();
    let label = "sha256";

    let circuit_file = File::open(get_testdata_path("tests/testdata/sha256_circuit.lfc2"))
        .expect("Failed to open circuit file");
    let mut circuit_reader = BufReader::new(circuit_file);
    let circuit =
        parse_lfc2_bytes::<Gf2_128, _>(&mut circuit_reader).expect("Failed to parse LFC2 circuit");

    let inputs_file = File::open(get_testdata_path("tests/testdata/sha256_inputs.json"))
        .expect("Failed to open inputs file");
    let raw_inputs: Vec<String> =
        serde_json::from_reader(inputs_file).expect("Failed to parse inputs JSON");

    let inputs: Vec<Gf2_128> = raw_inputs
        .iter()
        .map(|s| {
            let val = BigInt::parse_bytes(s.as_bytes(), 10).unwrap();
            let mut v_bytes = val.to_bytes_le().1;
            v_bytes.resize(16, 0);
            Gf2_128::from_bytes(&v_bytes).unwrap()
        })
        .collect();

    let mut rng = TestRng::new(12345);
    let prover = ZkProver::new(circuit.clone(), config.clone());
    let commit = prover.commit(&inputs, &mut rng);
    let proof = prover.prove(&inputs, &commit, label);

    let verifier = ZkVerifier::new(circuit, config);
    (verifier, inputs, proof, label)
}

#[test]
fn test_verify_valid_proof_succeeds() {
    let (verifier, inputs, proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    assert!(verifier.verify(pub_inputs, &proof, label).is_ok());
}

#[test]
fn test_verify_tampered_public_inputs() {
    let (verifier, inputs, proof, label) = setup_sha256_fixture();
    let mut pub_inputs = inputs[..verifier.circuit_data.npublic_input].to_vec();
    if pub_inputs.is_empty() {
        pub_inputs.push(Gf2_128::one());
    } else {
        pub_inputs[0] += Gf2_128::one();
    }

    let res = verifier.verify(&pub_inputs, &proof, label);
    assert!(res.is_err(), "Mismatched public inputs must be rejected");
}

#[test]
fn test_verify_tampered_merkle_root() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    proof.root[0] ^= 0xff; // Bit-flip Merkle root

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        matches!(
            res,
            Err(ZkVerificationError::LigeroVerification(
                LigeroVerificationError::MerkleProofInvalid
            ))
        ),
        "Corrupted Merkle root must return MerkleProofInvalid, got {:?}",
        res
    );
}

#[test]
fn test_verify_sumcheck_layer_count_mismatch() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    proof.sumcheck_proof.pop(); // Remove a layer proof

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        matches!(
            res,
            Err(ZkVerificationError::SumcheckProofLayerMismatch { .. })
        ),
        "Missing sumcheck layer must return SumcheckProofLayerMismatch"
    );
}

#[test]
fn test_verify_sumcheck_round_count_mismatch() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    proof.sumcheck_proof[0].hp[0].pop(); // Remove a round from hand 0

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        matches!(
            res,
            Err(ZkVerificationError::SumcheckProofRoundMismatch { .. })
        ),
        "Mismatched round count must return SumcheckProofRoundMismatch"
    );
}

#[test]
fn test_verify_tampered_sumcheck_round_evals() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    proof.sumcheck_proof[0].hp[0][0].evals[0] += Gf2_128::one(); // Tamper round evaluation

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        res.is_err(),
        "Corrupted round evaluation must cause verification failure"
    );
}

#[test]
fn test_verify_tampered_sumcheck_claims() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    proof.sumcheck_proof[0].claims[0] += Gf2_128::one(); // Tamper layer claim

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        res.is_err(),
        "Corrupted layer claim must cause verification failure"
    );
}

#[test]
fn test_verify_tampered_ligero_proof_evals() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    if !proof.ligero_proof.ldt_poly.is_empty() {
        proof.ligero_proof.ldt_poly[0] += Gf2_128::one(); // Tamper Ligero LDT polynomial eval
    }

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        res.is_err(),
        "Corrupted Ligero polynomial evals must cause verification failure"
    );
}

#[test]
fn test_verify_tampered_ligero_merkle_path() {
    let (verifier, inputs, mut proof, label) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    if !proof.ligero_proof.merkle_paths.is_empty() && !proof.ligero_proof.merkle_paths[0].is_empty()
    {
        proof.ligero_proof.merkle_paths[0][0] ^= 0xff; // Tamper Merkle authentication path
    }

    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        matches!(
            res,
            Err(ZkVerificationError::LigeroVerification(
                LigeroVerificationError::MerkleProofInvalid
            ))
        ),
        "Corrupted Merkle authentication path must return MerkleProofInvalid, got {:?}",
        res
    );
}

#[test]
fn test_verify_wrong_transcript_label() {
    let (verifier, inputs, proof, _) = setup_sha256_fixture();
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];

    let res = verifier.verify(pub_inputs, &proof, "wrong_transcript_label");
    assert!(
        res.is_err(),
        "Verification with wrong transcript label must be rejected"
    );
}
