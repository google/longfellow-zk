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
    algebra::{Field, Gf2_128},
    circuit::Circuit,
    ligero::LigeroConfig,
    zk::{ZkProver, ZkVerifier},
};

pub struct SimpleRng {
    pub state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl reference::algebra::Rng for SimpleRng {
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

fn create_zero_layer_circuit() -> Circuit<Gf2_128> {
    Circuit {
        id: [0u8; 32],
        field_id: 1,
        noutput: 4,
        logv: 2,
        npublic_input: 2,
        subfield_boundary: 2,
        ninput: 4,
        layers: vec![],
    }
}

#[test]
fn test_zero_layer_circuit_with_all_zero_inputs() {
    let circuit = create_zero_layer_circuit();
    let config = LigeroConfig::default();
    let label = "zero_layer_test";

    // All-zero inputs (both public inputs and witnesses are zero)
    let inputs = vec![Gf2_128::zero(); 4];

    let mut rng = SimpleRng::new(12345);
    let prover = ZkProver::new(circuit.clone(), config.clone());
    let commit = prover.commit(&inputs, &mut rng);
    let proof = prover.prove(&inputs, &commit, label);

    let verifier = ZkVerifier::new(circuit, config);
    let pub_inputs = &inputs[..verifier.circuit_data.npublic_input];
    let res = verifier.verify(pub_inputs, &proof, label);
    assert!(
        res.is_ok(),
        "Verification of valid zero-input proof on empty circuit failed"
    );
}

#[test]
fn test_zero_layer_circuit_with_non_zero_inputs_returns_error() {
    let circuit = create_zero_layer_circuit();

    // Non-zero inputs (prover expects circuit output to be zero, which is violated since output is input)
    let inputs = vec![
        Gf2_128::one(),
        Gf2_128::zero(),
        Gf2_128::zero(),
        Gf2_128::zero(),
    ];

    let res = reference::sumcheck::eval_circuit(&inputs, &circuit);
    assert_eq!(
        res,
        Err(reference::sumcheck::CircuitEvaluationError::CircuitOutputNotZero)
    );
}
