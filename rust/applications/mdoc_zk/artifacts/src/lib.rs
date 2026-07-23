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

#[must_use]
pub fn load_circuit_lfa1(hash: &str) -> Vec<u8> {
    let path_lfa1 = format!("{}/circuits/{}.lfa1", env!("CARGO_MANIFEST_DIR"), hash);
    if let Ok(bytes) = std::fs::read(&path_lfa1) {
        return bytes;
    }
    let path_lfc1 = format!("{}/circuits/{}.lfc1", env!("CARGO_MANIFEST_DIR"), hash);
    if let Ok(bytes) = std::fs::read(&path_lfc1) {
        return bytes;
    }
    let path_v1 = format!("{}/circuits/{}.v1", env!("CARGO_MANIFEST_DIR"), hash);
    if let Ok(bytes) = std::fs::read(&path_v1) {
        return bytes;
    }
    let path = format!("{}/circuits/{}", env!("CARGO_MANIFEST_DIR"), hash);
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read lfa1 archive file at {path}"))
}

#[must_use]
pub fn load_circuit_lfa2(hash: &str) -> Vec<u8> {
    let path_lfa2 = format!("{}/circuits/{}.lfa2", env!("CARGO_MANIFEST_DIR"), hash);
    if let Ok(bytes) = std::fs::read(&path_lfa2) {
        return bytes;
    }
    let path_lfc2 = format!("{}/circuits/{}.lfc2", env!("CARGO_MANIFEST_DIR"), hash);
    if let Ok(bytes) = std::fs::read(&path_lfc2) {
        return bytes;
    }
    let path_v2 = format!("{}/circuits/{}.v2", env!("CARGO_MANIFEST_DIR"), hash);
    std::fs::read(&path_v2)
        .unwrap_or_else(|_| panic!("Failed to read lfa2 archive file at {path_v2}"))
}

#[must_use]
pub fn load_circuit_lfc1(hash: &str) -> Vec<u8> {
    load_circuit_lfa1(hash)
}

#[must_use]
pub fn load_circuit_lfc2(hash: &str) -> Vec<u8> {
    load_circuit_lfa2(hash)
}

#[must_use]
pub fn load_circuit_v1(hash: &str) -> Vec<u8> {
    load_circuit_lfa1(hash)
}

#[must_use]
pub fn load_circuit_v2(hash: &str) -> Vec<u8> {
    load_circuit_lfa2(hash)
}

#[must_use]
pub fn load_prior_proof(hash: &str) -> Vec<u8> {
    let path = format!("{}/proofs/{}.bin", env!("CARGO_MANIFEST_DIR"), hash);
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read proof file at {path}"))
}

#[must_use]
pub fn load_prior_sig_witness(hash: &str) -> Vec<u8> {
    let path = format!(
        "{}/proofs/{}_sig_witness.bin",
        env!("CARGO_MANIFEST_DIR"),
        hash
    );
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read sig witness file at {path}"))
}

#[must_use]
pub fn load_prior_hash_witness(hash: &str) -> Vec<u8> {
    let path = format!(
        "{}/proofs/{}_hash_witness.bin",
        env!("CARGO_MANIFEST_DIR"),
        hash
    );
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read hash witness file at {path}"))
}

#[must_use]
pub fn all_circuit_hashes() -> &'static [&'static str] {
    &[
        // Version 7
        "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
        "6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad",
        "8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f",
        "5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460",
        // Version 6
        "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
        "b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
        "b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010",
        "c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6",
        // Version 5
        "f88a39e561ec0be02bb3dfe38fb609ad154e98decbbe632887d850fc612fea6f",
        "f51b7248b364462854d306326abded169854697d752d3bb6d9a9446ff7605ddb",
        "c27195e03e22c9ab4efe9e1dabd2c33aa8b2429cc4e86410c6f12542d3c5e0a1",
        "fa5fadfb2a916d3b71144e9b412eff78f71fd6a6d4607eac10de66b195868b7a",
    ]
}
