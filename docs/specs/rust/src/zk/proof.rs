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

use std::io::{Read, Write};

use crate::{
    algebra::Field,
    circuit::Circuit,
    ligero::{LigeroConfig, LigeroProof, read_ligero_proof, write_ligero_proof},
    sumcheck::{SumcheckLayerProof, read_sumcheck_proof, write_sumcheck_proof},
};

#[derive(Clone, Debug)]
pub struct ZkProof<F> {
    pub root: [u8; 32],
    pub sumcheck_proof: Vec<SumcheckLayerProof<F>>,
    pub ligero_proof: LigeroProof<F>,
}

pub fn read_zk_proof<F: Field + 'static, R: Read>(
    io: &mut R,
    circuit: &Circuit<F>,
    sf: &F::Subfield,
    config: &LigeroConfig,
) -> std::io::Result<ZkProof<F>> {
    let mut root = [0u8; 32];
    io.read_exact(&mut root)?;
    let sumcheck_proof = read_sumcheck_proof(io, circuit)?;
    let ligero_proof = read_ligero_proof(io, config, circuit, sf)?;
    Ok(ZkProof {
        root,
        sumcheck_proof,
        ligero_proof,
    })
}

pub fn write_zk_proof<F: Field + 'static, W: Write>(
    io: &mut W,
    proof: &ZkProof<F>,
    sf: &F::Subfield,
) -> std::io::Result<()> {
    io.write_all(&proof.root)?;
    write_sumcheck_proof(io, &proof.sumcheck_proof)?;
    write_ligero_proof(io, &proof.ligero_proof, sf)?;
    Ok(())
}
