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

use std::io::Result;

use core_algebra::{ElementOf, SerializableField};
use runtime_algebra::{field::RuntimeField, Subfield};

use crate::{
    ligero::{LigeroCommitment, LigeroGeometry, LigeroProof},
    sumcheck::{SumcheckProof, SumcheckProofGeometry},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkProofGeometry {
    pub sc_geom: SumcheckProofGeometry,
    pub com_geom: LigeroGeometry,
}

/// A complete Zero-Knowledge proof.
///
/// Contains the sumcheck proof, commitment root,
/// and the Ligero proof over the constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkProof<const W: usize, F: SerializableField> {
    pub sumcheck_proof: SumcheckProof<W, F>,
    pub com: LigeroCommitment,
    pub com_proof: LigeroProof<W, F>,
}

impl<const W: usize, F: RuntimeField<W> + SerializableField> ZkProof<W, F> {
    pub fn write_to_buf<SF: Subfield<E = ElementOf<F>>>(
        &self,
        buf: &mut Vec<u8>,
        geom: &ZkProofGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<()> {
        buf.extend_from_slice(&self.com.root.data);
        self.sumcheck_proof.write_to_buf(buf, &geom.sc_geom, f)?;
        self.com_proof.write_to_buf(buf, &geom.com_geom, f, sf)?;
        Ok(())
    }

    pub fn write<SF: Subfield<E = ElementOf<F>>>(
        &self,
        geom: &ZkProofGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.write_to_buf(&mut buf, geom, f, sf)?;
        Ok(buf)
    }

    pub fn read<SF: Subfield<E = ElementOf<F>>>(
        bytes: &mut &[u8],
        geom: &ZkProofGeometry,
        f: &F,
        sf: &SF,
    ) -> Result<Self> {
        let root_bytes = crate::util::read_bytes_32(bytes)?;
        let com = LigeroCommitment {
            root: crate::Digest { data: root_bytes },
        };

        let sumcheck_proof = SumcheckProof::read(bytes, &geom.sc_geom, f)?;
        let com_proof = LigeroProof::read(bytes, &geom.com_geom, f, sf)?;

        Ok(ZkProof {
            sumcheck_proof,
            com,
            com_proof,
        })
    }
}

/// Calculates the total number of witnesses (nw) and constraints (nq) for the given circuit,
/// taking into account the private/public witness splits and ZK padding variables.
#[must_use]
pub fn witness_and_constraint_count<F: SerializableField>(
    circuit: &core_proto::circuit::Circuit<F>,
) -> (usize, usize) {
    assert!(
        circuit.raw.ninput >= circuit.raw.npublic_input,
        "npublic_input ({}) exceeds ninput ({})",
        circuit.raw.npublic_input,
        circuit.raw.ninput
    );

    let n_witness = circuit.raw.ninput - circuit.raw.npublic_input;
    let mut pad_witness_len = 0;
    for clr in &circuit.raw.layers {
        pad_witness_len += 4 * clr.logw() + 3;
    }
    let nw = n_witness + pad_witness_len;
    let nq = circuit.raw.layers.len();
    (nw, nq)
}
