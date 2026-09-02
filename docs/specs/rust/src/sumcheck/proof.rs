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

use crate::{algebra::Field, circuit::Circuit, io::read_elt_field};

#[derive(Clone, Debug)]
pub struct SumcheckRoundEvals<F> {
    pub evals: [F; 2],
}

#[derive(Clone, Debug)]
pub struct SumcheckLayerProof<F> {
    pub hp: [Vec<SumcheckRoundEvals<F>>; 2],
    pub claims: [F; 2],
}

pub fn read_sumcheck_proof<F: Field, R: Read>(
    io: &mut R,
    circuit: &Circuit<F>,
) -> std::io::Result<Vec<SumcheckLayerProof<F>>> {
    let mut layers = Vec::with_capacity(circuit.layers.len());
    for ly in 0..circuit.layers.len() {
        let clr = &circuit.layers[ly];
        let mut hp0 = Vec::with_capacity(clr.logw);
        let mut hp1 = Vec::with_capacity(clr.logw);

        for _ in 0..clr.logw {
            let hp00 = read_elt_field(io)?;
            let hp10 = read_elt_field(io)?;
            let hp01 = read_elt_field(io)?;
            let hp11 = read_elt_field(io)?;

            hp0.push(SumcheckRoundEvals {
                evals: [hp00, hp01],
            });
            hp1.push(SumcheckRoundEvals {
                evals: [hp10, hp11],
            });
        }

        let claim0 = read_elt_field(io)?;
        let claim1 = read_elt_field(io)?;

        layers.push(SumcheckLayerProof {
            hp: [hp0, hp1],
            claims: [claim0, claim1],
        });
    }
    Ok(layers)
}

pub fn write_sumcheck_proof<F: Field, W: Write>(
    io: &mut W,
    sumcheck_proof: &[SumcheckLayerProof<F>],
) -> std::io::Result<()> {
    for ly in sumcheck_proof {
        for r in 0..ly.hp[0].len() {
            io.write_all(&ly.hp[0][r].evals[0].to_bytes())?;
            io.write_all(&ly.hp[1][r].evals[0].to_bytes())?;
            io.write_all(&ly.hp[0][r].evals[1].to_bytes())?;
            io.write_all(&ly.hp[1][r].evals[1].to_bytes())?;
        }
        io.write_all(&ly.claims[0].to_bytes())?;
        io.write_all(&ly.claims[1].to_bytes())?;
    }
    Ok(())
}
