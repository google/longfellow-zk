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

use core_algebra::ElementOf;
use runtime_algebra::SupportsSampling;
use runtime_proto::Digest;
use runtime_random::{RandomEngine, Transcript};

use crate::param::{LigeroCommitment, LigeroParam};

pub trait TranscriptLigero {
    fn write_commitment(&mut self, commitment: &LigeroCommitment);
    fn write_ligero_statement(&mut self, hash_of_ligero_statement: &Digest);
    fn gen_uldt<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<ElementOf<F>>;
    fn gen_alphal<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        nl: usize,
        f: &F,
    ) -> Vec<ElementOf<F>>;
    fn gen_alphaq<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<[ElementOf<F>; 3]>;
    fn gen_uquad<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<ElementOf<F>>;
    fn gen_idx(&mut self, param: &LigeroParam) -> Vec<usize>;
}

impl TranscriptLigero for Transcript {
    fn write_commitment(&mut self, commitment: &LigeroCommitment) {
        self.write_bytes(&commitment.root.data);
    }

    fn write_ligero_statement(&mut self, hash_of_ligero_statement: &Digest) {
        self.write_bytes(&hash_of_ligero_statement.data);
    }

    fn gen_uldt<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<ElementOf<F>> {
        self.elt_field_slice(param.nwqrow, f)
    }

    fn gen_alphal<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        nl: usize,
        f: &F,
    ) -> Vec<ElementOf<F>> {
        self.elt_field_slice(nl, f)
    }

    fn gen_alphaq<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<[ElementOf<F>; 3]> {
        let mut alpha = vec![[f.zero(), f.zero(), f.zero()]; param.nq];
        for slot in &mut alpha {
            slot[0] = self.elt_field(f);
            slot[1] = self.elt_field(f);
            slot[2] = self.elt_field(f);
        }
        alpha
    }

    fn gen_uquad<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        param: &LigeroParam,
        f: &F,
    ) -> Vec<ElementOf<F>> {
        self.elt_field_slice(param.nqtriples, f)
    }

    fn gen_idx(&mut self, param: &LigeroParam) -> Vec<usize> {
        assert!(param.block_enc >= param.dblock);
        assert!(param.block_enc - param.dblock >= param.nreq);
        let mut idx = vec![0; param.nreq];
        self.choose(&mut idx, param.block_enc - param.dblock, param.nreq);
        idx
    }
}
