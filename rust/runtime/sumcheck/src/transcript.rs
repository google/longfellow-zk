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

use core_algebra::SerializableField;
use core_proto::circuit::Circuit;
use runtime_algebra::{field::RuntimeField, ElementOf, SupportsSampling};
use runtime_proto::RoundPoly;
use runtime_random::{RandomEngine, Transcript};

use crate::MAX_LOGW;

/// Extension trait that adds sumcheck-specific helpers to the cryptographic Transcript.
pub trait TranscriptSumcheck {
    /// Writes the sumcheck statement and public parameters to the transcript.
    fn write_sumcheck_statement<const W: usize, F: RuntimeField<W> + SerializableField>(
        &mut self,
        circuit: &Circuit<F>,
        public_inputs: &[ElementOf<F>],
        f: &F,
    );
    /// Samples initial challenge query vectors for the circuit copy and gate variables.
    ///
    /// Because of a quirk of history, the format is defined to always
    /// sample `MAX_LOGW` elements from the transcript, irrespective
    /// of how many are actually needed.
    fn begin_circuit<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        f: &F,
    ) -> (Vec<ElementOf<F>>, Vec<ElementOf<F>>);

    /// Samples alpha and beta challenges at the start of a layer verification.
    fn begin_layer<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        f: &F,
    ) -> (ElementOf<F>, ElementOf<F>);

    /// Writes the layer's proof claims to the transcript at the end of a layer sumcheck.
    fn end_layer<F: SerializableField>(&mut self, claims: &[ElementOf<F>; 2], f: &F);

    /// Writes a round polynomial to the transcript and samples a challenge.
    fn round<const W: usize, F: SerializableField + SupportsSampling<W>>(
        &mut self,
        poly: &RoundPoly<W, F>,
        f: &F,
    ) -> ElementOf<F>;
}

impl TranscriptSumcheck for Transcript {
    fn write_sumcheck_statement<const W: usize, F: RuntimeField<W> + SerializableField>(
        &mut self,
        circuit: &Circuit<F>,
        public_inputs: &[ElementOf<F>],
        f: &F,
    ) {
        assert_eq!(
            public_inputs.len(),
            circuit.raw.npublic_input,
            "Public inputs length mismatch: expected {}, got {}",
            circuit.raw.npublic_input,
            public_inputs.len()
        );
        self.write_bytes(&circuit.id);

        // Public inputs.  This is a quirk in the spec, we should
        // write PUB_INPUTS as an array with a different tag instead
        // of individual field elements.  This is not a soundness problem
        // because npublic_input is part of the circuit id, which we
        // have already hashed.
        for inp in public_inputs.iter().take(circuit.raw.npublic_input) {
            self.write_elt_field(inp, f);
        }

        // Outputs pro-forma:
        self.write_elt_field(&f.zero(), f);

        // Enough zeroes for correlation intractability, one byte per term.
        let nterms = circuit
            .raw
            .layers
            .iter()
            .map(core_proto::Layer::num_terms)
            .sum::<usize>();
        self.write0(nterms);
    }

    fn begin_circuit<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        f: &F,
    ) -> (Vec<ElementOf<F>>, Vec<ElementOf<F>>) {
        let q = self.elt_field_slice(MAX_LOGW, f);
        let g = self.elt_field_slice(MAX_LOGW, f);
        (q, g)
    }

    fn begin_layer<const W: usize, F: SupportsSampling<W>>(
        &mut self,
        f: &F,
    ) -> (ElementOf<F>, ElementOf<F>) {
        let alpha = self.elt_field(f);
        let beta = self.elt_field(f);
        (alpha, beta)
    }

    fn end_layer<F: SerializableField>(&mut self, claims: &[ElementOf<F>; 2], f: &F) {
        self.write_elt_field_slice(claims, f);
    }

    fn round<const W: usize, F: SerializableField + SupportsSampling<W>>(
        &mut self,
        poly: &RoundPoly<W, F>,
        f: &F,
    ) -> ElementOf<F> {
        write_poly(self, poly, f);
        self.elt_field(f)
    }
}

fn write_poly<const W: usize, F: SerializableField>(
    ts: &mut Transcript,
    poly: &RoundPoly<W, F>,
    f: &F,
) {
    for i in 0..2 {
        ts.write_elt_field(&poly.evaluations[i], f);
    }
}
