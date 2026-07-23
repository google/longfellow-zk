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
use runtime_algebra::field::RuntimeField;

use crate::{Circuit, Layer};

#[derive(Debug, PartialEq, Eq)]
pub enum EvalError {
    UndefinedInput(usize),
    AssertionFailure,
    InputSizeMismatch { expected: usize, got: usize },
    ExcessiveInput,
}

pub fn initial_inputs<const W: usize, F: RuntimeField<W>>(f: &F) -> Vec<ElementOf<F>> {
    vec![f.one()]
}

pub fn process_inputs<const W: usize, F: RuntimeField<W>>(
    _f: &F,
    ninput: usize,
    inputs: &[ElementOf<F>],
) -> Result<Vec<ElementOf<F>>, EvalError> {
    if inputs.len() == ninput {
        Ok(inputs.to_vec())
    } else {
        Err(EvalError::InputSizeMismatch {
            expected: ninput,
            got: inputs.len(),
        })
    }
}

pub fn eval_circuit<const W: usize, FR: RuntimeField<W> + core_algebra::SerializableField>(
    fr: &FR,
    circuit: &Circuit<FR>,
    symbols: &crate::CircuitDebugSymbols,
    inputs: &[ElementOf<FR>],
) -> crate::CompiledEvalAssertions<EvalError> {
    let raw = &circuit.raw;

    let vin = match process_inputs(fr, raw.ninput, inputs) {
        Ok(v) => v,
        Err(err) => {
            return crate::CompiledEvalAssertions {
                result: Err(err),
                evaluations: Vec::new(),
            };
        }
    };

    let mut current_v = vin;

    for l in (0..raw.layers.len()).rev() {
        let noutput = if l == 0 {
            raw.noutput
        } else {
            raw.layers[l - 1].nw()
        };

        match eval_layer(fr, l, noutput, &raw.layers[l], &raw.constants, &current_v) {
            Ok(v) => current_v = v,
            Err(err) => {
                return crate::CompiledEvalAssertions {
                    result: Err(err),
                    evaluations: Vec::new(),
                };
            }
        }
    }

    let mut evaluations = Vec::new();
    let mut overall_failed = false;

    for (i, y) in current_v.iter().enumerate() {
        let wire = crate::WireRef::new(0, i);
        let path = symbols
            .get_formatted_path(&wire)
            .unwrap_or_else(|| format!("output.{}", i));

        if !fr.is_zero(y) {
            overall_failed = true;
            evaluations.push(crate::EvaluatedCompiledAssertion {
                wire,
                path,
                status: crate::CompiledAssertionStatus::Failed(
                    "circuit output non-zero".to_string(),
                ),
            });
        } else {
            evaluations.push(crate::EvaluatedCompiledAssertion {
                wire,
                path,
                status: crate::CompiledAssertionStatus::Passed,
            });
        }
    }

    crate::CompiledEvalAssertions {
        result: if overall_failed {
            Err(EvalError::AssertionFailure)
        } else {
            Ok(())
        },
        evaluations,
    }
}

fn eval_layer<FR: RuntimeField<W> + core_algebra::SerializableField, const W: usize>(
    fr: &FR,
    _layer_idx: usize,
    noutput: usize,
    layer: &Layer<FR>,
    constants: &[ElementOf<FR>],
    vin: &[ElementOf<FR>],
) -> Result<Vec<ElementOf<FR>>, EvalError> {
    let mut vout = vec![fr.zero(); noutput];
    let mut failed = false;

    layer.for_each_term(
        constants,
        #[inline(always)]
        |term| {
            let y = fr.mulf(&vin[term.h0 as usize], &vin[term.h1 as usize]);

            if fr.is_zero(&term.k) {
                if !fr.is_zero(&y) {
                    failed = true;
                }
            } else {
                fr.fma(&mut vout[term.g as usize], &term.k, &y);
            }
        },
    );

    if failed {
        Err(EvalError::AssertionFailure)
    } else {
        Ok(vout)
    }
}

fn convert_circuit<FC: core_algebra::SerializableField, FR: core_algebra::SerializableField>(
    fc: &FC,
    fr: &FR,
    circuit: &Circuit<FC>,
    field_id: core_proto::FieldID,
) -> Result<Circuit<FR>, String> {
    let writer = core_proto::writer::CircuitWriter::new(fc, field_id);
    let bytes = writer.to_bytes(circuit);
    let reader = core_proto::reader::CircuitReader::new(fr, field_id);
    let (converted_circuit, remaining) = reader.from_bytes(&bytes, true)?;
    if !remaining.is_empty() {
        return Err("Remaining bytes after deserialization".to_string());
    }

    Ok(converted_circuit)
}

pub fn eval_circuit_fc<
    const WR: usize,
    FC: core_algebra::SerializableField,
    FR: RuntimeField<WR> + core_algebra::SerializableField,
>(
    fc: &FC,
    fr: &FR,
    circuit: &Circuit<FC>,
    symbols: &crate::CircuitDebugSymbols,
    inputs: &[ElementOf<FR>],
    field_id: core_proto::FieldID,
) -> Result<crate::CompiledEvalAssertions<EvalError>, String> {
    let converted = convert_circuit(fc, fr, circuit, field_id)?;
    Ok(eval_circuit(fr, &converted, symbols, inputs))
}
