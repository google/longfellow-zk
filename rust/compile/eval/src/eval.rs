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

pub fn eval_circuit<'a, const W: usize, FR: RuntimeField<W> + core_algebra::SerializableField>(
    fr: &FR,
    circuit: &Circuit<FR>,
    symbols: &'a crate::CircuitDebugSymbols,
    inputs: &[ElementOf<FR>],
) -> crate::CompiledEvalAssertions<'a, EvalError> {
    let raw = &circuit.raw;
    let tracker = &symbols.tracker;

    let vin = match process_inputs(fr, raw.ninput, inputs) {
        Ok(v) => v,
        Err(err) => {
            return crate::CompiledEvalAssertions {
                result: Err(err),
                fates: std::collections::HashMap::new(),
                tracker,
            };
        }
    };

    let mut current_v = vin;
    let mut fates = std::collections::HashMap::new();
    let mut overall_failed = false;

    for l in (0..raw.layers.len()).rev() {
        let noutput = if l == 0 {
            raw.noutput
        } else {
            raw.layers[l - 1].nw()
        };

        let (v, failed_wires) = eval_layer(fr, noutput, &raw.layers[l], &raw.constants, &current_v);
        current_v = v;
        if !failed_wires.is_empty() {
            overall_failed = true;
        }
        for index in failed_wires {
            let wire = crate::WireRef::new(l, index);
            if let Some(id) = symbols.get_id(&wire) {
                fates.insert(
                    id,
                    compile_logic::scope::AssertionStatus::Failed(
                        "layer assertion failed".to_string(),
                    ),
                );
            }
        }
    }

    for (i, y) in current_v.iter().enumerate() {
        let wire = crate::WireRef::new(0, i);
        let is_ok = fr.is_zero(y);
        if !is_ok {
            overall_failed = true;
        }
        if let Some(id) = symbols.get_id(&wire) {
            let status = if is_ok {
                compile_logic::scope::AssertionStatus::Passed
            } else {
                compile_logic::scope::AssertionStatus::Failed("circuit output non-zero".to_string())
            };
            fates.insert(id, status);
        }
    }

    crate::CompiledEvalAssertions {
        result: if overall_failed {
            Err(EvalError::AssertionFailure)
        } else {
            Ok(())
        },
        fates,
        tracker,
    }
}

fn eval_layer<FR: RuntimeField<W> + core_algebra::SerializableField, const W: usize>(
    fr: &FR,
    noutput: usize,
    layer: &Layer<FR>,
    constants: &[ElementOf<FR>],
    vin: &[ElementOf<FR>],
) -> (Vec<ElementOf<FR>>, Vec<usize>) {
    let mut vout = vec![fr.zero(); noutput];
    let mut failed_wires = Vec::new();

    layer.for_each_term(
        constants,
        #[inline(always)]
        |term| {
            let y = fr.mulf(&vin[term.h0 as usize], &vin[term.h1 as usize]);

            if fr.is_zero(&term.k) {
                if !fr.is_zero(&y) {
                    failed_wires.push(term.g as usize);
                }
            } else {
                fr.fma(&mut vout[term.g as usize], &term.k, &y);
            }
        },
    );

    failed_wires.sort_unstable();
    failed_wires.dedup();
    (vout, failed_wires)
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
    'a,
    const WR: usize,
    FC: core_algebra::SerializableField,
    FR: RuntimeField<WR> + core_algebra::SerializableField,
>(
    fc: &FC,
    fr: &FR,
    circuit: &Circuit<FC>,
    symbols: &'a crate::CircuitDebugSymbols,
    inputs: &[ElementOf<FR>],
    field_id: core_proto::FieldID,
) -> Result<crate::CompiledEvalAssertions<'a, EvalError>, String> {
    let converted = convert_circuit(fc, fr, circuit, field_id)?;
    Ok(eval_circuit(fr, &converted, symbols, inputs))
}
