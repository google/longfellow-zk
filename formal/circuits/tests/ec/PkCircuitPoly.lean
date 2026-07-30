/-
# Copyright 2026 Google LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
-/

module
public import Mathlib
public import PkCircuit
public import ECDSA.Curves

/-!
# Polynomial Extraction for secp256k1

This module defines symbolic evaluation of a circuit step over multivariate polynomials.
It is used to extract the symbolic polynomials for the next state coordinates.
-/

@[expose] public section

abbrev Fq := Fq_secp

abbrev SymPoly := MvPolynomial String Fq

/-- Algebraic multiplexing -/
def polyMux {F : Type} [CommRing F] (b : F) (valTrue valFalse : F) : F :=
  b * valTrue + (1 - b) * valFalse

/-- Algebraic circuit step evaluating over polynomials -/
def circuitStepPoly {F : Type} [CommRing F] (acc : ProjectivePoint F) (b : F) (params : CurveParameters F) : ProjectivePoint F :=
  let tx := polyMux b params.gx 0
  let ty := polyMux b params.gy 1
  let tz := polyMux b 1 0
  circuitStep acc true tx ty tz params

/-! ### Symbolic Variables Configuration -/

/--
  Symbolic projective point representing the initial accumulator state.
  Coordinates are variables "accX", "accY", "accZ".
-/
noncomputable def sym_acc : ProjectivePoint SymPoly := {
  X := MvPolynomial.X "accX",
  Y := MvPolynomial.X "accY",
  Z := MvPolynomial.X "accZ"
}

/-- Symbolic variable "b" representing the scalar bit. -/
noncomputable def sym_b : SymPoly := MvPolynomial.X "b"

/--
  Secp256k1 curve parameters with symbolic generator coordinates "gx" and "gy".
-/
noncomputable def sym_secp256k1_params : CurveParameters SymPoly := {
  a := 0,
  b := 7,
  gx := MvPolynomial.X "gx",
  gy := MvPolynomial.X "gy",
  kBits := 256
}

/--
  Extracted projective point after one symbolic circuit step.
  Contains the polynomials representing the next X, Y, Z coordinates.
-/
noncomputable def extractedStep : ProjectivePoint SymPoly :=
  circuitStepPoly sym_acc sym_b sym_secp256k1_params

