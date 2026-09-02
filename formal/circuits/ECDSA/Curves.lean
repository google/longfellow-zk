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
public import ECDSA.ECBridge

open WeierstrassCurve.Projective

@[expose] public section
section CryptoCurves

/-- Field characteristic prime for Secp256k1 -/
def secp256k1_p : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

/-- Fact that secp256k1_p is prime -/
instance : Fact (Nat.Prime secp256k1_p) := ⟨by sorry⟩

/-- Field characteristic prime for P-256 -/
def p256_p : Nat := 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

/-- Fact that p256_p is prime -/
instance : Fact (Nat.Prime p256_p) := ⟨by sorry⟩

-- Base fields
abbrev Fq_secp := ZMod secp256k1_p
abbrev Fq_p256 := ZMod p256_p

-- Specific instances for decidability of projective equivalence relation
instance : DecidableRel (α := Fin 3 → Fq_secp) (· ≈ ·) := by
  intro P Q
  change Decidable (∃ u : Fq_secpˣ, u • Q = P)
  infer_instance

instance : DecidableRel (α := Fin 3 → Fq_p256) (· ≈ ·) := by
  intro P Q
  change Decidable (∃ u : Fq_p256ˣ, u • Q = P)
  infer_instance

noncomputable instance {R : Type*} [CommRing R] (W : WeierstrassCurve R) :
    DecidablePred (NonsingularLift (W' := W)) :=
  fun _ => Classical.propDecidable _

-- NeZero instances for Fq_secp
instance : NeZero (2 : Fq_secp) := NeZero.of_not_dvd (R := Fq_secp) (p := secp256k1_p) (by decide)
instance : NeZero (3 : Fq_secp) := NeZero.of_not_dvd (R := Fq_secp) (p := secp256k1_p) (by decide)

-- NeZero instances for Fq_p256
instance : NeZero (2 : Fq_p256) := NeZero.of_not_dvd (R := Fq_p256) (p := p256_p) (by decide)
instance : NeZero (3 : Fq_p256) := NeZero.of_not_dvd (R := Fq_p256) (p := p256_p) (by decide)

/-- Secp256k1 curve parameters -/
noncomputable def secp256k1_params : CurveParameters Fq_secp := {
  a := 0
  b := 7
  gx := 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  gy := 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  kBits := 256
}
/-- P-256 curve parameters -/
noncomputable def p256_params : CurveParameters Fq_p256 := {
  a := -3
  b := 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  gx := 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
  gy := 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
  kBits := 256
}

lemma secp256k1_elliptic : (secp256k1_params.toMathlib).IsElliptic := by
  rw [WeierstrassCurve.isElliptic_iff]
  rw [isUnit_iff_ne_zero]
  decide

instance : (secp256k1_params.toMathlib).IsElliptic := secp256k1_elliptic

instance : Fact (Odd (Fintype.card (secp256k1_params.toMathlib.toProjective.Point))) := ⟨by sorry⟩

instance : CurveHasNoPointsOfOrder2 secp256k1_params :=
  WeierstrassCurve.toProjective.Point.CurveHasNoPointsOfOrder2 secp256k1_params

lemma p256_elliptic : (p256_params.toMathlib).IsElliptic := by
  rw [WeierstrassCurve.isElliptic_iff]
  rw [isUnit_iff_ne_zero]
  decide

instance : (p256_params.toMathlib).IsElliptic := p256_elliptic

instance : Fact (Odd (Fintype.card (p256_params.toMathlib.toProjective.Point))) := ⟨by sorry⟩

instance : CurveHasNoPointsOfOrder2 p256_params :=
  WeierstrassCurve.toProjective.Point.CurveHasNoPointsOfOrder2 p256_params

end CryptoCurves
