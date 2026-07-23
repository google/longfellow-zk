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
public import ECDSA.Nat

/-!
# Elliptic Curve Core Arithmetic and ZK Circuit Specification

This file contains the core definitions and arithmetic formulas for projective elliptic curves
designed to support Zero-Knowledge (ZK) circuit soundness proofs.

This file is designed to be as minimal and clean as possible, serving as the source of truth
for the ZK circuit's mathematical behavior. It is intentionally decoupled from the
mathematical proof machinery and the Mathlib elliptic curve library.

A reviewer can verify that the definitions and formulas in this file match the C++ ZK circuit
constraints line-for-line, without having to wade through Lean proof machinery.

### Contents
1.  Core Types:
    *   `CurveParameters`: Parameters defining a short Weierstrass curve ($y^2 = x^3 + ax + b$)
        and its generator.
    *   `ProjectivePoint`: A triple `(X, Y, Z)` representing a projective point.
    *   `AffinePoint`: A pair `(x, y)` representing an affine point.
2.  Circuit-Matching Formulas:
    *   `addE` and `doubleE`: Complete projective addition and doubling formulas (Renes-Costello-Batten),
        matching the branch-free, division-free C++ implementation.
    *   `circuitStep`: Models a single step in the circuit's scalar multiplication loop.
3.  Mathematical Specifications:
    *   `bsmul`: Binary double-and-add scalar multiplication matching the circuit's loop.

All proof machinery—including the Mathlib bridge, algebraic closure proofs, and high-level
algebraic properties (like associativity)—has been moved to `ECDSA.ECBridge`
to keep this specification file clean.
-/

@[expose] public section

section Types

/--
  Parameters defining an elliptic curve in short Weierstrass form: y^2 = x^3 + a*x + b,
  along with a base point generator (gx, gy).
-/
structure CurveParameters (F : Type) where
  a : F
  b : F
  gx : F
  gy : F
  kBits : Nat
  deriving DecidableEq

/--
  Represents a point on an elliptic curve in projective coordinates (X, Y, Z).
-/
@[ext]
structure ProjectivePoint (F : Type) where
  X : F
  Y : F
  Z : F
  deriving DecidableEq

/--
  Checks if the coordinates of a projective point `p` satisfy the Weierstrass curve equation:
  `Y^2 * Z = X^3 + a * X * Z^2 + b * Z^3`.

  This predicate is purely algebraic and is used as a helper. It is not sufficient on its own
  to define curve membership (`ProjectivePoint.IsOnCurve`) because the invalid point `(0, 0, 0)`
  (which does not represent any point in projective space) trivially satisfies this equation.
  `ProjectivePoint.IsOnCurve` additionally enforces `p ≠ 0` to exclude this invalid point.
-/
def ProjectivePoint.SatisfiesCurveEquation {F : Type} [Field F] (p : ProjectivePoint F) (params : CurveParameters F) : Prop :=
  p.Y * p.Y * p.Z = p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z

/--
  In projective geometry, (0, 0, 0) does not represent any valid point on the projective plane
  and is generally a point to avoid during curve operations.
-/
@[simps]
instance {F : Type} [Zero F] : Zero (ProjectivePoint F) where
  zero := { X := 0, Y := 0, Z := 0 }

@[simps]
instance {M : Type*} {F : Type} [SMul M F] : SMul M (ProjectivePoint F) where
  smul m p := { X := m • p.X, Y := m • p.Y, Z := m • p.Z}

instance {M : Type*} {F : Type} [Monoid M] [MulAction M F] : MulAction M (ProjectivePoint F) where
  one_smul p := by ext <;> exact MulAction.one_smul _
  mul_smul m1 m2 p := by ext <;> exact SemigroupAction.mul_smul _ _ _

lemma smul_projective {F : Type} [Field F] (c : F) (p : ProjectivePoint F) :
    c • p = { X := c * p.X, Y := c * p.Y, Z := c * p.Z } := by
  rfl

/--
  Represents the mathematical point at infinity, conventionally defined in
  projective coordinates as (0, 1, 0).
-/
def infinityPoint {F : Type} [Field F] : ProjectivePoint F :=
  { X := 0, Y := 1, Z := 0 }

def ProjectiveEquiv {F : Type} [Field F] (p1 p2 : ProjectivePoint F) : Prop :=
  ∃ (c : F), c ≠ 0 ∧ p1 = c • p2

lemma ProjectiveEquiv.refl {F : Type} [Field F] (p : ProjectivePoint F) : ProjectiveEquiv p p :=
  ⟨1, one_ne_zero, by simp⟩

lemma ProjectiveEquiv.symm {F : Type} [Field F] {p1 p2 : ProjectivePoint F} :
    ProjectiveEquiv p1 p2 → ProjectiveEquiv p2 p1 := by
  rintro ⟨c, hc_ne, rfl⟩
  use c⁻¹
  refine ⟨inv_ne_zero hc_ne, ?_⟩
  rw [← SemigroupAction.mul_smul, inv_mul_cancel₀ hc_ne, MulAction.one_smul]

lemma ProjectiveEquiv.eq_zero {F : Type} [Field F] {p1 p2 : ProjectivePoint F}
    (h : ProjectiveEquiv p1 p2) (h2 : p2 = 0) : p1 = 0 := by
  rcases h with ⟨c, _, rfl⟩
  rw [h2]
  ext <;> simp

lemma ProjectiveEquiv.eq_zero_iff {F : Type} [Field F] {p1 p2 : ProjectivePoint F}
    (h : ProjectiveEquiv p1 p2) : p1 = 0 ↔ p2 = 0 := by
  constructor
  · intro h1
    exact h.symm.eq_zero h1
  · intro h2
    exact h.eq_zero h2

lemma ProjectiveEquiv.ne_zero_iff {F : Type} [Field F] {p1 p2 : ProjectivePoint F}
    (h : ProjectiveEquiv p1 p2) : p1 ≠ 0 ↔ p2 ≠ 0 :=
  not_congr h.eq_zero_iff

lemma ProjectiveEquiv.y_ne_zero {F : Type} [Field F] {p1 p2 : ProjectivePoint F} (h : ProjectiveEquiv p1 p2) (h_y : p2.Y ≠ 0) : p1.Y ≠ 0 := by
  rcases h with ⟨c, hc_ne, rfl⟩
  rw [smul_projective]
  dsimp
  exact mul_ne_zero hc_ne h_y

lemma ProjectiveEquiv.ne_zero {F : Type} [Field F] {p1 p2 : ProjectivePoint F}
    (h : ProjectiveEquiv p1 p2) (h2 : p2 ≠ 0) : p1 ≠ 0 := by
  rwa [h.ne_zero_iff]

lemma ProjectiveEquiv.trans {F : Type} [Field F] {p1 p2 p3 : ProjectivePoint F} :
    ProjectiveEquiv p1 p2 → ProjectiveEquiv p2 p3 → ProjectiveEquiv p1 p3 := by
  rintro ⟨c1, hc1_ne, rfl⟩ ⟨c2, hc2_ne, rfl⟩
  exact ⟨c1 * c2, mul_ne_zero hc1_ne hc2_ne, by rw [SemigroupAction.mul_smul]⟩

/--
  Represents a point on an elliptic curve in affine coordinates (X, Y).
-/
structure AffinePoint (F : Type) where
  X : F
  Y : F
  deriving DecidableEq

abbrev AffinePoint.toProjective {F : Type} [One F] (p : AffinePoint F) : ProjectivePoint F :=
  { X := p.X, Y := p.Y, Z := 1 }


end Types

section CircuitFormulas

/--
  Doubling of a projective point using the Renes-Costello-Batten (RCB) complete formula.
  This formula is branch-free and complete for all prime order curves in short Weierstrass form.
-/
def doubleE {F : Type} [CommRing F] (p : ProjectivePoint F) (params : CurveParameters F) : ProjectivePoint F :=
  let X := p.X; let Y := p.Y; let Z := p.Z
  let t0 := X * X
  let t1 := Y * Y
  let t2 := Z * Z
  let t3 := X * Y
  let t3_2 := t3 + t3
  let Z3t := X * Z
  let Z3t_2 := Z3t + Z3t
  let a := params.a
  let k3b := params.b + params.b + params.b
  let X3t := a * Z3t_2
  let Y3t := k3b * t2
  let Y3t_2 := X3t + Y3t
  let X3t_2 := t1 - Y3t_2
  let Y3t_3 := t1 + Y3t_2
  let Y3t_4 := X3t_2 * Y3t_3
  let X3t_3 := t3_2 * X3t_2
  let Z3t_3 := k3b * Z3t_2
  let t2_2 := a * t2
  let t3_3 := t0 - t2_2
  let t3_4 := a * t3_3
  let t3_5 := t3_4 + Z3t_3
  let Z3t_4 := t0 + t0
  let t0_2 := Z3t_4 + t0
  let t0_3 := t0_2 + t2_2
  let t0_4 := t0_3 * t3_5
  let Y3t_5 := Y3t_4 + t0_4
  let t2_3 := Y * Z
  let t2_4 := t2_3 + t2_3
  let t0_5 := t2_4 * t3_5
  let X3t_4 := X3t_3 - t0_5
  let Z3t_5 := t2_4 * t1
  let Z3t_6 := Z3t_5 + Z3t_5
  let Z3t_7 := Z3t_6 + Z3t_6
  { X := X3t_4, Y := Y3t_5, Z := Z3t_7 }

/--
  Addition of two projective points using the Renes-Costello-Batten (RCB) complete formula.
  This formula is branch-free and complete for all prime order curves in short Weierstrass form.
-/
def addE {F : Type} [CommRing F] (p1 p2 : ProjectivePoint F) (params : CurveParameters F) : ProjectivePoint F :=
  let X1 := p1.X; let Y1 := p1.Y; let Z1 := p1.Z
  let X2 := p2.X; let Y2 := p2.Y; let Z2 := p2.Z
  let t0 := X1 * X2
  let t1 := Y1 * Y2
  let t2 := Z1 * Z2
  let t3 := (X1 + Y1) * (X2 + Y2)
  let t4 := t0 + t1
  let t3_2 := t3 - t4
  let t4_2 := (X1 + Z1) * (X2 + Z2)
  let t5 := t0 + t2
  let t4_3 := t4_2 - t5
  let t5_2 := (Y1 + Z1) * (Y2 + Z2)
  let X3t := t1 + t2
  let t5_3 := t5_2 - X3t
  let a := params.a
  let k3b := params.b + params.b + params.b
  let Z3t := a * t4_3
  let X3t_2 := k3b * t2
  let Z3t_2 := X3t_2 + Z3t
  let X3t_3 := t1 - Z3t_2
  let Z3t_3 := t1 + Z3t_2
  let Y3t := X3t_3 * Z3t_3
  let t1_2 := t0 + t0
  let t1_3 := t1_2 + t0
  let t2_2 := a * t2
  let t4_4 := k3b * t4_3
  let t1_4 := t1_3 + t2_2
  let t2_3 := t0 - t2_2
  let t2_4 := a * t2_3
  let t4_5 := t4_4 + t2_4
  let t0_2 := t1_4 * t4_5
  let Y3t_2 := Y3t + t0_2
  let t0_3 := t5_3 * t4_5
  let X3t_4 := t3_2 * X3t_3
  let X3t_5 := X3t_4 - t0_3
  let t0_4 := t3_2 * t1_4
  let Z3t_4 := t5_3 * Z3t_3
  let Z3t_5 := Z3t_4 + t0_4
  { X := X3t_5, Y := Y3t_2, Z := Z3t_5 }

def circuitStep {F : Type} [CommRing F] (acc : ProjectivePoint F) (_b : Bool) (tx ty tz : F) (params : CurveParameters F) : ProjectivePoint F :=
  let tPoint : ProjectivePoint F := { X := tx, Y := ty, Z := tz }
  let doubled := doubleE acc params
  addE doubled tPoint params

end CircuitFormulas

section MathSpec

variable {F : Type} [Field F]

lemma addE_smul_left (p1 p2 : ProjectivePoint F) (params : CurveParameters F) (u : F) :
    addE (u • p1) p2 params = u^2 • addE p1 p2 params := by
  unfold addE
  dsimp [HSMul.hSMul, SMul.smul]
  ext <;> ring

lemma addE_smul_right (p1 p2 : ProjectivePoint F) (params : CurveParameters F) (u : F) :
    addE p1 (u • p2) params = u^2 • addE p1 p2 params := by
  unfold addE
  dsimp [HSMul.hSMul, SMul.smul]
  ext <;> ring

lemma addE_smul_both (p1 p2 : ProjectivePoint F) (params : CurveParameters F) (u v : F) :
    addE (u • p1) (v • p2) params = (u^2 * v^2) • addE p1 p2 params := by
  rw [addE_smul_left, addE_smul_right]
  ext <;> dsimp [HSMul.hSMul, SMul.smul] <;> ring

lemma doubleE_infinity (params : CurveParameters F) :
    doubleE infinityPoint params = infinityPoint := by
  unfold doubleE infinityPoint
  dsimp
  ext <;> ring

def AffinePoint.IsOnCurve {F : Type} [Field F] (p : AffinePoint F) (params : CurveParameters F) : Prop :=
  p.Y * p.Y = p.X * p.X * p.X + params.a * p.X + params.b

/--
  Defines scale equivalence between a projective point `p` and an affine point `q`.

  This is a secure and safe formulation because:
  1. The division-free scale equality check: `p.X * 1 = q.X * p.Z` and `p.Y * 1 = q.Y * p.Z`
  2. A non-zero check on `Z`: `p.Z ≠ 0` (which ensures that `p` is a valid finite point and not a point at infinity).

  Enforcing `p.Z ≠ 0` prevents the invalid projective point `(0, 0, 0)` from satisfying the equality.
-/
theorem projectiveEquiv_toProjective_iff {F : Type} [Field F] (p : ProjectivePoint F) (q : AffinePoint F) :
    ProjectiveEquiv p q.toProjective ↔ p.X = q.X * p.Z ∧ p.Y = q.Y * p.Z ∧ p.Z ≠ 0 := by
  constructor
  · rintro ⟨c, hc_ne, h_eq⟩
    have hx : p.X = c * q.X := congr_arg ProjectivePoint.X h_eq
    have hy : p.Y = c * q.Y := congr_arg ProjectivePoint.Y h_eq
    have hz : p.Z = c * 1 := congr_arg ProjectivePoint.Z h_eq
    rw [mul_one] at hz
    refine ⟨?_, ?_, ?_⟩
    · rw [hx, hz, mul_comm]
    · rw [hy, hz, mul_comm]
    · rwa [← hz] at hc_ne
  · rintro ⟨hx, hy, hz⟩
    use p.Z
    refine ⟨hz, ?_⟩
    change p = { X := p.Z * q.X, Y := p.Z * q.Y, Z := p.Z * 1 }
    ext
    · rw [hx, mul_comm]
    · rw [hy, mul_comm]
    · rw [mul_one]

def ProjectivePoint.IsOnCurve {F : Type} [Field F] (p : ProjectivePoint F) (params : CurveParameters F) : Prop :=
  p.SatisfiesCurveEquation params ∧ p ≠ 0

def nsmulFastE {F : Type} [Field F] (n : Nat) (P : ProjectivePoint F) (params : CurveParameters F) : ProjectivePoint F :=
  n.binaryRec infinityPoint (fun b _ acc =>
    let doubled := doubleE acc params
    if b then addE doubled P params else doubled
  )

lemma nsmulFastE_zero {F : Type} [Field F] (P : ProjectivePoint F) (params : CurveParameters F) :
    nsmulFastE 0 P params = infinityPoint := by
  unfold nsmulFastE
  simp

lemma nsmulFastE_bit (b : Bool) (n : Nat) (P : ProjectivePoint F) (params : CurveParameters F) :
    nsmulFastE (Nat.bit b n) P params =
      let acc := nsmulFastE n P params
      let doubled := doubleE acc params
      if b then addE doubled P params else doubled := by
  unfold nsmulFastE
  rw [Nat.binaryRec_eq]
  apply Or.inl
  dsimp
  exact doubleE_infinity params

/--
  Standard mathematical scalar multiplication using MSB-first double-and-add.

  This version takes a `List Bool` representing the scalar in binary. This is
  needed to model the step-by-step execution of the ZK circuit, which
  operates on bits. Proving equivalence between the circuit's loop and
  this specification is done by induction over this bit list.

  This lemma takes the approach of mapping the bits to a nat, and then
  using a notion of nsmul with recursion over the nat to define the
  scalar operation.

  In `ECBridge.lean`, we prove that this is projectively equivalent to Mathlib's
  group action (`•`) applied to `bitsToNat s`, allowing us to use Mathlib's
  algebraic properties for high-level proofs.
-/
def bsmul {F : Type} [Field F] (s : List Bool) (P : ProjectivePoint F) (params : CurveParameters F) : ProjectivePoint F :=
  nsmulFastE (bitsToNat s) P params

end MathSpec

