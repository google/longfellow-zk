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
public import ECDSA.EC

/-!
# Mathlib Bridge and Proof Machinery for Projective Elliptic Curves

This file contains the algebraic foundations, the Mathlib bridge, and the high-level soundness
proofs for the projective elliptic curve formalization. It imports `Mathlib`'s algebraic geometry
library and connects our custom projective formulas to Mathlib's formal group law.

### Contents and Proof Strategy

1. Closure properties:
    *   ZK circuits require division-free, branch-free formulas (like RCB `addE`).
    *   To reason about these, we must first prove they are closed on the curve (`addE_on_curve`,
        `doubleE_on_curve`). This requires proving that the result is never `(0,0,0)` (`addE_nonzero`).
    *   We prove this via coordinate-level case analysis on $Z$-coordinates, using Groebner-basis
        polynomial identities (`addE_nonzero_distinct`).

2.  The Mathlib Bridge:
    *   Once closure is proven, we define mappings from our `ProjectivePoint` to Mathlib's bundled
        `Point` type (`toMathlibPoint`). This requires proving that our `IsOnCurve` predicate
        implies Mathlib's `Nonsingular` predicate.
    *   We prove that our addition is equivalent to Mathlib's group addition (`addE_eq_add`).
    *   We prove that our scalar multiplication is equivalent to Mathlib's group action (`toMathlibPoint_nsmulFastE`, `toMathlibPoint_bsmul`).

3.  Lifted Proofs:
    *   The bridge allows us to "lift" our points to Mathlib, apply Mathlib's group theorems
        (like associativity, distributivity, and `abel` tactic simplification), and "lower" the
        results back to our representation.
    *   This allows us to prove `addE_assoc`, `bsmul_assoc_nat`, and other
        properties in just a few lines of code.

4.  Classical Equivalence:
    *   `IsOnCurve_implies_projective` and `projective_to_affine_on_curve` bridge the
        projective scale-equality checks of the circuit to classical affine curve membership.

### File Structure

The file is organized into the following sections:
- `CurveProperties`: Basic lemmas about curve parameters (e.g. non-existence of order 2 points).
- `CoordinateIdentities`: Low-level coordinate arithmetic and algebraic identities.
- `MathlibBridge`: Mappings between custom projective points and Mathlib points.
- `ProvenProperties`: High-level group properties (commutativity, associativity).
- `AffineProjectiveBridge`: Lemmas connecting projective and affine coordinates.
- `Bsmul`: Soundness of the bit-list scalar multiplication loop.
- `BridgeInstance`: Instantiation of curve properties for specific fields.
-/

@[expose] public section

section CurveProperties

variable {F : Type} [Field F]

/--
  Predicate class: A Weierstrass elliptic curve has no rational points of order 2,
  which is algebraically equivalent to the cubic polynomial having no roots in the field.
-/
class CurveHasNoPointsOfOrder2 {F : Type} [Field F] (params : CurveParameters F) : Prop where
  no_roots : ∀ (x : F), x^3 + params.a * x + params.b ≠ 0

/--
  Lemma: Any valid projective point on the elliptic curve under curve parameters
  has a non-zero Y coordinate if the curve has no rational points of order 2.
-/
lemma ProjectivePoint.IsOnCurve.Y_ne_zero {F : Type} [Field F] {p : ProjectivePoint F} {params : CurveParameters F}
    [h_curve : CurveHasNoPointsOfOrder2 params] (h_on : p.IsOnCurve params) :
    p.Y ≠ 0 := by
  intro hy
  rcases h_on with ⟨h_eq, h_not_zero⟩
  unfold ProjectivePoint.SatisfiesCurveEquation at h_eq
  rw [hy] at h_eq
  simp only [zero_mul, MulZeroClass.zero_mul] at h_eq
  by_cases hz : p.Z = 0
  · rw [hz] at h_eq
    simp only [MulZeroClass.mul_zero, add_zero] at h_eq
    have h_x : p.X = 0 := by
      by_cases hx : p.X = 0
      · exact hx
      · have h_prod : p.X * p.X * p.X ≠ 0 := mul_ne_zero (mul_ne_zero hx hx) hx
        rw [← h_eq] at h_prod
        contradiction
    exact h_not_zero (ProjectivePoint.ext h_x hy hz)
  · let x_val := p.X * p.Z⁻¹
    have h_inv : p.Z⁻¹ * p.Z = 1 := inv_mul_cancel₀ hz
    have h_cube : (x_val^3 + params.a * x_val + params.b) * (p.Z * p.Z * p.Z) = 0 := by
      calc
        (x_val^3 + params.a * x_val + params.b) * (p.Z * p.Z * p.Z)
        _ = (p.X * p.X * p.X) * (p.Z⁻¹ * p.Z) * (p.Z⁻¹ * p.Z) * (p.Z⁻¹ * p.Z) + params.a * p.X * (p.Z⁻¹ * p.Z) * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by ring
        _ = (p.X * p.X * p.X) * 1 * 1 * 1 + params.a * p.X * 1 * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by rw [h_inv]
        _ = p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by ring
        _ = 0 := h_eq.symm
    have hz3 : p.Z * p.Z * p.Z ≠ 0 := mul_ne_zero (mul_ne_zero hz hz) hz
    have h_root : x_val^3 + params.a * x_val + params.b = 0 := by
      cases mul_eq_zero.mp h_cube with
      | inl h_left => exact h_left
      | inr h_right => contradiction
    exact h_curve.no_roots x_val h_root

end CurveProperties

section CoordinateIdentities

/-!
  This section contains coordinate-level algebraic identities for elliptic curve operations
  (addition and doubling) represented in projective coordinates.
  These lemmas are proved using raw polynomial arithmetic (via `linear_combination` and `ring` tactics)
  and do not rely on Mathlib's high-level elliptic curve group theory.
  
  They establish:
  1. Closure properties (e.g., that addition/doubling of points on the curve yields a point on the curve).
  2. Complete addition properties (e.g., handling cases where Z-coordinates are zero).
  3. Key algebraic relations needed to bridge our formulas to Mathlib's projective formulas.
  
  These low-level identities serve as the foundation for the high-level group law proofs
  in the sections below.
-/

open WeierstrassCurve WeierstrassCurve.Projective MvPolynomial

local notation3 "x" => (0 : Fin 3)
local notation3 "y" => (1 : Fin 3)
local notation3 "z" => (2 : Fin 3)

variable {F : Type} [Field F]

/-- Convert our CurveParameters to Mathlib's WeierstrassCurve -/
def CurveParameters.toMathlib (params : CurveParameters F) : WeierstrassCurve F :=
  { a₁ := 0, a₂ := 0, a₃ := 0, a₄ := params.a, a₆ := params.b }

/-- Convert our ProjectivePoint to Mathlib's projective representative (Fin 3 → F) -/
def ProjectivePoint.toMathlib (p : ProjectivePoint F) : Fin 3 → F :=
  ![p.X, p.Y, p.Z]

/-- Convert Mathlib's projective representative (Fin 3 → F) back to our ProjectivePoint -/
def ProjectivePoint.fromMathlib (P : Fin 3 → F) : ProjectivePoint F :=
  { X := P 0, Y := P 1, Z := P 2 }

lemma ProjectiveEquiv_iff_equiv (p1 p2 : ProjectivePoint F) :
    ProjectiveEquiv p1 p2 ↔ p1.toMathlib ≈ p2.toMathlib := by
  constructor
  · rintro ⟨c, hc, h_eq⟩
    use Units.mk0 c hc
    ext i
    fin_cases i
    · have h := congr_arg ProjectivePoint.X h_eq
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h ⊢
      exact h.symm
    · have h := congr_arg ProjectivePoint.Y h_eq
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h ⊢
      exact h.symm
    · have h := congr_arg ProjectivePoint.Z h_eq
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h ⊢
      exact h.symm
  · rintro ⟨u, hu_eq⟩
    use (u : F)
    refine ⟨u.ne_zero, ?_⟩
    ext
    · have h0 := congr_fun hu_eq (0 : Fin 3)
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h0 ⊢
      exact h0.symm
    · have h1 := congr_fun hu_eq (1 : Fin 3)
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h1 ⊢
      exact h1.symm
    · have h2 := congr_fun hu_eq (2 : Fin 3)
      dsimp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h2 ⊢
      exact h2.symm

/-! ## Elliptic Curve Point Closure Lemmas -/

lemma SatisfiesCurveEquation.double {p : ProjectivePoint F} {params : CurveParameters F}
    (h : p.SatisfiesCurveEquation params) :
    (doubleE p params).SatisfiesCurveEquation params := by
  unfold ProjectivePoint.SatisfiesCurveEquation at *
  unfold doubleE
  dsimp
  linear_combination (8 * p.Y^3 * (-9 * p.X^5 * p.Z * params.a^2 - 108 * p.X^4 * p.Z^2 * params.a * params.b + 18 * p.X^3 * p.Z^3 * params.a^3 - 324 * p.X^3 * p.Z^3 * params.b^2 + 18 * p.X^2 * p.Y^2 * p.Z^2 * params.a^2 + 126 * p.X^2 * p.Z^4 * params.a^2 * params.b - 15 * p.X * p.Y^4 * p.Z * params.a + 54 * p.X * p.Y^2 * p.Z^3 * params.a * params.b - 21 * p.X * p.Z^5 * params.a^4 - 27 * p.X * p.Z^5 * params.a * params.b^2 + p.Y^6 - 63 * p.Y^4 * p.Z^2 * params.b - 18 * p.Y^2 * p.Z^4 * params.a^3 - 81 * p.Y^2 * p.Z^4 * params.b^2 - 18 * p.Z^6 * params.a^3 * params.b - 81 * p.Z^6 * params.b^3)) * h

lemma doubleE_eq_addE (p : ProjectivePoint F) (params : CurveParameters F)
    (h_on : p.SatisfiesCurveEquation params) :
    doubleE p params = addE p p params := by
  unfold ProjectivePoint.SatisfiesCurveEquation at h_on
  unfold doubleE addE
  dsimp
  apply ProjectivePoint.ext
  · ring
  · ring
  · linear_combination 6 * p.Y * h_on

set_option maxHeartbeats 5000000 in
lemma SatisfiesCurveEquation.addE {p1 p2 : ProjectivePoint F} {params : CurveParameters F}
    (h1 : p1.SatisfiesCurveEquation params)
    (h2 : p2.SatisfiesCurveEquation params) :
    (addE p1 p2 params).SatisfiesCurveEquation params := by
  unfold ProjectivePoint.SatisfiesCurveEquation at *
  unfold _root_.addE
  dsimp
  linear_combination (-27*p1.X^3*p2.X^5*p2.Y*params.a^2 - 162*p1.X^3*p2.X^4*p2.Y*p2.Z*params.a*params.b + 27*p1.X^3*p2.X^3*p2.Y^3*params.b + 18*p1.X^3*p2.X^3*p2.Y*p2.Z^2*params.a^3 - 243*p1.X^3*p2.X^3*p2.Y*p2.Z^2*params.b^2 - 9*p1.X^3*p2.X^2*p2.Y^3*p2.Z*params.a^2 + 54*p1.X^3*p2.X^2*p2.Y*p2.Z^3*params.a^2*params.b - 3*p1.X^3*p2.X*p2.Y*p2.Z^4*params.a^4 - p1.X^3*p2.Y^3*p2.Z^3*params.a^3 - 27*p1.X^2*p2.X^6*p1.Y*params.a^2 - 162*p1.X^2*p2.X^5*p1.Y*p2.Z*params.a*params.b - 162*p1.X^2*p2.X^5*p2.Y*p1.Z*params.a*params.b + 81*p1.X^2*p2.X^4*p1.Y*p2.Y^2*params.b + 9*p1.X^2*p2.X^4*p1.Y*p2.Z^2*params.a^3 - 243*p1.X^2*p2.X^4*p1.Y*p2.Z^2*params.b^2 + 54*p1.X^2*p2.X^4*p2.Y*p1.Z*p2.Z*params.a^3 - 486*p1.X^2*p2.X^4*p2.Y*p1.Z*p2.Z*params.b^2 - 36*p1.X^2*p2.X^3*p1.Y*p2.Y^2*p2.Z*params.a^2 - 18*p1.X^2*p2.X^3*p2.Y^3*p1.Z*params.a^2 + 216*p1.X^2*p2.X^3*p2.Y*p1.Z*p2.Z^2*params.a^2*params.b + 9*p1.X^2*p2.X^2*p1.Y*p2.Y^4*params.a + 3*p1.X^2*p2.X^2*p1.Y*p2.Z^4*params.a^4 - 81*p1.X^2*p2.X^2*p1.Y*p2.Z^4*params.a*params.b^2 - 12*p1.X^2*p2.X^2*p2.Y*p1.Z*p2.Z^3*params.a^4 - 12*p1.X^2*p2.X*p1.Y*p2.Y^2*p2.Z^3*params.a^3 + 18*p1.X^2*p2.X*p1.Y*p2.Z^5*params.a^3*params.b - 18*p1.X^2*p2.X*p2.Y^3*p1.Z*p2.Z^2*params.a^3 + 18*p1.X^2*p2.X*p2.Y*p1.Z*p2.Z^4*params.a^3*params.b + 3*p1.X^2*p1.Y*p2.Y^4*p2.Z^2*params.a^2 - 9*p1.X^2*p1.Y*p2.Y^2*p2.Z^4*params.a^2*params.b - p1.X^2*p1.Y*p2.Z^6*params.a^5 - 18*p1.X^2*p2.Y^3*p1.Z*p2.Z^3*params.a^2*params.b - 2*p1.X^2*p2.Y*p1.Z*p2.Z^5*params.a^5 - 162*p1.X*p2.X^6*p1.Y*p1.Z*params.a*params.b + 81*p1.X*p2.X^5*p1.Y^2*p2.Y*params.b + 54*p1.X*p2.X^5*p1.Y*p1.Z*p2.Z*params.a^3 - 486*p1.X*p2.X^5*p1.Y*p1.Z*p2.Z*params.b^2 + 36*p1.X*p2.X^5*p2.Y*p1.Z^2*params.a^3 - 243*p1.X*p2.X^5*p2.Y*p1.Z^2*params.b^2 - 54*p1.X*p2.X^4*p1.Y^2*p2.Y*p2.Z*params.a^2 - 54*p1.X*p2.X^4*p1.Y*p2.Y^2*p1.Z*params.a^2 + 135*p1.X*p2.X^4*p1.Y*p1.Z*p2.Z^2*params.a^2*params.b + 297*p1.X*p2.X^4*p2.Y*p1.Z^2*p2.Z*params.a^2*params.b + 9*p1.X*p2.X^3*p1.Y^2*p2.Y^3*params.a - 54*p1.X*p2.X^3*p1.Y^2*p2.Y*p2.Z^2*params.a*params.b - 54*p1.X*p2.X^3*p1.Y*p2.Y^2*p1.Z*p2.Z*params.a*params.b + 12*p1.X*p2.X^3*p1.Y*p1.Z*p2.Z^3*params.a^4 - 324*p1.X*p2.X^3*p1.Y*p1.Z*p2.Z^3*params.a*params.b^2 - 27*p1.X*p2.X^3*p2.Y^3*p1.Z^2*params.a*params.b + 162*p1.X*p2.X^3*p2.Y*p1.Z^2*p2.Z^2*params.a*params.b^2 - 27*p1.X*p2.X^2*p1.Y^2*p2.Y^3*p2.Z*params.b - 24*p1.X*p2.X^2*p1.Y^2*p2.Y*p2.Z^3*params.a^3 - 81*p1.X*p2.X^2*p1.Y^2*p2.Y*p2.Z^3*params.b^2 + 27*p1.X*p2.X^2*p1.Y*p2.Y^4*p1.Z*params.b - 72*p1.X*p2.X^2*p1.Y*p2.Y^2*p1.Z*p2.Z^2*params.a^3 + 144*p1.X*p2.X^2*p1.Y*p1.Z*p2.Z^4*params.a^3*params.b - 243*p1.X*p2.X^2*p1.Y*p1.Z*p2.Z^4*params.b^3 - 24*p1.X*p2.X^2*p2.Y^3*p1.Z^2*p2.Z*params.a^3 + 81*p1.X*p2.X^2*p2.Y^3*p1.Z^2*p2.Z*params.b^2 + 162*p1.X*p2.X^2*p2.Y*p1.Z^2*p2.Z^3*params.a^3*params.b + 243*p1.X*p2.X^2*p2.Y*p1.Z^2*p2.Z^3*params.b^3 + 21*p1.X*p2.X*p1.Y^2*p2.Y^3*p2.Z^2*params.a^2 - 27*p1.X*p2.X*p1.Y^2*p2.Y*p2.Z^4*params.a^2*params.b + 18*p1.X*p2.X*p1.Y*p2.Y^4*p1.Z*p2.Z*params.a^2 - 162*p1.X*p2.X*p1.Y*p2.Y^2*p1.Z*p2.Z^3*params.a^2*params.b - 10*p1.X*p2.X*p1.Y*p1.Z*p2.Z^5*params.a^5 + 108*p1.X*p2.X*p1.Y*p1.Z*p2.Z^5*params.a^2*params.b^2 - 135*p1.X*p2.X*p2.Y^3*p1.Z^2*p2.Z^2*params.a^2*params.b - 20*p1.X*p2.X*p2.Y*p1.Z^2*p2.Z^4*params.a^5 + 81*p1.X*p2.X*p2.Y*p1.Z^2*p2.Z^4*params.a^2*params.b^2 - 3*p1.X*p1.Y^2*p2.Y^5*p2.Z*params.a + 18*p1.X*p1.Y^2*p2.Y^3*p2.Z^3*params.a*params.b - 2*p1.X*p1.Y^2*p2.Y*p2.Z^5*params.a^4 - 27*p1.X*p1.Y^2*p2.Y*p2.Z^5*params.a*params.b^2 + 36*p1.X*p1.Y*p2.Y^4*p1.Z*p2.Z^2*params.a*params.b - 2*p1.X*p1.Y*p2.Y^2*p1.Z*p2.Z^4*params.a^4 - 108*p1.X*p1.Y*p2.Y^2*p1.Z*p2.Z^4*params.a*params.b^2 - 9*p1.X*p1.Y*p1.Z*p2.Z^6*params.a^4*params.b - 108*p1.X*p2.Y^3*p1.Z^2*p2.Z^3*params.a*params.b^2 - 15*p1.X*p2.Y*p1.Z^2*p2.Z^5*params.a^4*params.b + 27*p2.X^6*p1.Y^3*params.b + 45*p2.X^6*p1.Y*p1.Z^2*params.a^3 - 243*p2.X^6*p1.Y*p1.Z^2*params.b^2 - 18*p2.X^5*p1.Y^3*p2.Z*params.a^2 - 63*p2.X^5*p1.Y^2*p2.Y*p1.Z*params.a^2 + 378*p2.X^5*p1.Y*p1.Z^2*p2.Z*params.a^2*params.b + 189*p2.X^5*p2.Y*p1.Z^3*params.a^2*params.b + 9*p2.X^4*p1.Y^3*p2.Y^2*params.a - 216*p2.X^4*p1.Y^2*p2.Y*p1.Z*p2.Z*params.a*params.b - 135*p2.X^4*p1.Y*p2.Y^2*p1.Z^2*params.a*params.b + 9*p2.X^4*p1.Y*p1.Z^2*p2.Z^2*params.a^4 + 162*p2.X^4*p1.Y*p1.Z^2*p2.Z^2*params.a*params.b^2 - 42*p2.X^4*p2.Y*p1.Z^3*p2.Z*params.a^4 + 324*p2.X^4*p2.Y*p1.Z^3*p2.Z*params.a*params.b^2 - 20*p2.X^3*p1.Y^3*p2.Z^3*params.a^3 + 27*p2.X^3*p1.Y^2*p2.Y^3*p1.Z*params.b - 54*p2.X^3*p1.Y^2*p2.Y*p1.Z*p2.Z^2*params.a^3 - 243*p2.X^3*p1.Y^2*p2.Y*p1.Z*p2.Z^2*params.b^2 - 36*p2.X^3*p1.Y*p2.Y^2*p1.Z^2*p2.Z*params.a^3 + 360*p2.X^3*p1.Y*p1.Z^2*p2.Z^3*params.a^3*params.b - 2*p2.X^3*p2.Y^3*p1.Z^3*params.a^3 - 27*p2.X^3*p2.Y^3*p1.Z^3*params.b^2 + 126*p2.X^3*p2.Y*p1.Z^3*p2.Z^2*params.a^3*params.b + 243*p2.X^3*p2.Y*p1.Z^3*p2.Z^2*params.b^3 + 18*p2.X^2*p1.Y^3*p2.Y^2*p2.Z^2*params.a^2 - 45*p2.X^2*p1.Y^3*p2.Z^4*params.a^2*params.b + 51*p2.X^2*p1.Y^2*p2.Y^3*p1.Z*p2.Z*params.a^2 - 198*p2.X^2*p1.Y^2*p2.Y*p1.Z*p2.Z^3*params.a^2*params.b - 3*p2.X^2*p1.Y*p2.Y^4*p1.Z^2*params.a^2 - 432*p2.X^2*p1.Y*p2.Y^2*p1.Z^2*p2.Z^2*params.a^2*params.b - 37*p2.X^2*p1.Y*p1.Z^2*p2.Z^4*params.a^5 + 594*p2.X^2*p1.Y*p1.Z^2*p2.Z^4*params.a^2*params.b^2 - 171*p2.X^2*p2.Y^3*p1.Z^3*p2.Z*params.a^2*params.b - 44*p2.X^2*p2.Y*p1.Z^3*p2.Z^3*params.a^5 + 378*p2.X^2*p2.Y*p1.Z^3*p2.Z^3*params.a^2*params.b^2 - 6*p2.X*p1.Y^3*p2.Y^4*p2.Z*params.a + 36*p2.X*p1.Y^3*p2.Y^2*p2.Z^3*params.a*params.b - 2*p2.X*p1.Y^3*p2.Z^5*params.a^4 - 54*p2.X*p1.Y^3*p2.Z^5*params.a*params.b^2 + 180*p2.X*p1.Y^2*p2.Y^3*p1.Z*p2.Z^2*params.a*params.b - 7*p2.X*p1.Y^2*p2.Y*p1.Z*p2.Z^4*params.a^4 - 324*p2.X*p1.Y^2*p2.Y*p1.Z*p2.Z^4*params.a*params.b^2 + 108*p2.X*p1.Y*p2.Y^4*p1.Z^2*p2.Z*params.a*params.b + 20*p2.X*p1.Y*p2.Y^2*p1.Z^2*p2.Z^3*params.a^4 - 648*p2.X*p1.Y*p2.Y^2*p1.Z^2*p2.Z^3*params.a*params.b^2 - 66*p2.X*p1.Y*p1.Z^2*p2.Z^5*params.a^4*params.b + 324*p2.X*p1.Y*p1.Z^2*p2.Z^5*params.a*params.b^3 + 30*p2.X*p2.Y^3*p1.Z^3*p2.Z^2*params.a^4 - 324*p2.X*p2.Y^3*p1.Z^3*p2.Z^2*params.a*params.b^2 - 87*p2.X*p2.Y*p1.Z^3*p2.Z^4*params.a^4*params.b + 324*p2.X*p2.Y*p1.Z^3*p2.Z^4*params.a*params.b^3 + p1.Y^3*p2.Y^6 - 9*p1.Y^3*p2.Y^4*p2.Z^2*params.b + p1.Y^3*p2.Y^2*p2.Z^4*params.a^3 + 27*p1.Y^3*p2.Y^2*p2.Z^4*params.b^2 - 2*p1.Y^3*p2.Z^6*params.a^3*params.b - 27*p1.Y^3*p2.Z^6*params.b^3 - 18*p1.Y^2*p2.Y^5*p1.Z*p2.Z*params.b - 5*p1.Y^2*p2.Y^3*p1.Z*p2.Z^3*params.a^3 + 108*p1.Y^2*p2.Y^3*p1.Z*p2.Z^3*params.b^2 - 6*p1.Y^2*p2.Y*p1.Z*p2.Z^5*params.a^3*params.b - 162*p1.Y^2*p2.Y*p1.Z*p2.Z^5*params.b^3 - 9*p1.Y*p2.Y^4*p1.Z^2*p2.Z^2*params.a^3 + 108*p1.Y*p2.Y^4*p1.Z^2*p2.Z^2*params.b^2 + 15*p1.Y*p2.Y^2*p1.Z^2*p2.Z^4*params.a^3*params.b - 324*p1.Y*p2.Y^2*p1.Z^2*p2.Z^4*params.b^3 - p1.Y*p1.Z^2*p2.Z^6*params.a^6 - 45*p1.Y*p1.Z^2*p2.Z^6*params.a^3*params.b^2 + 27*p2.Y^3*p1.Z^3*p2.Z^3*params.a^3*params.b - 216*p2.Y^3*p1.Z^3*p2.Z^3*params.b^3 - 2*p2.Y*p1.Z^3*p2.Z^5*params.a^6 - 72*p2.Y*p1.Z^3*p2.Z^5*params.a^3*params.b^2) * h1 + (-36*p1.X^2*p2.X^3*p1.Y^3*p1.Z*params.a^2 + 243*p1.X^2*p2.X^3*p1.Y*p1.Z^3*params.a^2*params.b + 9*p1.X^2*p2.X^2*p1.Y^4*p2.Y*params.a - 162*p1.X^2*p2.X^2*p1.Y^3*p1.Z*p2.Z*params.a*params.b - 243*p1.X^2*p2.X^2*p1.Y^2*p2.Y*p1.Z^2*params.a*params.b - 66*p1.X^2*p2.X^2*p1.Y*p1.Z^3*p2.Z*params.a^4 + 648*p1.X^2*p2.X^2*p1.Y*p1.Z^3*p2.Z*params.a*params.b^2 - 33*p1.X^2*p2.X^2*p2.Y*p1.Z^4*params.a^4 + 324*p1.X^2*p2.X^2*p2.Y*p1.Z^4*params.a*params.b^2 + 27*p1.X^2*p2.X*p1.Y^4*p2.Y*p2.Z*params.b + 54*p1.X^2*p2.X*p1.Y^3*p2.Y^2*p1.Z*params.b + 12*p1.X^2*p2.X*p1.Y^3*p1.Z*p2.Z^2*params.a^3 - 162*p1.X^2*p2.X*p1.Y^3*p1.Z*p2.Z^2*params.b^2 + 36*p1.X^2*p2.X*p1.Y^2*p2.Y*p1.Z^2*p2.Z*params.a^3 - 486*p1.X^2*p2.X*p1.Y^2*p2.Y*p1.Z^2*p2.Z*params.b^2 + 30*p1.X^2*p2.X*p1.Y*p2.Y^2*p1.Z^3*params.a^3 - 162*p1.X^2*p2.X*p1.Y*p2.Y^2*p1.Z^3*params.b^2 - 171*p1.X^2*p2.X*p1.Y*p1.Z^3*p2.Z^2*params.a^3*params.b + 486*p1.X^2*p2.X*p1.Y*p1.Z^3*p2.Z^2*params.b^3 - 207*p1.X^2*p2.X*p2.Y*p1.Z^4*p2.Z*params.a^3*params.b + 243*p1.X^2*p2.X*p2.Y*p1.Z^4*p2.Z*params.b^3 - 3*p1.X^2*p1.Y^4*p2.Y*p2.Z^2*params.a^2 - 12*p1.X^2*p1.Y^3*p2.Y^2*p1.Z*p2.Z*params.a^2 + 18*p1.X^2*p1.Y^3*p1.Z*p2.Z^3*params.a^2*params.b - 9*p1.X^2*p1.Y^2*p2.Y^3*p1.Z^2*params.a^2 + 81*p1.X^2*p1.Y^2*p2.Y*p1.Z^2*p2.Z^2*params.a^2*params.b + 81*p1.X^2*p1.Y*p2.Y^2*p1.Z^3*p2.Z*params.a^2*params.b - 2*p1.X^2*p1.Y*p1.Z^3*p2.Z^3*params.a^5 - 135*p1.X^2*p1.Y*p1.Z^3*p2.Z^3*params.a^2*params.b^2 - p1.X^2*p2.Y*p1.Z^4*p2.Z^2*params.a^5 - 189*p1.X^2*p2.Y*p1.Z^4*p2.Z^2*params.a^2*params.b^2 - 189*p1.X*p2.X^3*p1.Y^3*p1.Z^2*params.a*params.b - 48*p1.X*p2.X^3*p1.Y*p1.Z^4*params.a^4 + 405*p1.X*p2.X^3*p1.Y*p1.Z^4*params.a*params.b^2 + 81*p1.X*p2.X^2*p1.Y^4*p2.Y*p1.Z*params.b + 54*p1.X*p2.X^2*p1.Y^3*p1.Z^2*p2.Z*params.a^3 - 486*p1.X*p2.X^2*p1.Y^3*p1.Z^2*p2.Z*params.b^2 + 87*p1.X*p2.X^2*p1.Y^2*p2.Y*p1.Z^3*params.a^3 - 324*p1.X*p2.X^2*p1.Y^2*p2.Y*p1.Z^3*params.b^2 - 414*p1.X*p2.X^2*p1.Y*p1.Z^4*p2.Z*params.a^3*params.b + 486*p1.X*p2.X^2*p1.Y*p1.Z^4*p2.Z*params.b^3 - 207*p1.X*p2.X^2*p2.Y*p1.Z^5*params.a^3*params.b + 243*p1.X*p2.X^2*p2.Y*p1.Z^5*params.b^3 - 36*p1.X*p2.X*p1.Y^4*p2.Y*p1.Z*p2.Z*params.a^2 - 42*p1.X*p2.X*p1.Y^3*p2.Y^2*p1.Z^2*params.a^2 + 189*p1.X*p2.X*p1.Y^3*p1.Z^2*p2.Z^2*params.a^2*params.b + 405*p1.X*p2.X*p1.Y^2*p2.Y*p1.Z^3*p2.Z*params.a^2*params.b + 162*p1.X*p2.X*p1.Y*p2.Y^2*p1.Z^4*params.a^2*params.b + 16*p1.X*p2.X*p1.Y*p1.Z^4*p2.Z^2*params.a^5 - 621*p1.X*p2.X*p1.Y*p1.Z^4*p2.Z^2*params.a^2*params.b^2 + 32*p1.X*p2.X*p2.Y*p1.Z^5*p2.Z*params.a^5 - 513*p1.X*p2.X*p2.Y*p1.Z^5*p2.Z*params.a^2*params.b^2 + 3*p1.X*p1.Y^4*p2.Y^3*p1.Z*params.a - 27*p1.X*p1.Y^4*p2.Y*p1.Z*p2.Z^2*params.a*params.b - 63*p1.X*p1.Y^3*p2.Y^2*p1.Z^2*p2.Z*params.a*params.b - 10*p1.X*p1.Y^3*p1.Z^2*p2.Z^3*params.a^4 + 27*p1.X*p1.Y^3*p1.Z^2*p2.Z^3*params.a*params.b^2 - 27*p1.X*p1.Y^2*p2.Y^3*p1.Z^3*params.a*params.b - 25*p1.X*p1.Y^2*p2.Y*p1.Z^3*p2.Z^2*params.a^4 + 135*p1.X*p1.Y^2*p2.Y*p1.Z^3*p2.Z^2*params.a*params.b^2 - 16*p1.X*p1.Y*p2.Y^2*p1.Z^4*p2.Z*params.a^4 + 135*p1.X*p1.Y*p2.Y^2*p1.Z^4*p2.Z*params.a*params.b^2 + 18*p1.X*p1.Y*p1.Z^4*p2.Z^3*params.a^4*params.b - 243*p1.X*p1.Y*p1.Z^4*p2.Z^3*params.a*params.b^3 + 33*p1.X*p2.Y*p1.Z^5*p2.Z^2*params.a^4*params.b - 324*p1.X*p2.Y*p1.Z^5*p2.Z^2*params.a*params.b^3 + 27*p2.X^3*p1.Y^5*p1.Z*params.b + 44*p2.X^3*p1.Y^3*p1.Z^3*params.a^3 - 270*p2.X^3*p1.Y^3*p1.Z^3*params.b^2 - 45*p2.X^3*p1.Y*p1.Z^5*params.a^3*params.b + 243*p2.X^3*p1.Y*p1.Z^5*params.b^3 - 18*p2.X^2*p1.Y^5*p1.Z*p2.Z*params.a^2 - 60*p2.X^2*p1.Y^4*p2.Y*p1.Z^2*params.a^2 + 378*p2.X^2*p1.Y^3*p1.Z^3*p2.Z*params.a^2*params.b + 243*p2.X^2*p1.Y^2*p2.Y*p1.Z^4*params.a^2*params.b - 2*p2.X^2*p1.Y*p1.Z^5*p2.Z*params.a^5 - 378*p2.X^2*p1.Y*p1.Z^5*p2.Z*params.a^2*params.b^2 - p2.X^2*p2.Y*p1.Z^6*params.a^5 - 189*p2.X^2*p2.Y*p1.Z^6*params.a^2*params.b^2 + 6*p2.X*p1.Y^5*p2.Y^2*p1.Z*params.a - 27*p2.X*p1.Y^5*p1.Z*p2.Z^2*params.a*params.b - 180*p2.X*p1.Y^4*p2.Y*p1.Z^2*p2.Z*params.a*params.b - 126*p2.X*p1.Y^3*p2.Y^2*p1.Z^3*params.a*params.b - 36*p2.X*p1.Y^3*p1.Z^3*p2.Z^2*params.a^4 + 324*p2.X*p1.Y^3*p1.Z^3*p2.Z^2*params.a*params.b^2 - 44*p2.X*p1.Y^2*p2.Y*p1.Z^4*p2.Z*params.a^4 + 432*p2.X*p1.Y^2*p2.Y*p1.Z^4*p2.Z*params.a*params.b^2 - 2*p2.X*p1.Y*p2.Y^2*p1.Z^5*params.a^4 + 108*p2.X*p1.Y*p2.Y^2*p1.Z^5*params.a*params.b^2 + 21*p2.X*p1.Y*p1.Z^5*p2.Z^2*params.a^4*params.b - 405*p2.X*p1.Y*p1.Z^5*p2.Z^2*params.a*params.b^3 + 33*p2.X*p2.Y*p1.Z^6*p2.Z*params.a^4*params.b - 324*p2.X*p2.Y*p1.Z^6*p2.Z*params.a*params.b^3 + p1.Y^6*p2.Y^3 + 9*p1.Y^5*p2.Y^2*p1.Z*p2.Z*params.b - 2*p1.Y^5*p1.Z*p2.Z^3*params.a^3 - 27*p1.Y^5*p1.Z*p2.Z^3*params.b^2 + 18*p1.Y^4*p2.Y^3*p1.Z^2*params.b - 135*p1.Y^4*p2.Y*p1.Z^2*p2.Z^2*params.b^2 + 4*p1.Y^3*p2.Y^2*p1.Z^3*p2.Z*params.a^3 - 162*p1.Y^3*p2.Y^2*p1.Z^3*p2.Z*params.b^2 - 34*p1.Y^3*p1.Z^3*p2.Z^3*params.a^3*params.b + 54*p1.Y^3*p1.Z^3*p2.Z^3*params.b^3 - p1.Y^2*p2.Y^3*p1.Z^4*params.a^3 - 27*p1.Y^2*p2.Y^3*p1.Z^4*params.b^2 - 57*p1.Y^2*p2.Y*p1.Z^4*p2.Z^2*params.a^3*params.b + 162*p1.Y^2*p2.Y*p1.Z^4*p2.Z^2*params.b^3 - 15*p1.Y*p2.Y^2*p1.Z^5*p2.Z*params.a^3*params.b + 81*p1.Y*p2.Y^2*p1.Z^5*p2.Z*params.b^3 - 2*p1.Y*p1.Z^5*p2.Z^3*params.a^6 - 9*p1.Y*p1.Z^5*p2.Z^3*params.a^3*params.b^2 - 243*p1.Y*p1.Z^5*p2.Z^3*params.b^4 - p2.Y*p1.Z^6*p2.Z^2*params.a^6 + 18*p2.Y*p1.Z^6*p2.Z^2*params.a^3*params.b^2 - 243*p2.Y*p1.Z^6*p2.Z^2*params.b^4) * h2

lemma infinity_on_curve (params : CurveParameters F) :
    infinityPoint.IsOnCurve params := by
  unfold ProjectivePoint.IsOnCurve ProjectivePoint.SatisfiesCurveEquation infinityPoint
  dsimp
  refine ⟨?_, ?_⟩
  · simp
  · intro h
    injection h with hx hy hz
    exact one_ne_zero hy


/-! ## Projective to Classical Affine Algebraic Equivalence Relations -/

lemma ProjectiveEquiv.isOnCurve {p1 p2 : ProjectivePoint F} (params : CurveParameters F)
    (h : ProjectiveEquiv p1 p2) (h1 : p2.IsOnCurve params) :
    p1.IsOnCurve params := by
  rcases h with ⟨c, hc_ne, rfl⟩
  unfold ProjectivePoint.IsOnCurve ProjectivePoint.SatisfiesCurveEquation at *
  constructor
  · rw [smul_projective]
    dsimp
    have h_eq := h1.1
    linear_combination c^3 * h_eq
  · intro h_zero
    have h_p2_zero : p2 = 0 := by
      have h_inv : p2 = c⁻¹ • (c • p2) := by
        rw [← SemigroupAction.mul_smul, inv_mul_cancel₀ hc_ne, MulAction.one_smul]
      rw [h_inv, h_zero]
      rw [smul_projective]
      change ({ X := c⁻¹ * (0 : F), Y := c⁻¹ * (0 : F), Z := c⁻¹ * (0 : F) } : ProjectivePoint F) = ({ X := 0, Y := 0, Z := 0 } : ProjectivePoint F)
      ext <;> ring
    exact h1.2 h_p2_zero

lemma ProjectiveEquiv.doubleE {p1 p2 : ProjectivePoint F} (params : CurveParameters F)
    (h : ProjectiveEquiv p1 p2) : ProjectiveEquiv (_root_.doubleE p1 params) (_root_.doubleE p2 params) := by
  rcases h with ⟨c, hc_ne, rfl⟩
  use c^4
  have hc4_ne : c^4 ≠ 0 := pow_ne_zero 4 hc_ne
  refine ⟨hc4_ne, ?_⟩
  unfold _root_.doubleE
  dsimp only
  rw [smul_projective, smul_projective]
  ext <;> dsimp <;> ring

set_option maxHeartbeats 1000000 in
lemma ProjectiveEquiv.addE {p1 p2 q1 q2 : ProjectivePoint F} (params : CurveParameters F)
    (h1 : ProjectiveEquiv p1 q1) (h2 : ProjectiveEquiv p2 q2) :
    ProjectiveEquiv (_root_.addE p1 p2 params) (_root_.addE q1 q2 params) := by
  rcases h1 with ⟨c1, hc1_ne, rfl⟩
  rcases h2 with ⟨c2, hc2_ne, rfl⟩
  use c1^2 * c2^2
  have hc1_sq_ne : c1^2 ≠ 0 := pow_ne_zero 2 hc1_ne
  have hc2_sq_ne : c2^2 ≠ 0 := pow_ne_zero 2 hc2_ne
  have hmul_ne : c1^2 * c2^2 ≠ 0 := mul_ne_zero hc1_sq_ne hc2_sq_ne
  refine ⟨hmul_ne, ?_⟩
  unfold _root_.addE
  dsimp only
  rw [smul_projective, smul_projective, smul_projective]
  ext <;> dsimp <;> ring

lemma ProjectiveEquiv.nsmulFastE {p1 p2 : ProjectivePoint F} (n : Nat) (params : CurveParameters F)
    (h : ProjectiveEquiv p1 p2) :
    ProjectiveEquiv (_root_.nsmulFastE n p1 params) (_root_.nsmulFastE n p2 params) := by
  induction n using Nat.binaryRec with
  | zero =>
    unfold _root_.nsmulFastE
    rw [Nat.binaryRec_zero, Nat.binaryRec_zero]
    exact ProjectiveEquiv.refl (infinityPoint (F := F))
  | bit b n' ih =>
    rw [nsmulFastE_bit b n' p1 params, nsmulFastE_bit b n' p2 params]
    dsimp
    have h_doubled : ProjectiveEquiv (_root_.doubleE (_root_.nsmulFastE n' p1 params) params) (_root_.doubleE (_root_.nsmulFastE n' p2 params) params) := by
      exact ih.doubleE params
    cases b with
    | false =>
      dsimp
      exact h_doubled
    | true =>
      dsimp
      exact h_doubled.addE params h

lemma ProjectivePoint.X_eq_zero_of_Z_eq_zero (p : ProjectivePoint F) (params : CurveParameters F)
    (h_on : p.IsOnCurve params) (hz : p.Z = 0) : p.X = 0 := by
  have h_eq := h_on.1
  unfold ProjectivePoint.SatisfiesCurveEquation at h_eq
  rw [hz] at h_eq
  have hx3 : p.X^3 = 0 := by
    calc p.X^3 = p.X * p.X * p.X + params.a * p.X * 0 * 0 + params.b * 0 * 0 * 0 := by ring
    _ = p.Y * p.Y * 0 := h_eq.symm
    _ = 0 := by ring
  exact eq_zero_of_pow_eq_zero hx3

lemma ProjectivePoint.Y_ne_zero_of_Z_eq_zero (p : ProjectivePoint F) (params : CurveParameters F)
    (h_on : p.IsOnCurve params) (hz : p.Z = 0) : p.Y ≠ 0 := by
  intro hy
  have h_x := ProjectivePoint.X_eq_zero_of_Z_eq_zero p params h_on hz
  have hp_zero : p = 0 := ProjectivePoint.ext h_x hy hz
  exact h_on.2 hp_zero

lemma doubleE_zero_x_z (Y : F) (params : CurveParameters F) :
    doubleE { X := 0, Y := Y, Z := 0 } params = { X := 0, Y := Y^4, Z := 0 } := by
  unfold doubleE
  ext <;> dsimp <;> ring

lemma doubleE_nonzero [NeZero (2 : F)]
    (p : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params] (h : p.IsOnCurve params) :
    doubleE p params ≠ 0 := by
  intro hp_zero
  by_cases hz : p.Z = 0
  · have hx := ProjectivePoint.X_eq_zero_of_Z_eq_zero p params h hz
    have hy := ProjectivePoint.Y_ne_zero_of_Z_eq_zero p params h hz
    have h_p_val : p = { X := 0, Y := p.Y, Z := 0 } := ProjectivePoint.ext hx rfl hz
    rw [h_p_val] at hp_zero
    rw [doubleE_zero_x_z p.Y params] at hp_zero
    have hy4_zero : p.Y^4 = 0 := congr_arg ProjectivePoint.Y hp_zero
    have hy_zero2 : p.Y = 0 := eq_zero_of_pow_eq_zero hy4_zero
    exact hy hy_zero2
  · have hz_dbl : (doubleE p params).Z = 0 := congr_arg ProjectivePoint.Z hp_zero
    have h_dbl_z_val : (doubleE p params).Z = 8 * p.Y^3 * p.Z := by
      unfold doubleE
      dsimp
      ring
    rw [h_dbl_z_val] at hz_dbl
    have h_y3_zero : p.Y^3 = 0 := by
      have h_mul1 : 8 * p.Y^3 = 0 ∨ p.Z = 0 := mul_eq_zero.mp hz_dbl
      rcases h_mul1 with h8y3 | hz_zero
      · have h_mul2 : (8 : F) = 0 ∨ p.Y^3 = 0 := mul_eq_zero.mp h8y3
        rcases h_mul2 with h8 | hy3
        · have h2 : (2 : F) ≠ 0 := NeZero.ne 2
          have h8_val : (8 : F) = 2^3 := by ring
          rw [h8_val] at h8
          have h2_zero := eq_zero_of_pow_eq_zero h8
          contradiction
        · exact hy3
      · contradiction
    have hy_zero := eq_zero_of_pow_eq_zero h_y3_zero
    have h_on_eq := h.1
    unfold ProjectivePoint.SatisfiesCurveEquation at h_on_eq
    have h_num : p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z = 0 := by
      calc p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z
        = p.Y * p.Y * p.Z := h_on_eq.symm
        _ = 0 * 0 * p.Z := by rw [hy_zero]
        _ = 0 := by ring
    have h_div : (p.X / p.Z)^3 + params.a * (p.X / p.Z) + params.b = 0 := by
      have h_nz_pow : p.Z^3 ≠ 0 := pow_ne_zero 3 hz
      apply mul_left_cancel₀ h_nz_pow
      have h_inv : p.Z * p.Z⁻¹ = 1 := mul_inv_cancel₀ hz
      calc p.Z^3 * ((p.X / p.Z)^3 + params.a * (p.X / p.Z) + params.b)
        = p.Z^3 * ((p.X * p.Z⁻¹)^3 + params.a * (p.X * p.Z⁻¹) + params.b) := by simp only [div_eq_mul_inv]
        _ = p.X * p.X * p.X * (p.Z * p.Z⁻¹)^3 + params.a * p.X * p.Z * p.Z * (p.Z * p.Z⁻¹) + params.b * p.Z * p.Z * p.Z := by ring
        _ = p.X * p.X * p.X * 1^3 + params.a * p.X * p.Z * p.Z * 1 + params.b * p.Z * p.Z * p.Z := by rw [h_inv]
        _ = p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by ring
        _ = 0 := h_num
        _ = p.Z^3 * 0 := by ring
    exact h_curve.no_roots (p.X / p.Z) h_div

/--
  Proves that doubling a point on the curve yields another point on the curve.
  This establishes the algebraic closure of the doubling operation.
-/
lemma doubleE_on_curve [NeZero (2 : F)]
    (p : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h : p.IsOnCurve params) :
    (doubleE p params).IsOnCurve params := by
  constructor
  · exact SatisfiesCurveEquation.double h.1
  · exact doubleE_nonzero p params h

set_option maxHeartbeats 800000 in
lemma addE_nonzero_distinct [NeZero (2 : F)]
    (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (hz1 : p1.Z = 1) (hz2 : p2.Z = 1) (h_x : p1.X ≠ p2.X) :
    addE p1 p2 params ≠ 0 := by
  intro hp_zero
  have hz3 : (addE p1 p2 params).Z = 0 := congr_arg ProjectivePoint.Z hp_zero
  have h_on1_copy := h_on1.1
  have h_on2_copy := h_on2.1
  unfold ProjectivePoint.SatisfiesCurveEquation at h_on1_copy h_on2_copy
  rw [hz1] at h_on1_copy
  rw [hz2] at h_on2_copy
  let X1 := p1.X; let Y1 := p1.Y
  let X2 := p2.X; let Y2 := p2.Y
  let a := params.a; let b := params.b
  have h_eq1_simp : Y1 * Y1 - X1 * X1 * X1 - a * X1 - b = 0 := by
    calc Y1 * Y1 - X1 * X1 * X1 - a * X1 - b
      = Y1 * Y1 * 1 - (X1 * X1 * X1 + a * X1 * 1 * 1 + b * 1 * 1 * 1) := by ring
      _ = 0 := by rw [h_on1_copy]; ring
  have h_eq2_simp : Y2 * Y2 - X2 * X2 * X2 - a * X2 - b = 0 := by
    calc Y2 * Y2 - X2 * X2 * X2 - a * X2 - b
      = Y2 * Y2 * 1 - (X2 * X2 * X2 + a * X2 * 1 * 1 + b * 1 * 1 * 1) := by ring
      _ = 0 := by rw [h_on2_copy]; ring
  have h_z3_val : (addE p1 p2 params).Z = (Y1 + Y2) * (Y1 * Y2 + (b + b + b) + a * (X1 + X2)) + (X1 * Y2 + Y1 * X2) * (3 * X1 * X2 + a) := by
    unfold addE
    dsimp
    rw [hz1, hz2]
    ring
  rw [h_z3_val] at hz3
  let N := (Y1 + Y2) * (Y1 + Y2) - (X1 + X2) * (X1 - X2) * (X1 - X2)
  let D := (X1 - X2) * (X1 - X2)
  let target := N * N * N + a * N * D * D + b * D * D * D
  let Coeff_0 := X1^6 - 3*X1^5*X2 + 8*X1^3*X2^3 - 2*X1^3*X2*a - 2*X1^3*Y1^2 - 6*X1^3*Y1*Y2 - 3*X1^3*Y2^2 - 2*X1^3*b - 6*X1^2*X2^4 + 9*X1^2*X2^2*a + 3*X1^2*X2*Y1^2 + 12*X1^2*X2*Y1*Y2 + 6*X1^2*X2*Y2^2 + 9*X1^2*X2*b - 6*X1*X2^5 - 13*X1*X2^3*a + 3*X1*X2^2*Y1^2 + 6*X1*X2^2*Y1*Y2 + 12*X1*X2^2*Y2^2 - 15*X1*X2^2*b + 2*X1*X2*a^2 + X1*Y1^2*a + 4*X1*Y1*Y2*a + 2*X1*Y2^2*a + 2*X1*a*b + 8*X2^6 + X2^4*a - 4*X2^3*Y1^2 - 24*X2^3*Y1*Y2 - 12*X2^3*Y2^2 + 12*X2^3*b - 9*X2^2*a^2 - X2*Y1^2*a - 16*X2*Y1*Y2*a + 10*X2*Y2^2*a - 7*X2*a*b + Y1^4 + 6*Y1^3*Y2 + 15*Y1^2*Y2^2 + 30*Y1*Y2^3 - 12*Y1*Y2*b + 3*Y2^4 + 3*Y2^2*b + 2*b^2
  let Coeff_1 := 18*X1^3*Y1*Y2 + 15*X1^2*X2^2*a + 6*X1^2*X2*Y1^2 + 6*X1^2*X2*Y1*Y2 + 3*X1^2*X2*Y2^2 - 9*X1^2*X2*b - 2*X1^2*a^2 - 3*X1*X2^5 - 10*X1*X2^3*a + 12*X1*X2^2*Y1*Y2 + 3*X1*X2^2*Y2^2 + 15*X1*X2^2*b + 9*X1*X2*a^2 + 7*X1*Y1^2*a + 26*X1*Y1*Y2*a + 3*X1*Y2^2*a - 4*X1*a*b + X2^6 + 5*X2^3*Y1^2 - 6*X2^3*Y1*Y2 - 2*X2^3*Y2^2 - 10*X2^3*b - 5*X2*Y1^2*a + 4*X2*Y1*Y2*a + X2*Y2^2*a + 9*X2*a*b - Y1^4 - 12*Y1^3*Y2 + 11*Y1^2*Y2^2 + 11*Y1^2*b + 6*Y1*Y2^3 + 30*Y1*Y2*b + Y2^4 + 4*Y2^2*b - 2*b^2
  let Coeff_2 := 3*X1^2*X2*Y2 + 3*X1*X2^2*Y1 + X1*Y1*a + 2*X1*Y2*a + 2*X2*Y1*a + X2*Y2*a + Y1^2*Y2 + Y1*Y2^2 + 3*Y1*b + 3*Y2*b
  have h_identity : target = Coeff_0 * (Y1 * Y1 - X1 * X1 * X1 - a * X1 - b) + Coeff_1 * (Y2 * Y2 - X2 * X2 * X2 - a * X2 - b) + Coeff_2 * ((Y1 + Y2) * (Y1 * Y2 + (b + b + b) + a * (X1 + X2)) + (X1 * Y2 + Y1 * X2) * (3 * X1 * X2 + a)) := by
    dsimp [target, N, D, Coeff_0, Coeff_1, Coeff_2]
    ring
  have h_target_zero : target = 0 := by
    rw [h_identity]
    rw [h_eq1_simp, h_eq2_simp, hz3]
    ring
  have h_D_ne : D ≠ 0 := by
    intro hD
    have h_sub : X1 - X2 = 0 := by
      have h_mul : (X1 - X2) * (X1 - X2) = 0 := hD
      rcases mul_eq_zero.mp h_mul with h | h
      · exact h
      · exact h
    have h_eq_x : X1 = X2 := eq_of_sub_eq_zero h_sub
    exact h_x h_eq_x
  have h_nz_D3 : D * D * D ≠ 0 := mul_ne_zero (mul_ne_zero h_D_ne h_D_ne) h_D_ne
  have h_div : (N / D)^3 + a * (N / D) + b = 0 := by
    apply mul_left_cancel₀ h_nz_D3
    have h_inv : D * D⁻¹ = 1 := mul_inv_cancel₀ h_D_ne
    calc (D * D * D) * ((N / D)^3 + a * (N / D) + b)
      = (D * D * D) * ((N * D⁻¹)^3 + a * (N * D⁻¹) + b) := by simp only [div_eq_mul_inv]
      _ = N * N * N * (D * D⁻¹)^3 + a * N * D * D * (D * D⁻¹) + b * D * D * D := by ring
      _ = N * N * N * 1^3 + a * N * D * D * 1 + b * D * D * D := by rw [h_inv]
      _ = N * N * N + a * N * D * D + b * D * D * D := by ring
      _ = target := rfl
      _ = 0 := h_target_zero
      _ = (D * D * D) * 0 := by ring
  exact h_curve.no_roots (N / D) h_div

lemma addE_opposite_Y (p : ProjectivePoint F) (params : CurveParameters F) (hz : p.Z = 1) :
    (addE p { X := p.X, Y := -p.Y, Z := 1 } params).Y = (doubleE p params).Y := by
  unfold addE doubleE
  dsimp
  rw [hz]
  ring

lemma addE_opposite_XZ (p : ProjectivePoint F) (params : CurveParameters F) (hz : p.Z = 1) :
    (addE p { X := p.X, Y := -p.Y, Z := 1 } params).X = 0 ∧ (addE p { X := p.X, Y := -p.Y, Z := 1 } params).Z = 0 := by
  unfold addE
  dsimp
  rw [hz]
  constructor <;> ring

lemma addE_nonzero_case4 (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (hz1 : p1.Z = 0) (hz2 : p2.Z = 0) :
    addE p1 p2 params ≠ 0 := by
  have hx1 := ProjectivePoint.X_eq_zero_of_Z_eq_zero p1 params h_on1 hz1
  have hx2 := ProjectivePoint.X_eq_zero_of_Z_eq_zero p2 params h_on2 hz2
  have hy1 := ProjectivePoint.Y_ne_zero_of_Z_eq_zero p1 params h_on1 hz1
  have hy2 := ProjectivePoint.Y_ne_zero_of_Z_eq_zero p2 params h_on2 hz2
  unfold addE
  simp [hx1, hz1, hx2, hz2]
  intro h_zero
  injection h_zero with _ hy_zero _
  rcases mul_eq_zero.mp hy_zero with hA | hB
  · rcases mul_eq_zero.mp hA with hA1 | hA2
    · exact hy1 hA1
    · exact hy2 hA2
  · rcases mul_eq_zero.mp hB with hB1 | hB2
    · exact hy1 hB1
    · exact hy2 hB2

lemma addE_nonzero_case3 (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (hz1 : p1.Z = 0) (hz2 : p2.Z ≠ 0) :
    addE p1 p2 params ≠ 0 := by
  have hx1 := ProjectivePoint.X_eq_zero_of_Z_eq_zero p1 params h_on1 hz1
  have hy1 := ProjectivePoint.Y_ne_zero_of_Z_eq_zero p1 params h_on1 hz1
  have hy2 : p2.Y ≠ 0 := h_on2.Y_ne_zero
  unfold addE
  simp [hx1, hz1]
  intro h_zero
  injection h_zero with _ _ hz_zero
  rcases mul_eq_zero.mp hz_zero with hA | hB
  · have h_ring : p1.Y * (p2.Y + p2.Z) - p1.Y * p2.Y = p1.Y * p2.Z := by ring
    rw [h_ring] at hA
    rcases mul_eq_zero.mp hA with hy1_zero | hz2_zero
    · exact hy1 hy1_zero
    · exact hz2 hz2_zero
  · rcases mul_eq_zero.mp hB with hy1_zero | hy2_zero
    · exact hy1 hy1_zero
    · exact hy2 hy2_zero

lemma addE_nonzero_case2 (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (hz1 : p1.Z ≠ 0) (hz2 : p2.Z = 0) :
    addE p1 p2 params ≠ 0 := by
  have hx2 := ProjectivePoint.X_eq_zero_of_Z_eq_zero p2 params h_on2 hz2
  have hy2 := ProjectivePoint.Y_ne_zero_of_Z_eq_zero p2 params h_on2 hz2
  have hy1 : p1.Y ≠ 0 := h_on1.Y_ne_zero
  unfold addE
  simp [hx2, hz2]
  intro h_zero
  injection h_zero with _ _ hz_zero
  rcases mul_eq_zero.mp hz_zero with hA | hB
  · have h_ring : (p1.Y + p1.Z) * p2.Y - p1.Y * p2.Y = p1.Z * p2.Y := by ring
    rw [h_ring] at hA
    rcases mul_eq_zero.mp hA with hz1_zero | hy2_zero
    · exact hz1 hz1_zero
    · exact hy2 hy2_zero
  · rcases mul_eq_zero.mp hB with hy1_zero | hy2_zero
    · exact hy1 hy1_zero
    · exact hy2 hy2_zero

lemma addE_nonzero_opposite [NeZero (2 : F)] [NeZero (3 : F)]
    (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (hz1 : p1.Z = 1) (hz2 : p2.Z = 1)
    (h_x : p1.X = p2.X) (h_not_equiv : ¬ p1.toMathlib ≈ p2.toMathlib) :
    addE p1 p2 params ≠ 0 := by
  have h_y_eq : p2.Y = -p1.Y := by
    have h_eq1 := h_on1.1
    have h_eq2 := h_on2.1
    unfold ProjectivePoint.SatisfiesCurveEquation at h_eq1 h_eq2
    rw [hz1] at h_eq1
    rw [hz2] at h_eq2
    rw [h_x] at h_eq1
    have h_trans : p1.Y * p1.Y * 1 = p2.Y * p2.Y * 1 := h_eq1.trans h_eq2.symm
    have h_y_sq : p1.Y^2 = p2.Y^2 := by linear_combination h_trans
    have h_sub_sq : p1.Y^2 - p2.Y^2 = 0 := sub_eq_zero.mpr h_y_sq
    have h_factor : (p1.Y - p2.Y) * (p1.Y + p2.Y) = 0 := by
      calc (p1.Y - p2.Y) * (p1.Y + p2.Y) = p1.Y^2 - p2.Y^2 := by ring
      _ = 0 := h_sub_sq
    rcases mul_eq_zero.mp h_factor with hy_sub | hy_add
    · have hy_eq : p1.Y = p2.Y := eq_of_sub_eq_zero hy_sub
      have hp_eq : p1 = p2 := ProjectivePoint.ext h_x hy_eq (hz1.trans hz2.symm)
      have hp_equiv : p1.toMathlib ≈ p2.toMathlib := by
        rw [← ProjectiveEquiv_iff_equiv]
        rw [hp_eq]
        exact ProjectiveEquiv.refl _
      contradiction
    · have hy_eq : p2.Y = -p1.Y := by linear_combination hy_add
      exact hy_eq
  have hp2_val : p2 = { X := p1.X, Y := -p1.Y, Z := 1 } := ProjectivePoint.ext h_x.symm h_y_eq hz2
  rw [hp2_val]
  intro h_zero
  have h_Y_eq := addE_opposite_Y p1 params hz1
  have h_XZ_eq := addE_opposite_XZ p1 params hz1
  have h_add_val : addE p1 { X := p1.X, Y := -p1.Y, Z := 1 } params = { X := 0, Y := (doubleE p1 params).Y, Z := 0 } := by
    apply ProjectivePoint.ext
    · exact h_XZ_eq.1
    · exact h_Y_eq
    · exact h_XZ_eq.2
  rw [h_add_val] at h_zero
  have h_dbl_Y_zero : (doubleE p1 params).Y = 0 := congr_arg ProjectivePoint.Y h_zero
  have h_dbl_on := doubleE_on_curve p1 params h_on1
  have h_dbl_Y_ne := h_dbl_on.Y_ne_zero
  exact h_dbl_Y_ne h_dbl_Y_zero

lemma addE_nonzero_of_not_equiv [NeZero (2 : F)] [NeZero (3 : F)]
    (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_curve : CurveHasNoPointsOfOrder2 params]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (h_not_equiv : ¬ p1.toMathlib ≈ p2.toMathlib) :
    addE p1 p2 params ≠ 0 := by
  by_cases hz1 : p1.Z = 0
  · by_cases hz2 : p2.Z = 0
    · exact addE_nonzero_case4 p1 p2 params h_on1 h_on2 hz1 hz2
    · exact addE_nonzero_case3 p1 p2 params h_on1 h_on2 hz1 hz2
  · by_cases hz2 : p2.Z = 0
    · exact addE_nonzero_case2 p1 p2 params h_on1 h_on2 hz1 hz2
    · let c1 := p1.Z⁻¹
      let c2 := p2.Z⁻¹
      have hc1_ne : c1 ≠ 0 := inv_ne_zero hz1
      have hc2_ne : c2 ≠ 0 := inv_ne_zero hz2
      let p1' := c1 • p1
      let p2' := c2 • p2
      have hp1'_Z : p1'.Z = 1 := by
        dsimp [p1']
        exact inv_mul_cancel₀ hz1
      have hp2'_Z : p2'.Z = 1 := by
        dsimp [p2']
        exact inv_mul_cancel₀ hz2
      have hp1_equiv : ProjectiveEquiv p1 p1' := by
        use c1⁻¹
        refine ⟨inv_ne_zero hc1_ne, ?_⟩
        rw [← SemigroupAction.mul_smul, inv_mul_cancel₀ hc1_ne, MulAction.one_smul]
      have hp2_equiv : ProjectiveEquiv p2 p2' := by
        use c2⁻¹
        refine ⟨inv_ne_zero hc2_ne, ?_⟩
        rw [← SemigroupAction.mul_smul, inv_mul_cancel₀ hc2_ne, MulAction.one_smul]
      have hp1'_on : p1'.IsOnCurve params := ProjectiveEquiv.isOnCurve params hp1_equiv.symm h_on1
      have hp2'_on : p2'.IsOnCurve params := ProjectiveEquiv.isOnCurve params hp2_equiv.symm h_on2
      have h_not_equiv' : ¬ p1'.toMathlib ≈ p2'.toMathlib := by
        intro h_equiv'
        have hp1'_equiv_p2' : ProjectiveEquiv p1' p2' := by
          rw [ProjectiveEquiv_iff_equiv]
          exact h_equiv'
        have hp1_equiv_p2 : ProjectiveEquiv p1 p2 :=
          ProjectiveEquiv.trans hp1_equiv (ProjectiveEquiv.trans hp1'_equiv_p2' hp2_equiv.symm)
        have h_equiv_mathlib : p1.toMathlib ≈ p2.toMathlib := by
          rw [← ProjectiveEquiv_iff_equiv]
          exact hp1_equiv_p2
        exact h_not_equiv h_equiv_mathlib
      by_cases h_x : p1'.X = p2'.X
      · have h_nz' := addE_nonzero_opposite p1' p2' params hp1'_on hp2'_on hp1'_Z hp2'_Z h_x h_not_equiv'
        have h_add_equiv : ProjectiveEquiv (addE p1 p2 params) (addE p1' p2' params) :=
          hp1_equiv.addE params hp2_equiv
        exact ProjectiveEquiv.ne_zero h_add_equiv h_nz'
      · have h_nz' := addE_nonzero_distinct p1' p2' params hp1'_on hp2'_on hp1'_Z hp2'_Z h_x
        have h_add_equiv : ProjectiveEquiv (addE p1 p2 params) (addE p1' p2' params) :=
          hp1_equiv.addE params hp2_equiv
        exact ProjectiveEquiv.ne_zero h_add_equiv h_nz'

lemma doubleE_eq_dblXYZ (p : ProjectivePoint F) (params : CurveParameters F)
    (h_on : p.SatisfiesCurveEquation params) :
    (doubleE p params).toMathlib = (params.toMathlib).toProjective.dblXYZ p.toMathlib := by
  unfold ProjectivePoint.SatisfiesCurveEquation at h_on
  unfold ProjectivePoint.toMathlib doubleE WeierstrassCurve.Projective.dblXYZ
  unfold WeierstrassCurve.Projective.dblX WeierstrassCurve.Projective.dblY WeierstrassCurve.Projective.dblZ
  unfold WeierstrassCurve.Projective.negDblY CurveParameters.toMathlib WeierstrassCurve.Projective.negY
  dsimp
  ext i
  fin_cases i
  · simp
    ring
  · simp
    linear_combination (9 * params.b * p.Z - 3 * params.a * p.X) * h_on
  · simp
    ring

lemma equiv_of_cross_mul (params : CurveParameters F) {P Q : Fin 3 → F}
    (hP : (params.toMathlib).toProjective.Equation P) (hQ : (params.toMathlib).toProjective.Equation Q)
    (hP_nz : P ≠ 0) (hQ_nz : Q ≠ 0)
    (hx : P x * Q z = Q x * P z) (hy : P y * Q z = Q y * P z) : P ≈ Q := by
  by_cases hPz : P z = 0
  · have hQz : Q z = 0 := by
      have hPx : P x = 0 := X_eq_zero_of_Z_eq_zero hP hPz
      have hPy : P y ≠ 0 := by
        intro h
        apply hP_nz
        ext i
        fin_cases i
        · exact hPx
        · exact h
        · exact hPz
      have h_mul : P y * Q z = 0 := by
        calc P y * Q z = Q y * P z := hy
        _ = Q y * 0 := by rw [hPz]
        _ = 0 := mul_zero _
      exact mul_eq_zero.mp h_mul |>.resolve_left hPy
    have hPx : P x = 0 := X_eq_zero_of_Z_eq_zero hP hPz
    have hQx : Q x = 0 := X_eq_zero_of_Z_eq_zero hQ hQz
    have hPy : P y ≠ 0 := by
      intro h
      apply hP_nz
      ext i; fin_cases i <;> assumption
    have hQy : Q y ≠ 0 := by
      intro h
      apply hQ_nz
      ext i; fin_cases i <;> assumption
    use Units.mk0 (P y / Q y) (div_ne_zero hPy hQy)
    simp only [Units.smul_def, smul_fin3, Units.val_mk0]
    ext i
    fin_cases i
    · simp [hPx, hQx]
    · simp [div_mul_cancel₀ _ hQy]
    · simp [hPz, hQz]
  · have hQz : Q z ≠ 0 := by
      intro h
      have hQx : Q x = 0 := X_eq_zero_of_Z_eq_zero hQ h
      have hQy : Q y ≠ 0 := by
        intro h'
        apply hQ_nz
        ext i; fin_cases i <;> assumption
      have h_mul : Q y * P z = 0 := by
        calc Q y * P z = P y * Q z := hy.symm
        _ = P y * 0 := by rw [h]
        _ = 0 := mul_zero _
      have hPz_zero := mul_eq_zero.mp h_mul |>.resolve_left hQy
      exact hPz hPz_zero
    exact equiv_of_X_eq_of_Y_eq hPz hQz hx hy

lemma addE_X_mul_addZ_eq_addX_mul_addE_Z (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    (h1 : p1.SatisfiesCurveEquation params)
    (h2 : p2.SatisfiesCurveEquation params) :
    (addE p1 p2 params).X * (params.toMathlib).toProjective.addZ p1.toMathlib p2.toMathlib =
      (params.toMathlib).toProjective.addX p1.toMathlib p2.toMathlib * (addE p1 p2 params).Z := by
  unfold ProjectivePoint.SatisfiesCurveEquation at h1 h2
  unfold ProjectivePoint.toMathlib addE WeierstrassCurve.Projective.addX WeierstrassCurve.Projective.addZ
  unfold CurveParameters.toMathlib
  dsimp
  linear_combination
    (- 3 * p2.X^2 * p1.Y * p2.Z^2 * params.a - 3 * p2.X^2 * p2.Y * p1.Z * p2.Z * params.a - 3 * p2.X * p1.Y * p2.Y^2 * p2.Z - 3 * p2.X * p2.Y^3 * p1.Z - 9 * p2.X * p1.Y * p2.Z^3 * params.b - 9 * p2.X * p2.Y * p1.Z * p2.Z^2 * params.b + p1.Y * p2.Z^4 * params.a^2 + p2.Y * p1.Z * p2.Z^3 * params.a^2) * h1
    + (3 * p1.X^2 * p1.Y * p1.Z * p2.Z * params.a + 3 * p1.X * p1.Y^3 * p2.Z + 3 * p1.X * p1.Y^2 * p2.Y * p1.Z + 3 * p1.X^2 * p2.Y * p1.Z^2 * params.a + 9 * p1.X * p1.Y * p1.Z^2 * p2.Z * params.b + 9 * p1.X * p2.Y * p1.Z^3 * params.b - p1.Y * p1.Z^3 * p2.Z * params.a^2 - p2.Y * p1.Z^4 * params.a^2) * h2

lemma addE_Y_mul_addZ_eq_addY_mul_addE_Z (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    (h1 : p1.SatisfiesCurveEquation params)
    (h2 : p2.SatisfiesCurveEquation params) :
    (addE p1 p2 params).Y * (params.toMathlib).toProjective.addZ p1.toMathlib p2.toMathlib =
      (params.toMathlib).toProjective.addY p1.toMathlib p2.toMathlib * (addE p1 p2 params).Z := by
  unfold ProjectivePoint.SatisfiesCurveEquation at h1 h2
  unfold ProjectivePoint.toMathlib addE WeierstrassCurve.Projective.addY WeierstrassCurve.Projective.addZ WeierstrassCurve.Projective.addX WeierstrassCurve.Projective.negAddY WeierstrassCurve.Projective.negY
  unfold CurveParameters.toMathlib
  dsimp
  linear_combination
    (9 * p1.X * p2.X^3 * p2.Z * params.a + 9 * p1.X * p2.X^2 * p2.Y^2 + 27 * p1.X * p2.X^2 * p2.Z^2 * params.b - 3 * p1.X * p2.X * p2.Z^3 * params.a^2 + 3 * p2.X^2 * p1.Z * p2.Z^2 * params.a^2 + 3 * p2.X * p2.Y^2 * p1.Z * p2.Z * params.a + 9 * p2.X * p1.Z * p2.Z^3 * params.a * params.b - p1.Z * p2.Z^4 * params.a^3) * h1
    + (- 9 * p1.X^3 * p2.X * p1.Z * params.a - 9 * p1.X^2 * p2.X * p1.Y^2 - 27 * p1.X^2 * p2.X * p1.Z^2 * params.b - 3 * p1.X^2 * p1.Z^2 * p2.Z * params.a^2 + 3 * p1.X * p2.X * p1.Z^3 * params.a^2 - 3 * p1.X * p1.Y^2 * p1.Z * p2.Z * params.a - 9 * p1.X * p1.Z^3 * p2.Z * params.a * params.b + p1.Z^4 * p2.Z * params.a^3) * h2

end CoordinateIdentities

section MathlibBridge

/-!
## Mathlib Bridge for Projective Elliptic Curves

This section establishes a formal bridge between our custom projective elliptic curve representation
(designed to match the ZK circuit constraints line-for-line) and Mathlib's robust elliptic curve
formalization (`Mathlib.AlgebraicGeometry.EllipticCurve.Projective`).

### Bridging Steps & Technical Difficulties

1.  Define mappings from our `ProjectivePoint` to Mathlib's projective representatives (`toMathlib`)
    and back (`fromMathlib`).
2.  Prove that our projective equivalence relation (`ProjectiveEquiv`) is equivalent to Mathlib's
    setoid equivalence (`≈`) on projective representatives.
3.  Prove that our completeness case-analyses and addition formulas are equivalent to Mathlib's.
    *Technical Difficulty*: Our `addE` uses the Renes-Costello-Batten (RCB) complete addition formula
    (division-free, branch-free), while Mathlib uses a different formulation that branches on equivalence.
    We prove they are equivalent modulo the curve equation using a "cross-multiplication" lemma
    (`equiv_of_cross_mul`) and Groebner-basis-style polynomial identity verification via `linear_combination`.

-/

open WeierstrassCurve WeierstrassCurve.Projective MvPolynomial

local notation3 "x" => (0 : Fin 3)
local notation3 "y" => (1 : Fin 3)
local notation3 "z" => (2 : Fin 3)

variable {F : Type} [Field F]

lemma satisfiesCurveEquation_iff (p : ProjectivePoint F) (params : CurveParameters F) :
    p.SatisfiesCurveEquation params ↔ (params.toMathlib).toProjective.Equation p.toMathlib := by
  unfold ProjectivePoint.SatisfiesCurveEquation ProjectivePoint.toMathlib CurveParameters.toMathlib
  rw [WeierstrassCurve.Projective.equation_iff]
  dsimp
  constructor
  · intro h
    linear_combination h
  · intro h
    linear_combination h

lemma isOnCurve_implies_nonsingular (p : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    (h_on : p.IsOnCurve params) :
    (params.toMathlib).toProjective.Nonsingular p.toMathlib := by
  have h_eq : (params.toMathlib).toProjective.Equation p.toMathlib := by
    rw [← satisfiesCurveEquation_iff]
    exact h_on.1
  have h_eq_unfolded : p.Y * p.Y * p.Z = p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := h_on.1
  by_cases hz : p.Z = 0
  · -- Case Z = 0
    have hx3 : p.X * p.X * p.X = 0 := by
      linear_combination -h_eq_unfolded + (p.Y * p.Y - params.a * p.X * p.Z - params.b * p.Z * p.Z) * hz
    have hx : p.X = 0 := by
      have h1 : p.X * p.X = 0 ∨ p.X = 0 := mul_eq_zero.mp hx3
      cases h1 with
      | inl h2 =>
        have h3 : p.X = 0 ∨ p.X = 0 := mul_eq_zero.mp h2
        cases h3 with
        | inl h4 => exact h4
        | inr h5 => exact h5
      | inr h6 => exact h6
    have hy_ne : p.Y ≠ 0 := by
      intro hy
      have hp_zero : p = 0 := by
        ext <;> assumption
      exact h_on.2 hp_zero
    have h_smul : p.toMathlib = p.Y • ![0, 1, 0] := by
      unfold ProjectivePoint.toMathlib
      ext i
      fin_cases i <;> simp [hx, hz]
    have h_equiv : p.toMathlib ≈ ![0, 1, 0] := by
      use (hy_ne.isUnit).unit
      simp [h_smul]
    rw [WeierstrassCurve.Projective.nonsingular_of_equiv h_equiv]
    exact WeierstrassCurve.Projective.nonsingular_zero
  · -- Case Z ≠ 0
    have hz_math : p.toMathlib z ≠ 0 := hz
    rw [nonsingular_of_Z_ne_zero hz_math]
    haveI : Nontrivial F := inferInstance
    rw [← WeierstrassCurve.Affine.equation_iff_nonsingular]
    have h_eval := @eval_polynomial_of_Z_ne_zero F _ (params.toMathlib) p.toMathlib hz_math
    have h_eval_zero : eval p.toMathlib (params.toMathlib).toProjective.polynomial = 0 := h_eq
    rw [h_eval_zero, zero_div] at h_eval
    exact h_eval.symm

noncomputable def Point.equivSubtype {R : Type*} [CommRing R] (W' : Projective R) :
    W'.Point ≃ { p : PointClass R // W'.NonsingularLift p } where
  toFun P := ⟨P.point, P.nonsingular⟩
  invFun p := ⟨p.property⟩
  left_inv P := by cases P; rfl
  right_inv p := by rcases p with ⟨p, h⟩; rfl

noncomputable instance instFintypePoint {R : Type*} [CommRing R] [Fintype (Fin 3 → R)]
    [DecidableRel (α := Fin 3 → R) (· ≈ ·)] (W' : Projective R) [DecidablePred W'.NonsingularLift] :
    Fintype W'.Point :=
  Fintype.ofEquiv _ (Point.equivSubtype W').symm

/-- Map our ProjectivePoint (with IsOnCurve proof) to Mathlib's Point -/
def ProjectivePoint.toMathlibPoint (p : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    (h_on : p.IsOnCurve params) :
    (params.toMathlib).toProjective.Point :=
  ⟨(nonsingularLift_iff p.toMathlib).mpr (isOnCurve_implies_nonsingular p params h_on)⟩

lemma toMathlib_eq_zero_iff (p : ProjectivePoint F) : p.toMathlib = 0 ↔ p = 0 := by
  constructor
  · intro h
    ext
    · exact congr_fun h 0
    · exact congr_fun h 1
    · exact congr_fun h 2
  · rintro rfl
    ext i
    fin_cases i <;> rfl

lemma add_nonsingular (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params) :
    (params.toMathlib).toProjective.Nonsingular ((params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib) := by
  have h_sum := (p1.toMathlibPoint params h_on1 + p2.toMathlibPoint params h_on2).nonsingular
  change (params.toMathlib).toProjective.NonsingularLift ⟦(params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib⟧ at h_sum
  rwa [nonsingularLift_iff] at h_sum

lemma nonsingular_ne_zero (params : CurveParameters F) {P : Fin 3 → F}
    (h : (params.toMathlib).toProjective.Nonsingular P) : P ≠ 0 := by
  intro h_zero
  rcases h with ⟨_, h_deriv⟩
  have hX : eval P (params.toMathlib).toProjective.polynomialX = 0 := by
    rw [eval_polynomialX, h_zero]
    simp
  have hY : eval P (params.toMathlib).toProjective.polynomialY = 0 := by
    rw [eval_polynomialY, h_zero]
    simp
  have hZ : eval P (params.toMathlib).toProjective.polynomialZ = 0 := by
    rw [eval_polynomialZ, h_zero]
    simp
  rcases h_deriv with hX' | hY' | hZ'
  · contradiction
  · contradiction
  · contradiction

lemma addE_eq_addXYZ (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params)
    (h_not_equiv : ¬ p1.toMathlib ≈ p2.toMathlib) :
    (addE p1 p2 params).toMathlib ≈ (params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib := by
  have h_on3 := addE_nonzero_of_not_equiv p1 p2 params h_on1 h_on2 h_not_equiv
  have h_eq_x := addE_X_mul_addZ_eq_addX_mul_addE_Z p1 p2 params h_on1.left h_on2.left
  have h_eq_y := addE_Y_mul_addZ_eq_addY_mul_addE_Z p1 p2 params h_on1.left h_on2.left

  have h_eq_P : (params.toMathlib).toProjective.Equation (addE p1 p2 params).toMathlib := by
    have h_sat := SatisfiesCurveEquation.addE h_on1.left h_on2.left
    rwa [satisfiesCurveEquation_iff] at h_sat

  have h_eq_Q : (params.toMathlib).toProjective.Equation ((params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib) := by
    have h_ns_add := add_nonsingular p1 p2 params h_on1 h_on2
    have h_eq_add := h_ns_add.left
    have h_add_eq : (params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib = (params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib := by
      unfold WeierstrassCurve.Projective.add
      rw [if_neg h_not_equiv]
    rwa [h_add_eq] at h_eq_add

  have h_P_nz : (addE p1 p2 params).toMathlib ≠ 0 := by
    intro h
    have h_zero := (toMathlib_eq_zero_iff (addE p1 p2 params)).mp h
    exact h_on3 h_zero

  have h_Q_nz : (params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib ≠ 0 := by
    have h_ns_add := add_nonsingular p1 p2 params h_on1 h_on2
    have h_add_eq : (params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib = (params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib := by
      unfold WeierstrassCurve.Projective.add
      rw [if_neg h_not_equiv]
    have h_ns_addXYZ : (params.toMathlib).toProjective.Nonsingular ((params.toMathlib).toProjective.addXYZ p1.toMathlib p2.toMathlib) := by
      rwa [← h_add_eq]
    exact nonsingular_ne_zero params h_ns_addXYZ

  exact equiv_of_cross_mul params h_eq_P h_eq_Q h_P_nz h_Q_nz h_eq_x h_eq_y


lemma toMathlib_smul (p : ProjectivePoint F) (v : F) : (v • p).toMathlib = v • p.toMathlib := by
  ext i
  fin_cases i <;> rfl

/--
  Bridges our custom projective addition formula (`addE`) to Mathlib's
  projective elliptic curve addition (`WeierstrassCurve.Projective.add`).
-/
theorem addE_eq_add (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params) :
    (addE p1 p2 params).toMathlib ≈ (params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib := by
  unfold WeierstrassCurve.Projective.add
  split_ifs with h
  · rcases h with ⟨u, hu_eq⟩
    have h_p2_eq : p2 = (u⁻¹ : F) • p1 := by
      ext
      · have h0 := congr_fun hu_eq (0 : Fin 3)
        simp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h0
        simp [HSMul.hSMul, SMul.smul]
        have h_inv : (u⁻¹ : F) * (u : F) = 1 := by simp
        calc p2.X = 1 * p2.X := by ring
        _ = ((u⁻¹ : F) * (u : F)) * p2.X := by rw [h_inv]
        _ = (u⁻¹ : F) * ((u : F) * p2.X) := by ring
        _ = (u⁻¹ : F) * p1.X := by rw [h0]
      · have h1 := congr_fun hu_eq (1 : Fin 3)
        simp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h1
        simp [HSMul.hSMul, SMul.smul]
        have h_inv : (u⁻¹ : F) * (u : F) = 1 := by simp
        calc p2.Y = 1 * p2.Y := by ring
        _ = ((u⁻¹ : F) * (u : F)) * p2.Y := by rw [h_inv]
        _ = (u⁻¹ : F) * ((u : F) * p2.Y) := by ring
        _ = (u⁻¹ : F) * p1.Y := by rw [h1]
      · have h2 := congr_fun hu_eq (2 : Fin 3)
        simp [ProjectivePoint.toMathlib, HSMul.hSMul, SMul.smul] at h2
        simp [HSMul.hSMul, SMul.smul]
        have h_inv : (u⁻¹ : F) * (u : F) = 1 := by simp
        calc p2.Z = 1 * p2.Z := by ring
        _ = ((u⁻¹ : F) * (u : F)) * p2.Z := by rw [h_inv]
        _ = (u⁻¹ : F) * ((u : F) * p2.Z) := by ring
        _ = (u⁻¹ : F) * p1.Z := by rw [h2]
    rw [h_p2_eq]
    rw [addE_smul_right]
    rw [toMathlib_smul]
    have h_dbl_add := doubleE_eq_addE p1 params h_on1.left
    rw [← h_dbl_add]
    have h_dbl_eq := doubleE_eq_dblXYZ p1 params h_on1.left
    rw [h_dbl_eq]
    have hu2 : IsUnit ((u⁻¹ : F)^2) := by
      use u⁻¹ * u⁻¹
      simp [sq]
    exact smul_equiv (WeierstrassCurve.Projective.dblXYZ (params.toMathlib).toProjective p1.toMathlib) hu2
  · exact addE_eq_addXYZ p1 p2 params h_on1 h_on2 h

/--
  Proves that the projective addition of two valid points on the curve
  never results in the invalid projective point `(0, 0, 0)` (represented as `0`).
  This is a critical helper for proving the algebraic closure of addition (`addE_on_curve`).
-/
theorem addE_nonzero (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params) :
    addE p1 p2 params ≠ 0 := by
  intro h_add_zero
  have h_add_zero_math : (addE p1 p2 params).toMathlib = 0 := by
    rw [toMathlib_eq_zero_iff]
    exact h_add_zero
  have h_equiv := addE_eq_add p1 p2 params h_on1 h_on2
  rcases h_equiv with ⟨c, h_eq⟩
  rw [h_add_zero_math] at h_eq
  have h_add_zero_of_smul : (params.toMathlib).toProjective.add p1.toMathlib p2.toMathlib = 0 := by
    ext i
    fin_cases i
    · have h0 := congr_fun h_eq (0 : Fin 3)
      simp [HSMul.hSMul, SMul.smul] at h0
      exact h0
    · have h1 := congr_fun h_eq (1 : Fin 3)
      simp [HSMul.hSMul, SMul.smul] at h1
      exact h1
    · have h2 := congr_fun h_eq (2 : Fin 3)
      simp [HSMul.hSMul, SMul.smul] at h2
      exact h2
  have h_ns_add := add_nonsingular p1 p2 params h_on1 h_on2
  have h_ne_zero := nonsingular_ne_zero params h_ns_add
  exact h_ne_zero h_add_zero_of_smul

/--
  Proves that adding two points on the curve yields another point on the curve.
  This establishes the algebraic closure of the complete addition operation.
-/
lemma addE_on_curve (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h1 : p1.IsOnCurve params) (h2 : p2.IsOnCurve params) :
    (addE p1 p2 params).IsOnCurve params := by
  constructor
  · exact SatisfiesCurveEquation.addE h1.1 h2.1
  · exact addE_nonzero p1 p2 params h1 h2

lemma nsmulFastE_on_curve (n : Nat) (p : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : p.IsOnCurve params) :
    (nsmulFastE n p params).IsOnCurve params := by
  induction n using Nat.binaryRec with
  | zero =>
    unfold nsmulFastE
    rw [Nat.binaryRec_zero]
    exact infinity_on_curve params
  | bit b n' ih =>
    rw [nsmulFastE_bit]
    dsimp
    have h_doubled : (doubleE (nsmulFastE n' p params) params).IsOnCurve params := by
      exact doubleE_on_curve (nsmulFastE n' p params) params ih
    split
    · exact addE_on_curve (doubleE (nsmulFastE n' p params) params) p params h_doubled hp
    · exact h_doubled

lemma bsmul_on_curve (s : List Bool) (p : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : p.IsOnCurve params) :
    (bsmul s p params).IsOnCurve params := by
  unfold bsmul
  exact nsmulFastE_on_curve (bitsToNat s) p params hp

lemma toMathlibPoint_add (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params) :
    (addE p1 p2 params).toMathlibPoint params (addE_on_curve p1 p2 params h_on1 h_on2) =
      p1.toMathlibPoint params h_on1 + p2.toMathlibPoint params h_on2 := by
  ext
  rw [Point.add_point]
  dsimp [ProjectivePoint.toMathlibPoint]
  rw [addMap_eq]
  rw [Quotient.eq]
  exact addE_eq_add p1 p2 params h_on1 h_on2

lemma toMathlibPoint_infinity (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    (h : infinityPoint.IsOnCurve params) :
    infinityPoint.toMathlibPoint params h = 0 := by
  ext
  dsimp [ProjectivePoint.toMathlibPoint, infinityPoint]
  rw [WeierstrassCurve.Projective.Point.zero_point]
  rfl

lemma toMathlibPoint_eq_iff_ProjectiveEquiv (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    (h1 : p1.IsOnCurve params) (h2 : p2.IsOnCurve params) :
    p1.toMathlibPoint params h1 = p2.toMathlibPoint params h2 ↔ ProjectiveEquiv p1 p2 := by
  constructor
  · intro h
    have h_point : (p1.toMathlibPoint params h1).point = (p2.toMathlibPoint params h2).point := by
      rw [h]
    dsimp [ProjectivePoint.toMathlibPoint] at h_point
    rw [Quotient.eq] at h_point
    rw [ProjectiveEquiv_iff_equiv]
    exact h_point
  · intro h
    rw [ProjectiveEquiv_iff_equiv] at h
    ext
    dsimp [ProjectivePoint.toMathlibPoint]
    rw [Quotient.eq]
    exact h

lemma toMathlibPoint_double (p : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h : p.IsOnCurve params) :
    (doubleE p params).toMathlibPoint params (doubleE_on_curve p params h) =
      2 • (p.toMathlibPoint params h) := by
  have h_double_on := doubleE_on_curve p params h
  have h_add_on := addE_on_curve p p params h h
  have h_equiv_iff :=
    toMathlibPoint_eq_iff_ProjectiveEquiv (doubleE p params) (addE p p params) params h_double_on h_add_on
  rw [two_nsmul]
  rw [← toMathlibPoint_add p p params h h]
  change (doubleE p params).toMathlibPoint params h_double_on = (addE p p params).toMathlibPoint params h_add_on
  rw [h_equiv_iff]
  rw [doubleE_eq_addE p params h.1]
  exact ProjectiveEquiv.refl _

/--
  Bridges our custom double-and-add scalar multiplication (`nsmulFastE`)
  to Mathlib's group action (`•`). This shows that our loop-based implementation
  is equivalent to the mathematical scalar multiplication.
-/
lemma toMathlibPoint_nsmulFastE (n : Nat) (P : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic] [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h : P.IsOnCurve params) :
    (nsmulFastE n P params).toMathlibPoint params (nsmulFastE_on_curve n P params h) =
    n • (P.toMathlibPoint params h) := by
  induction n using Nat.binaryRec with
  | zero =>
    simp only [nsmulFastE, Nat.binaryRec_zero]
    rw [toMathlibPoint_infinity params]
    rw [zero_smul]
  | bit b n ih =>
    have h_n := nsmulFastE_on_curve n P params h
    have h_double := doubleE_on_curve (nsmulFastE n P params) params h_n
    have h_add := addE_on_curve (doubleE (nsmulFastE n P params) params) P params h_double h
    cases b with
    | false =>
      have h_eq : nsmulFastE (Nat.bit false n) P params = doubleE (nsmulFastE n P params) params := by
        rw [nsmulFastE_bit false n P params]
        rfl
      have h_equiv : ProjectiveEquiv (nsmulFastE (Nat.bit false n) P params) (doubleE (nsmulFastE n P params) params) := by
        rw [h_eq]
        exact ProjectiveEquiv.refl _
      have h_2n_on := nsmulFastE_on_curve (Nat.bit false n) P params h
      have h_point_eq :=
        (toMathlibPoint_eq_iff_ProjectiveEquiv (nsmulFastE (Nat.bit false n) P params) (doubleE (nsmulFastE n P params) params) params h_2n_on h_double).mpr h_equiv
      rw [h_point_eq]
      rw [Nat.bit_false_apply]
      rw [mul_comm]
      rw [mul_nsmul]
      rw [← ih]
      rw [← toMathlibPoint_double (nsmulFastE n P params) params h_n]
    | true =>
      have h_eq : nsmulFastE (Nat.bit true n) P params = addE (doubleE (nsmulFastE n P params) params) P params := by
        rw [nsmulFastE_bit true n P params]
        rfl
      have h_equiv : ProjectiveEquiv (nsmulFastE (Nat.bit true n) P params) (addE (doubleE (nsmulFastE n P params) params) P params) := by
        rw [h_eq]
        exact ProjectiveEquiv.refl _
      have h_2n1_on := nsmulFastE_on_curve (Nat.bit true n) P params h
      have h_point_eq :=
        (toMathlibPoint_eq_iff_ProjectiveEquiv (nsmulFastE (Nat.bit true n) P params) (addE (doubleE (nsmulFastE n P params) params) P params) params h_2n1_on h_add).mpr h_equiv
      rw [h_point_eq]
      rw [Nat.bit_true_apply]
      rw [add_nsmul]
      rw [one_nsmul]
      rw [mul_comm]
      rw [mul_nsmul]
      rw [← ih]
      rw [← toMathlibPoint_double (nsmulFastE n P params) params h_n]
      rw [← toMathlibPoint_add (doubleE (nsmulFastE n P params) params) P params h_double h]

end MathlibBridge

/-!
## Proven Algebraic Properties of Elliptic Curve Operations

This section establishes basic algebraic properties of the complete addition (`addE`)
and doubling (`doubleE`) operations under projective coordinates. Specifically, it proves:
1. Commutativity of addition (`addE_comm`).
2. Left identity behavior of the point at infinity (`addE_infinity_left`).
3. Double and addition properties of the point at infinity.
-/
section ProvenProperties

variable {F : Type} [Field F]

lemma addE_comm (p1 p2 : ProjectivePoint F) (params : CurveParameters F) :
    addE p1 p2 params = addE p2 p1 params := by
  unfold addE
  dsimp
  ext <;> ring

/-- Point at infinity acts as left identity -/
lemma addE_infinity_left (p : ProjectivePoint F) (params : CurveParameters F) (h_py : p.Y ≠ 0) :
    ProjectiveEquiv (addE infinityPoint p params) p := by
  use p.Y
  refine ⟨h_py, ?_⟩
  unfold addE
  dsimp only
  rw [smul_projective]
  ext <;> dsimp [infinityPoint] <;> ring

lemma addE_infinity_infinity (params : CurveParameters F) :
    addE infinityPoint infinityPoint params = infinityPoint := by
  unfold addE infinityPoint
  dsimp
  ext <;> ring

/--
  Proves associativity of our complete addition formula (`addE`) up to projective equivalence.
  This is proven by lifting the points to Mathlib, applying Mathlib's associativity theorem,
  and lowering the result back.
-/
theorem ProjectiveEquiv.addE_assoc {F : Type} [Field F] (p1 p2 p3 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params] [NeZero (2 : F)] [NeZero (3 : F)]
    (h_on1 : p1.IsOnCurve params) (h_on2 : p2.IsOnCurve params) (h_on3 : p3.IsOnCurve params) :
    ProjectiveEquiv (_root_.addE (_root_.addE p1 p2 params) p3 params) (_root_.addE p1 (_root_.addE p2 p3 params) params) := by
  have h_on12 := addE_on_curve p1 p2 params h_on1 h_on2
  have h_on23 := addE_on_curve p2 p3 params h_on2 h_on3
  have h_on123_l := addE_on_curve (_root_.addE p1 p2 params) p3 params h_on12 h_on3
  have h_on123_r := addE_on_curve p1 (_root_.addE p2 p3 params) params h_on1 h_on23

  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_on123_l h_on123_r]
  rw [toMathlibPoint_add (_root_.addE p1 p2 params) p3 params h_on12 h_on3]
  rw [toMathlibPoint_add p1 (_root_.addE p2 p3 params) params h_on1 h_on23]
  rw [toMathlibPoint_add p1 p2 params h_on1 h_on2]
  rw [toMathlibPoint_add p2 p3 params h_on2 h_on3]
  rw [add_assoc]

/--
  Rearranges a sum of four points: `(A + B) + (C + D) ≈ (A + C) + (B + D)` up to projective equivalence.

  This lemma is needed for ECDSA verification proofs:
  1. In loop verification: To combine generator (`G`), public key (`PK`), and randomizer (`R`)
     contributions from different steps of the scalar multiplication loop.
  2. In soundness/cancellation proofs: To group a point with its inverse to show they cancel out,
     e.g., `(e_G + r_PK) + (e_G_neg + r_PK_neg)` to `(e_G + e_G_neg) + (r_PK + r_PK_neg)`.
-/
lemma addE_rearrange (A B C D : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic] [CurveHasNoPointsOfOrder2 params]
    [NeZero (2 : F)] [NeZero (3 : F)]
    (hA : A.IsOnCurve params) (hB : B.IsOnCurve params) (hC : C.IsOnCurve params) (hD : D.IsOnCurve params) :
    ProjectiveEquiv (addE (addE A B params) (addE C D params) params)
    (addE (addE A C params) (addE B D params) params) := by
  have h_AB := addE_on_curve A B params hA hB
  have h_CD := addE_on_curve C D params hC hD
  have h_AC := addE_on_curve A C params hA hC
  have h_BD := addE_on_curve B D params hB hD
  have h_lhs := addE_on_curve (addE A B params) (addE C D params) params h_AB h_CD
  have h_rhs := addE_on_curve (addE A C params) (addE B D params) params h_AC h_BD

  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_lhs h_rhs]
  rw [toMathlibPoint_add (addE A B params) (addE C D params) params h_AB h_CD]
  rw [toMathlibPoint_add (addE A C params) (addE B D params) params h_AC h_BD]
  rw [toMathlibPoint_add A B params hA hB]
  rw [toMathlibPoint_add C D params hC hD]
  rw [toMathlibPoint_add A C params hA hC]
  rw [toMathlibPoint_add B D params hB hD]
  abel

lemma addE_rearrange_triple (A B C D E P6 : ProjectivePoint F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic] [CurveHasNoPointsOfOrder2 params]
    [NeZero (2 : F)] [NeZero (3 : F)]
    (hA : A.IsOnCurve params) (hB : B.IsOnCurve params) (hC : C.IsOnCurve params)
    (hD : D.IsOnCurve params) (hE : E.IsOnCurve params) (hP6 : P6.IsOnCurve params) :
    ProjectiveEquiv (addE (addE (addE A B params) C params) (addE (addE D E params) P6 params) params)
    (addE (addE (addE A D params) (addE B E params) params) (addE C P6 params) params) := by
  have h_AB := addE_on_curve A B params hA hB
  have h_DE := addE_on_curve D E params hD hE
  have h_step1 := addE_rearrange (addE A B params) C (addE D E params) P6 params h_AB hC h_DE hP6
  have h_rearrange_inner := addE_rearrange A B D E params hA hB hD hE
  have h_step2 := h_rearrange_inner.addE params (ProjectiveEquiv.refl (addE C P6 params))
  exact ProjectiveEquiv.trans h_step1 h_step2

end ProvenProperties

/-!
## Projective to Affine Boundary Bridge

This section provides helper lemmas to bridge the gap between the circuit's internal
projective representation and its external affine representation (used for public keys
and signatures at the circuit boundary).
-/
section AffineProjectiveBridge

variable {F : Type} [Field F]

/--
  Proves that if a projective point `p` is scale-equivalent to an affine point `q`
  that lies on the curve, then `p` satisfies the projective curve equation.
-/
theorem IsOnCurve_implies_projective (p : ProjectivePoint F) (q : AffinePoint F) (params : CurveParameters F) :
    ProjectiveEquiv p q.toProjective → q.IsOnCurve params →
    p.SatisfiesCurveEquation params := by
    intro h1 h2
    unfold ProjectivePoint.SatisfiesCurveEquation
    rw [projectiveEquiv_toProjective_iff] at h1
    rcases h1 with ⟨hx, hy, hz⟩
    have hC : q.Y * q.Y = q.X * q.X * q.X + params.a * q.X + params.b := h2
    calc p.Y * p.Y * p.Z = (q.Y * p.Z) * (q.Y * p.Z) * p.Z := by rw [hy]
  _ = (q.Y * q.Y) * (p.Z * p.Z * p.Z) := by ring
  _ = (q.X * q.X * q.X + params.a * q.X + params.b) * (p.Z * p.Z * p.Z) := by rw [hC]
  _ = (q.X * p.Z) * (q.X * p.Z) * (q.X * p.Z) + params.a * (q.X * p.Z) * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by ring
  _ = p.X * p.X * p.X + params.a * p.X * p.Z * p.Z + params.b * p.Z * p.Z * p.Z := by rw [hx]

/--
  Proves that if an affine point is on the curve, its direct projective representation
  (with Z=1) is on the projective curve.
-/
theorem affine_to_projective_on_curve (q : AffinePoint F) (params : CurveParameters F)
    (hq : q.IsOnCurve params) :
    ProjectivePoint.IsOnCurve q.toProjective params := by
  have h_sat := IsOnCurve_implies_projective q.toProjective q params (ProjectiveEquiv.refl _) hq
  refine ⟨h_sat, ?_⟩
  intro h_zero
  change ({ X := q.X, Y := q.Y, Z := 1 : ProjectivePoint F }) = ({ X := 0, Y := 0, Z := 0 : ProjectivePoint F }) at h_zero
  injection h_zero with _ _ hz
  exact one_ne_zero hz

/--
  Proves that projecting a projective point on the curve to affine coordinates
  yields a point that satisfies the affine curve equation, provided the Z coordinate
  is invertible.
-/
theorem projective_to_affine_on_curve (p : ProjectivePoint F) (params : CurveParameters F)
    (h_proj : p.SatisfiesCurveEquation params)
    (hz : p.Z ≠ 0) :
    AffinePoint.IsOnCurve { X := p.X * p.Z⁻¹, Y := p.Y * p.Z⁻¹ } params := by
  unfold AffinePoint.IsOnCurve
  dsimp
  unfold ProjectivePoint.SatisfiesCurveEquation at h_proj
  have h_proj_sub : p.Y ^ 2 * p.Z - p.X ^ 3 - params.a * p.X * p.Z ^ 2 - params.b * p.Z ^ 3 = 0 := by
    linear_combination h_proj
  have h_inv : p.Z * p.Z⁻¹ = 1 := mul_inv_cancel₀ hz
  have h_inv_sub : p.Z * p.Z⁻¹ - 1 = 0 := by
    linear_combination h_inv
  linear_combination
    h_proj_sub * (p.Z⁻¹) ^ 3 +
    h_inv_sub * (- p.Y ^ 2 * (p.Z⁻¹) ^ 2 + params.a * p.X * p.Z⁻¹ * (p.Z * p.Z⁻¹ + 1) + params.b * ((p.Z * p.Z⁻¹) ^ 2 + p.Z * p.Z⁻¹ + 1))

end AffineProjectiveBridge

/-!
### Bit-list Scalar Multiplication (bsmul)

This section contains lemmas and bridging proofs for `bsmul`, which models
the step-by-step bitwise scalar multiplication loop used in the ZK circuit.
We establish its relation to Mathlib's group action (`•`) and prove its
algebraic properties (distributivity, associativity, etc.) by lifting them to Mathlib.
-/
section Bsmul

variable {F : Type} [Field F]

lemma bsmul.singleton (b : Bool) (P : ProjectivePoint F) (params : CurveParameters F) :
    bsmul [b] P params = if b then addE (doubleE infinityPoint params) P params else infinityPoint := by
  unfold bsmul bitsToNat
  dsimp [List.foldl]
  cases b
  · exact nsmulFastE_zero P params
  · change nsmulFastE (Nat.bit true 0) P params = _
    rw [nsmulFastE_bit true 0, nsmulFastE_zero]
    simp

/--
  Bridges our bit-list scalar multiplication (`bsmul`) to Mathlib's group action (`•`).
  This is the key theorem used to lift circuit-level scalar multiplication to Mathlib
  for high-level proofs.
-/
lemma toMathlibPoint_bsmul (s : List Bool) (P : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (h : P.IsOnCurve params) :
    (bsmul s P params).toMathlibPoint params (bsmul_on_curve s P params h) =
    (bitsToNat s) • (P.toMathlibPoint params h) := by
  unfold bsmul
  exact toMathlibPoint_nsmulFastE (bitsToNat s) P params h


/-! ## Projective Scalar Multiplication Algebraic Properties -/

/--
  Shows that projective scalar multiplication distributes over elliptic curve addition
  up to projective equivalence.
-/
lemma bsmul_addE (s : List Bool) (p1 p2 : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp1 : p1.IsOnCurve params) (hp2 : p2.IsOnCurve params) :
    ProjectiveEquiv (bsmul s (addE p1 p2 params) params)
    (addE (bsmul s p1 params) (bsmul s p2 params) params) := by
  have h_on_add := addE_on_curve p1 p2 params hp1 hp2
  have h_on_s1 := bsmul_on_curve s p1 params hp1
  have h_on_s2 := bsmul_on_curve s p2 params hp2
  have h_on_s_add := bsmul_on_curve s (addE p1 p2 params) params h_on_add
  have h_on_add_s := addE_on_curve (bsmul s p1 params) (bsmul s p2 params) params h_on_s1 h_on_s2
  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_on_s_add h_on_add_s]
  rw [toMathlibPoint_bsmul s (addE p1 p2 params) params h_on_add]
  rw [toMathlibPoint_add p1 p2 params hp1 hp2]
  rw [toMathlibPoint_add (bsmul s p1 params) (bsmul s p2 params) params h_on_s1 h_on_s2]
  rw [toMathlibPoint_bsmul s p1 params hp1]
  rw [toMathlibPoint_bsmul s p2 params hp2]
  rw [nsmul_add]

lemma bsmul_addE_triple (s : List Bool) (p1 p2 p3 : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp1 : p1.IsOnCurve params) (hp2 : p2.IsOnCurve params) (hp3 : p3.IsOnCurve params) :
    ProjectiveEquiv (bsmul s (addE (addE p1 p2 params) p3 params) params)
    (addE (addE (bsmul s p1 params) (bsmul s p2 params) params) (bsmul s p3 params) params) := by
  have hp12 := addE_on_curve p1 p2 params hp1 hp2
  have h_outer := bsmul_addE s (addE p1 p2 params) p3 params hp12 hp3
  have h_inner := bsmul_addE s p1 p2 params hp1 hp2
  have h_congr := h_inner.addE params (ProjectiveEquiv.refl (bsmul s p3 params))
  exact ProjectiveEquiv.trans h_outer h_congr

/--
  Shows that projective scalar multiplication commutes with elliptic curve doubling
  up to projective equivalence.
-/
lemma bsmul_doubleE (s : List Bool) (p : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : p.IsOnCurve params) :
    ProjectiveEquiv (bsmul s (doubleE p params) params)
    (doubleE (bsmul s p params) params) := by
  have h_on_double := doubleE_on_curve p params hp
  have h_on_s := bsmul_on_curve s p params hp
  have h_on_s_double := bsmul_on_curve s (doubleE p params) params h_on_double
  have h_on_double_s := doubleE_on_curve (bsmul s p params) params h_on_s
  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_on_s_double h_on_double_s]
  rw [toMathlibPoint_bsmul s (doubleE p params) params h_on_double]
  rw [toMathlibPoint_double p params hp]
  rw [toMathlibPoint_double (bsmul s p params) params h_on_s]
  rw [toMathlibPoint_bsmul s p params hp]
  rw [smul_comm]

/--
  General distributivity lemma showing that projective scalar multiplication
  with generic padded bit-lengths distributes over scalar addition up to projective equivalence.
-/
lemma bsmul_distrib_nat_gen (k : Nat) (val1 val2 : Nat) (P : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params) :
    ProjectiveEquiv (bsmul (padBits (natToBits (val1 + val2)) k) P params)
    (addE (bsmul (padBits (natToBits val1) k) P params) (bsmul (padBits (natToBits val2) k) P params) params) := by
  have h_val1_on := bsmul_on_curve (padBits (natToBits val1) k) P params hp
  have h_val2_on := bsmul_on_curve (padBits (natToBits val2) k) P params hp
  have h_sum_on := bsmul_on_curve (padBits (natToBits (val1 + val2)) k) P params hp
  have h_add_on := addE_on_curve (bsmul (padBits (natToBits val1) k) P params) (bsmul (padBits (natToBits val2) k) P params) params h_val1_on h_val2_on

  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_sum_on h_add_on]
  rw [toMathlibPoint_bsmul (h := hp)]
  rw [toMathlibPoint_add (bsmul (padBits (natToBits val1) k) P params) (bsmul (padBits (natToBits val2) k) P params) params h_val1_on h_val2_on]
  rw [toMathlibPoint_bsmul (h := hp)]
  rw [toMathlibPoint_bsmul (h := hp)]
  rw [bitsToNat_padBits]
  rw [bitsToNat_padBits]
  rw [bitsToNat_padBits]
  rw [add_nsmul]

/--
  Shows associativity between projective scalar multiplication and scalar multiplication
  under padded bit lists.
-/
lemma bsmul_assoc_nat (k : Nat) (val1 val2 : Nat) (P : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params) :
    ProjectiveEquiv (bsmul (padBits (natToBits val1) k) (bsmul (padBits (natToBits val2) k) P params) params)
    (bsmul (padBits (natToBits (val1 * val2)) k) P params) := by
  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params
    (bsmul_on_curve (padBits (natToBits val1) k) (bsmul (padBits (natToBits val2) k) P params) params
      (bsmul_on_curve (padBits (natToBits val2) k) P params hp))
    (bsmul_on_curve (padBits (natToBits (val1 * val2)) k) P params hp)]
  rw [toMathlibPoint_bsmul (h := bsmul_on_curve (padBits (natToBits val2) k) P params hp)]
  rw [toMathlibPoint_bsmul (h := hp)]
  rw [toMathlibPoint_bsmul (h := hp)]
  rw [bitsToNat_padBits]
  rw [bitsToNat_padBits]
  rw [bitsToNat_padBits]
  rw [mul_comm val1 val2]
  rw [mul_nsmul]

/--
  Allows taking the scalar value modulo the curve group order for projective scalar multiplication
  if the scalar order annihilates the base point to the point at infinity.
-/
lemma bsmul_mod_nat (k : Nat) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F) (order : Nat)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params)
    (h_annihilate : ProjectiveEquiv (bsmul (padBits (natToBits order) k) P params) infinityPoint) :
    ProjectiveEquiv (bsmul (padBits (natToBits (val % order)) k) P params) (bsmul (padBits (natToBits val) k) P params) := by
  have h_on_mod := bsmul_on_curve (padBits (natToBits (val % order)) k) P params hp
  have h_on_val := bsmul_on_curve (padBits (natToBits val) k) P params hp
  rw [← toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_on_mod h_on_val]
  rw [toMathlibPoint_bsmul (P := P) (h := hp)]
  rw [toMathlibPoint_bsmul (P := P) (h := hp)]
  rw [bitsToNat_padBits]
  rw [bitsToNat_padBits]
  have h_ann_on := bsmul_on_curve (padBits (natToBits order) k) P params hp
  have h_inf_on := infinity_on_curve params
  have h_ann_eq := (toMathlibPoint_eq_iff_ProjectiveEquiv _ _ params h_ann_on h_inf_on).mpr h_annihilate
  rw [toMathlibPoint_bsmul (P := P) (h := hp)] at h_ann_eq
  rw [bitsToNat_padBits] at h_ann_eq
  rw [toMathlibPoint_infinity] at h_ann_eq
  rw [← Nat.div_add_mod val order]
  rw [add_nsmul]
  rw [mul_nsmul]
  rw [h_ann_eq]
  rw [smul_zero]
  rw [zero_add]
  rw [Nat.add_comm (order * (val / order)) (val % order)]
  rw [Nat.add_mul_mod_self_left (val % order) order (val / order)]
  rw [Nat.mod_mod]

lemma bsmul_equiv_of_mod_eq (k : Nat) (A B : Nat) (P : ProjectivePoint F) (params : CurveParameters F) (order : Nat)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params) (h_order : ProjectiveEquiv (bsmul (padBits (natToBits order) k) P params) infinityPoint)
    (h_eq : A % order = B % order) :
    ProjectiveEquiv (bsmul (padBits (natToBits A) k) P params) (bsmul (padBits (natToBits B) k) P params) := by
  have h_mod_A := ProjectiveEquiv.symm (bsmul_mod_nat k A P params order hp h_order)
  have h_subst : ProjectiveEquiv (bsmul (padBits (natToBits (A % order)) k) P params) (bsmul (padBits (natToBits (B % order)) k) P params) := by
    rw [h_eq]
    exact ProjectiveEquiv.refl _
  have h_mod_B := bsmul_mod_nat k B P params order hp h_order
  exact ProjectiveEquiv.trans h_mod_A (ProjectiveEquiv.trans h_subst h_mod_B)

/--
  Shows that doubling a projectively scalar multiplied point is equivalent to
  appending a `false` bit (shifting by 2) to the bit list representation.
-/
lemma bsmul_scale_double (s : List Bool) (p : ProjectivePoint F) (params : CurveParameters F) :
    doubleE (bsmul s p params) params =
    bsmul (s ++ [false]) p params := by
  unfold bsmul
  rw [bitsToNat_append]
  rw [nsmulFastE_bit]
  dsimp

/--
  Bit-list scalar multiplication (bsmul) of the point at infinity always results in the point at infinity.
-/
lemma bsmul_infinity (s : List Bool) (params : CurveParameters F) :
    bsmul s infinityPoint params = infinityPoint := by
  unfold bsmul
  generalize bitsToNat s = n
  induction n using Nat.binaryRec with
  | zero =>
    unfold nsmulFastE
    rw [Nat.binaryRec_zero]
  | bit b n' ih =>
    rw [nsmulFastE_bit]
    dsimp
    rw [ih, doubleE_infinity]
    cases b with
    | false => rfl
    | true => exact addE_infinity_infinity params


/--
  Shows that prepending any number of `false` bits (padding zeros) to the bit list
  does not alter the value of the projective scalar multiplication.
-/
lemma bsmul_prepend_false_list (n : Nat) (s : List Bool) (P : ProjectivePoint F) (params : CurveParameters F) :
    bsmul (List.replicate n false ++ s) P params = bsmul s P params := by
  induction n with
  | zero => simp
  | succ n ih =>
    dsimp [List.replicate]
    exact ih

/--
  Shows that a padded bit list version of a natural number produces the exact same
  projective scalar multiplication result as the unpadded bit list version.
-/
lemma bsmul_pad_nat_eq (k : Nat) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F) :
    bsmul (padBits (natToBits val) k) P params = bsmul (natToBits val) P params := by
  unfold padBits List.leftpad
  exact bsmul_prepend_false_list (k - (natToBits val).length) (natToBits val) P params

/--
  Shows that padding a natural number to two different lengths produces projectively equivalent results.
-/
lemma bsmul_pad_nat_equiv (k1 k2 : Nat) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F) :
    ProjectiveEquiv (bsmul (padBits (natToBits val) k1) P params)
    (bsmul (padBits (natToBits val) k2) P params) := by
  rw [bsmul_pad_nat_eq k1 val P params]
  rw [bsmul_pad_nat_eq k2 val P params]
  exact ProjectiveEquiv.refl _

/--
  General inverse lemma showing that a point multiplied by `val` added to the same point
  multiplied by `order - val` yields the point at infinity.
-/
lemma bsmul_inverse_gen {P : ProjectivePoint F} {params : CurveParameters F} {order : Nat} {k : Nat}
    (val : Nat) (h_val : val < order)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params)
    (h_annihilate : ProjectiveEquiv (_root_.bsmul (padBits (natToBits order) k) P params) infinityPoint) :
    ProjectiveEquiv (_root_.addE (_root_.bsmul (padBits (natToBits val) k) P params) (_root_.bsmul (padBits (natToBits (order - val)) k) P params) params) infinityPoint := by
  have h_sum : val + (order - val) = order := by omega
  have h_distrib := bsmul_distrib_nat_gen k val (order - val) P params hp
  rw [h_sum] at h_distrib
  exact ProjectiveEquiv.trans (ProjectiveEquiv.symm h_distrib) h_annihilate

lemma bsmul_add_neg_cancel (k : Nat) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F) (order : Nat)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params) (h_order : ProjectiveEquiv (bsmul (padBits (natToBits order) k) P params) infinityPoint)
    (h_order_pos : 0 < order) :
    ProjectiveEquiv (addE (bsmul (padBits (natToBits val) k) P params) (bsmul (padBits (natToBits (order - (val % order))) k) P params) params) infinityPoint := by
  have h_val_red : ProjectiveEquiv (bsmul (padBits (natToBits val) k) P params) (bsmul (padBits (natToBits (val % order)) k) P params) := by
    exact ProjectiveEquiv.symm (bsmul_mod_nat k val P params order hp h_order)
  have h_sum_equiv : ProjectiveEquiv
    (addE (bsmul (padBits (natToBits val) k) P params) (bsmul (padBits (natToBits (order - (val % order))) k) P params) params)
    (addE (bsmul (padBits (natToBits (val % order)) k) P params) (bsmul (padBits (natToBits (order - (val % order))) k) P params) params) := by
    exact h_val_red.addE params (ProjectiveEquiv.refl _)
  have h_cancel : ProjectiveEquiv (addE (bsmul (padBits (natToBits (val % order)) k) P params) (bsmul (padBits (natToBits (order - (val % order))) k) P params) params) infinityPoint := by
    have h_lt : val % order < order := Nat.mod_lt val h_order_pos
    exact bsmul_inverse_gen (val % order) h_lt hp h_order
  exact ProjectiveEquiv.trans h_sum_equiv h_cancel

/--
  Congruence lemma showing that projective scalar multiplication preserves projective equivalence of base points.
-/
lemma ProjectiveEquiv.bsmul {p1 p2 : ProjectivePoint F} (s : List Bool) (params : CurveParameters F)
    (h : ProjectiveEquiv p1 p2) : ProjectiveEquiv (_root_.bsmul s p1 params) (_root_.bsmul s p2 params) := by
  unfold _root_.bsmul
  exact h.nsmulFastE (bitsToNat s) params

/--
  Shows equivalence between single-bit scalar multiplication and 1-bit padded natural number multiplication.
-/
lemma bsmul_bool_eq_nat (b : Bool) (P : ProjectivePoint F) (params : CurveParameters F) :
    bsmul [b] P params = bsmul (padBits (natToBits (if b then 1 else 0)) 1) P params := by
  cases b
  · simp [natToBits, Nat.bits, padBits, List.leftpad]
  · simp [natToBits, Nat.bits, padBits, List.leftpad]

lemma bsmul_one (Q : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] (hQ : Q.IsOnCurve params) :
    ProjectiveEquiv (bsmul [true] Q params) Q := by
  unfold bsmul
  dsimp [bitsToNat]
  change ProjectiveEquiv (nsmulFastE (Nat.bit true 0) Q params) Q
  rw [nsmulFastE_bit]
  dsimp
  unfold nsmulFastE
  rw [Nat.binaryRec_zero]
  try dsimp
  rw [doubleE_infinity]
  exact addE_infinity_left Q params hQ.Y_ne_zero

lemma bsmul_scale_nat (n : Nat) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)] (hp : P.IsOnCurve params) :
    ProjectiveEquiv (bsmul ([true] ++ List.replicate n false) (bsmul (padBits (natToBits val) 1) P params) params)
    (bsmul (padBits (natToBits (val * 2^n)) (n+1)) P params) := by
  induction n with
  | zero =>
    simp
    have h_Q_on : (bsmul (padBits (natToBits val) 1) P params).IsOnCurve params := bsmul_on_curve _ P params hp
    exact bsmul_one _ params h_Q_on
  | succ n ih =>
    have h_scale_succ : [true] ++ List.replicate (n+1) false = ([true] ++ List.replicate n false) ++ [false] := by
      simp [List.replicate_succ']
    rw [h_scale_succ]
    have h_step1 := bsmul_scale_double ([true] ++ List.replicate n false) (bsmul (padBits (natToBits val) 1) P params) params
    have h_LHS : ProjectiveEquiv (bsmul (([true] ++ List.replicate n false) ++ [false]) (bsmul (padBits (natToBits val) 1) P params) params)
      (doubleE (bsmul ([true] ++ List.replicate n false) (bsmul (padBits (natToBits val) 1) P params) params) params) := by
      rw [←h_step1]
      exact ProjectiveEquiv.refl _
    have h_congr : ProjectiveEquiv (doubleE (bsmul ([true] ++ List.replicate n false) (bsmul (padBits (natToBits val) 1) P params) params) params)
      (doubleE (bsmul (padBits (natToBits (val * 2^n)) (n+1)) P params) params) := by
      exact ih.doubleE params
    have h_step2 := ProjectiveEquiv.trans h_LHS h_congr
    have h_scale_double_R := bsmul_scale_double (padBits (natToBits (val * 2^n)) (n+1)) P params
    have h_congr_R : ProjectiveEquiv (doubleE (bsmul (padBits (natToBits (val * 2^n)) (n+1)) P params) params)
      (bsmul (padBits (natToBits (val * 2^n)) (n+1) ++ [false]) P params) := by
      rw [h_scale_double_R]
      exact ProjectiveEquiv.refl _
    have h_step3 := ProjectiveEquiv.trans h_step2 h_congr_R
    have h_list_eq : padBits (natToBits (val * 2^n)) (n+1) ++ [false] = padBits (natToBits (val * 2^(n+1))) (n+2) := by
      have h_pow : val * 2^(n+1) = (val * 2^n) * 2 := by ring
      rw [h_pow]
      exact padBits_scale_double (val * 2^n) n
    rw [h_list_eq] at h_step3
    exact h_step3

lemma bsmul_scale_helper (n : Nat) (b : Bool) (val : Nat) (P : ProjectivePoint F) (params : CurveParameters F)
    [CurveHasNoPointsOfOrder2 params] [h_ell : (params.toMathlib).IsElliptic] [NeZero (2 : F)] [NeZero (3 : F)]
    (hp : P.IsOnCurve params) (h_val : val = if b then 1 else 0) :
    ProjectiveEquiv (bsmul ([true] ++ List.replicate n false) (bsmul [b] P params) params)
    (bsmul (padBits (natToBits (val * 2^n)) (n+1)) P params) := by
  have h_eq : bsmul [b] P params = bsmul (padBits (natToBits val) 1) P params := by
    rw [h_val]
    exact bsmul_bool_eq_nat b P params
  have h_equiv : ProjectiveEquiv (bsmul [b] P params) (bsmul (padBits (natToBits val) 1) P params) := by
    rw [h_eq]
    exact ProjectiveEquiv.refl _
  have h_scale := bsmul_scale_nat n val P params hp
  have h_tx_scaled : ProjectiveEquiv (bsmul ([true] ++ List.replicate n false) (bsmul [b] P params) params)
                                      (bsmul ([true] ++ List.replicate n false) (bsmul (padBits (natToBits val) 1) P params) params) := by
    exact h_equiv.bsmul ([true] ++ List.replicate n false) params
  exact ProjectiveEquiv.trans h_tx_scaled h_scale

end Bsmul

section BridgeInstance

lemma eq_zero_of_add_self_eq_zero_of_odd_card {G : Type*} [AddGroup G] [Fintype G]
    (h_odd : Odd (Fintype.card G)) (x : G) (hx : x + x = 0) : x = 0 := by
  have h2x : 2 • x = 0 := by
    rw [two_nsmul]
    exact hx
  have h_dvd : addOrderOf x ∣ 2 := by
    rwa [← addOrderOf_dvd_iff_nsmul_eq_zero] at h2x
  have h_dvd_card : addOrderOf x ∣ Fintype.card G := addOrderOf_dvd_card
  have h_coprime : Nat.Coprime 2 (Fintype.card G) := h_odd.coprime_two_left
  have h_one : addOrderOf x = 1 := by
    have h_dvd_gcd : addOrderOf x ∣ Nat.gcd 2 (Fintype.card G) := Nat.dvd_gcd h_dvd h_dvd_card
    rw [Nat.Coprime.gcd_eq_one h_coprime] at h_dvd_gcd
    exact Nat.eq_one_of_dvd_one h_dvd_gcd
  exact AddMonoid.addOrderOf_eq_one_iff.mp h_one

open WeierstrassCurve

instance WeierstrassCurve.toProjective.Point.CurveHasNoPointsOfOrder2
    {F : Type} [Field F] (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [NeZero (2 : F)] [NeZero (3 : F)]
    [Fintype (params.toMathlib.toProjective.Point)]
    [h_odd : Fact (Odd (Fintype.card (params.toMathlib.toProjective.Point)))] :
    CurveHasNoPointsOfOrder2 params where
  no_roots := by
    intro x_0 h_root
    let P_proj : ProjectivePoint F := { X := x_0, Y := 0, Z := 1 }
    have h_P_on : P_proj.IsOnCurve params := by
      constructor
      · unfold ProjectivePoint.SatisfiesCurveEquation
        simp [P_proj]
        linear_combination -1 * h_root
      · intro h_zero
        injection h_zero with _ _ h_z
        exact one_ne_zero h_z
    let P_ml := P_proj.toMathlibPoint params h_P_on
    have h_rep_eq : P_proj.toMathlib = WeierstrassCurve.Projective.neg (params.toMathlib) P_proj.toMathlib := by
      ext i
      fin_cases i
      · rfl
      · dsimp [ProjectivePoint.toMathlib, WeierstrassCurve.Projective.neg, WeierstrassCurve.Projective.negY, CurveParameters.toMathlib]
        ring
      · rfl
    have h_neg : P_ml = - P_ml := by
      ext
      exact congr_arg (Quotient.mk _) h_rep_eq
    have h_double : P_ml + P_ml = 0 := by
      nth_rw 2 [h_neg]
      rw [add_neg_cancel]
    have h_ne_zero : P_ml ≠ 0 := by
      intro h_ml_zero
      have h_inf_on : infinityPoint.IsOnCurve params := infinity_on_curve params
      have h_ml_inf : P_ml = infinityPoint.toMathlibPoint params h_inf_on := by
        rw [toMathlibPoint_infinity params h_inf_on]
        exact h_ml_zero
      have h_equiv : ProjectiveEquiv P_proj infinityPoint := by
        rwa [toMathlibPoint_eq_iff_ProjectiveEquiv P_proj infinityPoint params h_P_on h_inf_on] at h_ml_inf
      rcases h_equiv with ⟨c, hc, h_eq⟩
      have h_z := congr_arg ProjectivePoint.Z h_eq
      dsimp [P_proj, infinityPoint, HSMul.hSMul, SMul.smul] at h_z
      rw [mul_zero] at h_z
      exact one_ne_zero h_z
    have h_bad := eq_zero_of_add_self_eq_zero_of_odd_card h_odd.out P_ml h_double
    contradiction

end BridgeInstance
