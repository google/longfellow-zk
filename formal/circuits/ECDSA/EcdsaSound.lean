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

import ECDSA.Ecdsa

/-!
# ECDSA Soundness Proof

This module contains the formal soundness proof for the ECDSA verification circuit.
It establishes that if the circuit constraints are satisfied for a given witness,
then the reconstructed signature is valid under the standard ECDSA specification.

Specifically, it proves that if there exists a valid circuit witness `w` satisfying
`ValidEcdsaWitness` for a public key `pk` and hashed message `e`, then the reconstructed
signature values `r = natR(bi)` and `s = order - natS(bi)` form a mathematically valid
ECDSA signature under the standard non-interactive elliptic curve verification
relation `StandardEcdsaVerify`.

The main result is `ecdsa_circuit_soundness`.
-/
set_option linter.unusedSectionVars false

section ECDSA

variable {F : Type} [Field F] [NeZero (2 : F)] [NeZero (3 : F)] [NeZero (4 : F)] [NeZero (5 : F)] [NeZero (6 : F)] [NeZero (7 : F)]

/--
  ### Soundness Hypotheses:
  1. **Witness Validity (`h : ValidEcdsaWitness`)**:
     - The circuit's intermediate variables, bounds, and polynomial verification loop constraints are satisfied.
  2. **Prime Group Order (`h_prime : Fact (Nat.Prime order)`)**:
     - The subgroup order `order` is prime, which is used to guarantee the existence of modular inverses.
  3. **Base Point Validity (`h_G_on`)**:
     - The base generator point `G` is a valid projective curve point.
  4. **Key and Point Orders (`h_pk_order`, `h_G_order`, `h_R_order`)**:
     - The public key `pk`, base generator `G`, and reconstruct point `R` are assumed to be scaled to the
       point at infinity `infinityPoint` under group order multiplication (`order * P = O`).
  5. **Exceptional Weierstrass Addition Prevention (`h_GPK_Z`, `h_GR_Z`, `h_RPK_Z`, `h_GRPK_Z`)**:
     - The projective additions `G + PK`, `R + G`, `R + PK`, and `G + (R + PK)` must not hit the point
       at infinity (i.e., their Z-coordinates must be non-zero). This avoids exceptional addition cases.

-/
theorem ecdsa_circuit_soundness (w : EcdsaWitness F) (pk : AffinePoint F) (e : F) (order : Nat) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [Fintype (params.toMathlib.toProjective.Point)]
    [h_odd : Fact (Odd (Fintype.card (params.toMathlib.toProjective.Point)))]
    [h_prime : Fact (Nat.Prime order)]
    (h : ValidEcdsaWitness w pk e order params)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_pk_order : bsmul (padBits (natToBits order) params.kBits) pk.toProjective params = infinityPoint)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_R_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective params) infinityPoint) :
    ∃ (r s : Nat) (e_nat : Nat),
      r = natR (w.bi.map val3) ∧
      s = order - natS (w.bi.map val3) ∧
      e_nat = natE (w.bi.map val3) ∧
      StandardEcdsaVerify pk e_nat r s order params := by
  have h_copy := h
  rcases h with ⟨h_len, h_len_x, h_len_y, h_len_z, h_len_pre, h_bi, h_pre, h_loop, h_final_x, h_final_z, h_est, h_rst, h_on_pk, h_on_r, h_rx_inv, h_s_inv_f, h_pk_inv, h_r_lt, h_s_lt⟩
  rcases h_pre with ⟨h_pre_len, h_gpk_eq, h_gr_eq, h_rpk_eq, h_grpk_eq⟩
  let bi_nat := w.bi.map val3
  let r_nat := natR bi_nat
  let s_nat := natS bi_nat
  let e_nat := natE bi_nat
  use r_nat
  use (order - s_nat)
  use e_nat
  refine ⟨rfl, rfl, rfl, ?_⟩
  unfold StandardEcdsaVerify
  refine ⟨h_on_pk, h_pk_order, ?_⟩
  -- 1. Prove r range checks
  have h_r_pos := r_nat_pos w pk e order params h_copy
  refine ⟨h_r_pos, h_r_lt, ?_⟩
  -- 2. Prove s range checks
  have h_s_rng := s_range w pk e order params h_copy
  have ⟨h_s_pos, h_s_lt⟩ := h_s_rng
  refine ⟨h_s_pos, h_s_lt, ?_⟩
  -- 3. Prove core verification relation
  have h_bi_nat_bounds : ∀ v ∈ w.bi.map val3, v < 8 := map_val3_bounds w.bi h_bi

  have h_loop_nat : EcdsaLoopConstraints infinityPoint true bi_nat w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params := by
    have h_equiv := EcdsaLoopConstraintsF_cast_eq bi_nat h_bi_nat_bounds infinityPoint true w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params
    rw [cast_val3_eq w.bi h_bi] at h_equiv
    exact h_equiv.mp h_loop

  have h_loop_F_eq : ecdsaLoopResultF infinityPoint true w.bi w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params =
                     ecdsaLoopResult infinityPoint true bi_nat w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params := by
    have h_eq := ecdsaLoopResultF_cast_eq bi_nat h_bi_nat_bounds infinityPoint true w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params
    rw [cast_val3_eq w.bi h_bi] at h_eq
    exact h_eq

  have h_pure_eq : ecdsaLoopResult infinityPoint true bi_nat w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params =
                   ecdsaPureLoopResult bi_nat pk w.rx w.ry w.pre params := by
     have h_thm := ecdsaLoopResult_eq_ecdsaPureLoopResult infinityPoint true bi_nat w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params h_loop_nat
     exact h_thm

  have h_pure_x : (ecdsaPureLoopResult bi_nat pk w.rx w.ry w.pre params).X = 0 := by
    rw [←h_pure_eq, ←h_loop_F_eq]
    exact h_final_x
  have h_pure_z : (ecdsaPureLoopResult bi_nat pk w.rx w.ry w.pre params).Z = 0 := by
    rw [←h_pure_eq, ←h_loop_F_eq]
    exact h_final_z

  have h_R_proj_on : ProjectivePoint.IsOnCurve ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective params := by
    refine ⟨?_, ?_⟩
    · have h_on_aff : AffinePoint.IsOnCurve { X := w.rx, Y := w.ry } params := h_on_r
      unfold AffinePoint.IsOnCurve at h_on_aff
      unfold ProjectivePoint.SatisfiesCurveEquation
      simp only [mul_one]
      exact h_on_aff
    · intro h_zero
      change (({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective) = ({ X := 0, Y := 0, Z := 0 : ProjectivePoint F }) at h_zero
      injection h_zero with _ _ h_z
      exact one_ne_zero h_z

  have h_PK_proj_on : ProjectivePoint.IsOnCurve pk.toProjective params := by
    refine ⟨?_, ?_⟩
    · unfold AffinePoint.IsOnCurve at h_on_pk
      unfold ProjectivePoint.SatisfiesCurveEquation
      simp only [mul_one]
      exact h_on_pk
    · intro h_zero
      change (pk.toProjective) = ({ X := 0, Y := 0, Z := 0 : ProjectivePoint F }) at h_zero
      injection h_zero with _ _ h_z
      exact one_ne_zero h_z

  -- Inline proofs for Z-coordinate exceptional bounds
  have h_GPK_on : ProjectivePoint.IsOnCurve (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params) params :=
    addE_on_curve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params h_G_on h_PK_proj_on
  have h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0 :=
    z_ne_zero_of_point_equality_and_on_curve (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params) (w.pre.getD 0 0) (w.pre.getD 1 0) params h_GPK_on h_gpk_eq

  have h_GR_on : ProjectivePoint.IsOnCurve (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) params :=
    addE_on_curve ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params h_R_proj_on h_G_on
  have h_GR_Z : (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0 :=
    z_ne_zero_of_point_equality_and_on_curve (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) (w.pre.getD 2 0) (w.pre.getD 3 0) params h_GR_on h_gr_eq

  have h_RPK_on : ProjectivePoint.IsOnCurve (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params) params :=
    addE_on_curve ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params h_R_proj_on h_PK_proj_on
  have h_RPK_Z : (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0 :=
    z_ne_zero_of_point_equality_and_on_curve (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params) (w.pre.getD 4 0) (w.pre.getD 5 0) params h_RPK_on h_rpk_eq

  have h_RPK_proj_on : ProjectivePoint.IsOnCurve ({ X := w.pre.getD 4 0, Y := w.pre.getD 5 0 : AffinePoint F }).toProjective params :=
    projective_point_on_curve_of_point_equality (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params) (w.pre.getD 4 0) (w.pre.getD 5 0) params h_RPK_on h_RPK_Z h_rpk_eq
  have h_GRPK_on : ProjectivePoint.IsOnCurve (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := w.pre.getD 4 0, Y := w.pre.getD 5 0 : AffinePoint F }).toProjective params) params :=
    addE_on_curve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := w.pre.getD 4 0, Y := w.pre.getD 5 0 : AffinePoint F }).toProjective params h_G_on h_RPK_proj_on
  have h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0 := by
    have h_pt_eq : { X := (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } =
                   ({ X := w.pre.getD 4 0, Y := w.pre.getD 5 0 : AffinePoint F }).toProjective := by
      ext
      · dsimp
        have hx := h_rpk_eq.1
        rw [hx]
        rw [mul_comm (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z, mul_assoc, mul_inv_cancel₀ h_RPK_Z, mul_one]
      · dsimp
        have hy := h_rpk_eq.2
        rw [hy]
        rw [mul_comm (addE ({ X := w.rx, Y := w.ry : AffinePoint F }).toProjective pk.toProjective params).Z, mul_assoc, mul_inv_cancel₀ h_RPK_Z, mul_one]
      · rfl
    rw [h_pt_eq]
    exact z_ne_zero_of_point_equality_and_on_curve (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := w.pre.getD 4 0, Y := w.pre.getD 5 0 : AffinePoint F }).toProjective params) (w.pre.getD 6 0) (w.pre.getD 7 0) params h_GRPK_on h_grpk_eq

  have h_PK_order_equiv : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) pk.toProjective params) infinityPoint := by
    have h_std_order := h_pk_order
    exact h_std_order ▸ ProjectiveEquiv.refl _

  have ⟨h_s_pos, h_s_lt⟩ := s_range w pk e order params h_copy
  have h_s_inv := exists_mod_inv_of_prime_of_lt_of_pos h_s_lt h_s_pos
  rcases h_s_inv with ⟨s_inv, hs_inv⟩
  have h_bi_nat_len : bi_nat.length = params.kBits := by rw [List.length_map]; exact h_len
  have h_equiv := ecdsa_algebraic_equivalence bi_nat pk w.rx w.ry w.pre params order
    h_bi_nat_len h_bi_nat_bounds ⟨h_pre_len, h_gpk_eq, h_gr_eq, h_rpk_eq, h_grpk_eq⟩ h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z
    h_G_on h_PK_proj_on h_R_proj_on
    h_G_order h_PK_order_equiv h_R_order
    ⟨h_pure_x, h_pure_z⟩ s_inv hs_inv
  rcases h_equiv with ⟨h_R_eq, h_RZ_ne⟩
  let z := e_nat % order
  let u1 := (z * s_inv) % order
  let u2 := (r_nat * s_inv) % order
  let G_proj : ProjectivePoint F := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj : ProjectivePoint F := pk.toProjective
  let R_std := addE (bsmul (padBits (natToBits u1) params.kBits) G_proj params) (bsmul (padBits (natToBits u2) params.kBits) PK_proj params) params
  use s_inv
  refine ⟨hs_inv, ?_⟩
  constructor
  · intro h_inf
    exact h_RZ_ne h_inf.2
  · use R_std.Z⁻¹
    have h_mul_inv : R_std.Z * R_std.Z⁻¹ = 1 := mul_inv_cancel₀ h_RZ_ne
    refine ⟨h_mul_inv, ?_⟩
    have h_RX_eq : R_std.X = w.rx * R_std.Z := by
      exact (projectiveEquiv_toProjective_iff R_std { X := w.rx, Y := w.ry }).mp h_R_eq |>.1
    rw [h_RX_eq]
    rw [mul_assoc, h_mul_inv, mul_one]
    have h_rx_eq : reconstructR bi_nat = ((natR bi_nat : Nat) : F) := reconstructR_eq_natR bi_nat
    rw [h_rx_eq] at h_rst
    exact h_rst

end ECDSA
