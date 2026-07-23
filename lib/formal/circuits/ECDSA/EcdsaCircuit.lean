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

import ECDSA.EcdsaSpec

open Classical

section ECDSA

variable {F : Type} [Field F] [NeZero (2 : F)] [NeZero (3 : F)] [NeZero (4 : F)] [NeZero (5 : F)] [NeZero (6 : F)] [NeZero (7 : F)]

-- ===========================================================================
-- ZK Circuit Model (verify_circuit.h)
-- Formal model of the circuit constructed using C++ primitives to verify an
-- ECDSA signature.
-- ===========================================================================

/--
  Witness for the ECDSA verification circuit.
  Each of these fields maps directly to the similarly named field in the 
  C++ `struct Witness` in `verify_circuit.h`. For convenience, they are described:
  - `rx`, `ry` map to `EltW rx, ry` (coordinates of the signature point R).
  - `pre` maps to `EltW pre[8]` (precomputed points GPK, GR, RPK, GRPK).
  - `rx_inv`, `s_inv`, `pk_inv` map to `EltW rx_inv, s_inv, pk_inv` (multiplicative inverses).
  - `bi` maps to `EltW bi[kBits]` (the 3-bit multiplexer select indices).
  - `int_x`, `int_y`, `int_z` map to `EltW int_x[]`, `int_y[]`, `int_z[]` (intermediate loop accumulators).
-/
structure EcdsaWitness (F : Type) where
  rx : F
  ry : F
  pre : List F -- size 8
  rx_inv : F
  s_inv : F
  pk_inv : F
  bi : List F -- select indices
  int_x : List F
  int_y : List F
  int_z : List F

/--
  Checks if a projective point is equal to an affine point (given by its coordinates).
  Maps directly to the C++ `point_equality` helper in `verify_circuit.h`.
  This method works when
  1. The projective point `proj` is NOT the point at infinity.
     If `proj` is the point at infinity (where `Z = 0` and `Y ≠ 0`),
     this check will always evaluate to `False` (since `Y = Z * affY` would imply `Y = 0`),
     which correctly rejects the point at infinity.
  2. `proj.Z ≠ 0`. When `proj.Z ≠ 0`, this is mathematically
     equivalent to `affX = proj.X / proj.Z` and `affY = proj.Y / proj.Z`.
-/
def IsPointEquality (proj : ProjectivePoint F) (affX affY : F) : Prop :=
  proj.X = proj.Z * affX ∧ proj.Y = proj.Z * affY

/--
  Validates that the precomputed points table `pre` is constructed correctly.
  Maps to the C++ parallel precomputation checks in `verify_signature3`:
  - `GPK := addE G PK` and `IsPointEquality GPK pre[0] pre[1]`
    maps to `addE(cg_pkx, cg_pky, cg_pkz, gx, gy, 1, pk_x, pk_y, 1)`
    and `point_equality(cg_pkx, cg_pky, cg_pkz, w.pre[GPK_X], w.pre[GPK_Y])`.
  - `GR := addE R G` maps to `addE(cr_gx, cr_gy, cr_gz, w.rx, w.ry, 1, gx, gy, 1)`
    and `point_equality(cr_gx, ..., w.pre[GR_X], w.pre[GR_Y])`.
  - `RPK := addE R PK` maps to `addE(cr_pkx, cr_pky, cr_pkz, w.rx, w.ry, 1, pk_x, pk_y, 1)`
    and `point_equality(cr_pkx, ..., w.pre[RPK_X], w.pre[RPK_Y])`.
  - `GRPK := addE G RPK` maps to `addE(cr_g_pkx, ..., gx, gy, 1, w.pre[RPK_X], w.pre[RPK_Y], 1)`
    and `point_equality(cr_g_pkx, ..., w.pre[GRPK_X], w.pre[GRPK_Y])`.
-/
def ValidPreComputationExact (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : Prop :=
  pre.length = 8 ∧
  let G_proj : ProjectivePoint F := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj : ProjectivePoint F := pk.toProjective
  let R_proj : ProjectivePoint F := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  let GPK := addE G_proj PK_proj params
  let GR := addE R_proj G_proj params
  let RPK := addE R_proj PK_proj params
  let GRPK := addE G_proj ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective params
  IsPointEquality GPK (pre.getD 0 0) (pre.getD 1 0) ∧
  IsPointEquality GR (pre.getD 2 0) (pre.getD 3 0) ∧
  IsPointEquality RPK (pre.getD 4 0) (pre.getD 5 0) ∧
  IsPointEquality GRPK (pre.getD 6 0) (pre.getD 7 0)

/--
  Multiplexer that selects the point slice to add at each step.
  Decomposes the index `v` in [0, 7] into 3 bits (s, r, e) and selects the point.
  Maps directly to `arr_x[]`, `arr_y[]`, `arr_z[]` in `verify_signature3`:
  - 0: `infinityPoint` (0, 1, 0)      <- when s, r, e are all 0
  - 1: `G` (gx, gy, 1)                <- when e bit is 1, others 0 (G)
  - 2: `PK` (pk_x, pk_y, 1)           <- when r bit is 1, others 0 (PK)
  - 3: `GPK` (pre[0], pre[1], 1)      <- when e, r are 1, s is 0 (G + PK)
  - 4: `R` (rx, ry, 1)                <- when s bit is 1, others 0 (R)
  - 5: `GR` (pre[2], pre[3], 1)       <- when e, s are 1, r is 0 (G + R)
  - 6: `RPK` (pre[4], pre[5], 1)      <- when r, s are 1, e is 0 (R + PK)
  - 7: `GRPK` (pre[6], pre[7], 1)     <- when e, r, s are all 1 (G + R + PK)
-/
def muxPoint (v : Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  match v with
  | 0 => { X := 0, Y := 1, Z := 0 } -- infinity
  | 1 => ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective -- G
  | 2 => pk.toProjective -- PK
  | 3 => ({ X := pre.getD 0 0, Y := pre.getD 1 0 : AffinePoint F }).toProjective -- GPK
  | 4 => ({ X := rx, Y := ry : AffinePoint F }).toProjective -- R
  | 5 => ({ X := pre.getD 2 0, Y := pre.getD 3 0 : AffinePoint F }).toProjective -- GR
  | 6 => ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective -- RPK
  | 7 => { X := pre.getD 6 0, Y := pre.getD 7 0, Z := 1 } -- GRPK
  | _ => { X := 0, Y := 1, Z := 0 }

/--
  Models the unrolled loop step assertions on intermediate accumulator values.
  Maps directly to the C++ loop step in `verify_signature3`:
  - `tx, ty, tz := muxPoint v` maps to `xx.mux(w.bi[i])` point selection.
  - `doubled := doubleE acc` and `nextAcc := addE doubled tx` maps to:
    `if (i > 0) { doubleE(ax, ay, az, ax, ay, az); }`
    `addE(ax, ay, az, ax, ay, az, tx, ty, tz);`
  - `nextAcc.X = wx` etc. maps to the intermediate witness assertions:
    `lc_.assert_eq(ax, w.int_x[i]);`
    `lc_.assert_eq(ay, w.int_y[i]);`
    `lc_.assert_eq(az, w.int_z[i]);`
  - Passing `{ X := wx, Y := wy, Z := wz }` to next recursive step maps to:
    `ax = w.int_x[i]; ay = w.int_y[i]; az = w.int_z[i];`
-/
def EcdsaLoopConstraints {F : Type} [Field F] :
  ProjectivePoint F → Bool → List Nat → List F → List F → List F → AffinePoint F → F → F → List F → CurveParameters F → Prop
  | _, _, [], _, _, _, _, _, _, _, _ => True
  | _, _, [_], [], [], [], _, _, _, _, _ => True
  | acc, is_first, v :: vs@(_::_), wx :: wxs, wy :: wys, wz :: wzs, pk, rx, ry, pre, params =>
    let tx := muxPoint v pk rx ry pre params
    let doubled := if is_first then acc else doubleE acc params
    let nextAcc := addE doubled tx params
    nextAcc.X = wx ∧ nextAcc.Y = wy ∧ nextAcc.Z = wz ∧
    EcdsaLoopConstraints { X := wx, Y := wy, Z := wz } false vs wxs wys wzs pk rx ry pre params
  | _, _, _, _, _, _, _, _, _, _, _ => False

def ecdsaLoopResult {F : Type} [Field F] :
  ProjectivePoint F → Bool → List Nat → List F → List F → List F → AffinePoint F → F → F → List F → CurveParameters F → ProjectivePoint F
  | acc, _, [], _, _, _, _, _, _, _, _ => acc
  | acc, is_first, [v], [], [], [], pk, rx, ry, pre, params =>
    let tx := muxPoint v pk rx ry pre params
    let doubled := if is_first then acc else doubleE acc params
    addE doubled tx params
  | _, _, _ :: vs@(_::_), wx :: wxs, wy :: wys, wz :: wzs, pk, rx, ry, pre, params =>
    ecdsaLoopResult { X := wx, Y := wy, Z := wz } false vs wxs wys wzs pk rx ry pre params
  | _, _, _, _, _, _, _, _, _, _, _ => infinityPoint

def ecdsaLoopStepExact (state : ProjectivePoint F × Bool) (v : Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F × Bool :=
  let (acc, is_first) := state
  let tx := muxPoint v pk rx ry pre params
  let doubled := if is_first then acc else doubleE acc params
  let nextAcc := addE doubled tx params
  (nextAcc, false)

def ecdsaPureLoopResultGeneral {F : Type} [Field F] (acc : ProjectivePoint F) (is_first : Bool) (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  let (finalAcc, _) := bi.foldl (fun state v => ecdsaLoopStepExact state v pk rx ry pre params) (acc, is_first)
  finalAcc

def ecdsaPureLoopResult {F : Type} [Field F] (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  ecdsaPureLoopResultGeneral infinityPoint true bi pk rx ry pre params

noncomputable def val3 {F : Type} [Field F] (v : F) : Nat :=
  if v = 0 then 0
  else if v = 1 then 1
  else if v = 2 then 2
  else if v = 3 then 3
  else if v = 4 then 4
  else if v = 5 then 5
  else if v = 6 then 6
  else if v = 7 then 7
  else 0

noncomputable def muxPointF (v : F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  if v = 0 then { X := 0, Y := 1, Z := 0 } -- infinity
  else if v = 1 then ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective -- G
  else if v = 2 then pk.toProjective -- PK
  else if v = 3 then ({ X := pre.getD 0 0, Y := pre.getD 1 0 : AffinePoint F }).toProjective -- GPK
  else if v = 4 then ({ X := rx, Y := ry : AffinePoint F }).toProjective -- R
  else if v = 5 then ({ X := pre.getD 2 0, Y := pre.getD 3 0 : AffinePoint F }).toProjective -- GR
  else if v = 6 then ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective -- RPK
  else if v = 7 then { X := pre.getD 6 0, Y := pre.getD 7 0, Z := 1 } -- GRPK
  else { X := 0, Y := 1, Z := 0 }

noncomputable def EcdsaLoopConstraintsF {F : Type} [Field F] :
  ProjectivePoint F → Bool → List F → List F → List F → List F → AffinePoint F → F → F → List F → CurveParameters F → Prop
  | _, _, [], _, _, _, _, _, _, _, _ => True
  | _, _, [_], [], [], [], _, _, _, _, _ => True
  | acc, is_first, v :: vs@(_::_), wx :: wxs, wy :: wys, wz :: wzs, pk, rx, ry, pre, params =>
    let tx := muxPointF v pk rx ry pre params
    let doubled := if is_first then acc else doubleE acc params
    let nextAcc := addE doubled tx params
    nextAcc.X = wx ∧ nextAcc.Y = wy ∧ nextAcc.Z = wz ∧
    EcdsaLoopConstraintsF { X := wx, Y := wy, Z := wz } false vs wxs wys wzs pk rx ry pre params
  | _, _, _, _, _, _, _, _, _, _, _ => False

noncomputable def ecdsaLoopResultF {F : Type} [Field F] :
  ProjectivePoint F → Bool → List F → List F → List F → List F → AffinePoint F → F → F → List F → CurveParameters F → ProjectivePoint F
  | acc, _, [], _, _, _, _, _, _, _, _ => acc
  | acc, is_first, [v], [], [], [], pk, rx, ry, pre, params =>
    let tx := muxPointF v pk rx ry pre params
    let doubled := if is_first then acc else doubleE acc params
    addE doubled tx params
  | _, _, _ :: vs@(_::_), wx :: wxs, wy :: wys, wz :: wzs, pk, rx, ry, pre, params =>
    ecdsaLoopResultF { X := wx, Y := wy, Z := wz } false vs wxs wys wzs pk rx ry pre params
  | _, _, _, _, _, _, _, _, _, _, _ => infinityPoint

noncomputable def ecdsaLoopStepExactF (state : ProjectivePoint F × Bool) (v : F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F × Bool :=
  let (acc, is_first) := state
  let tx := muxPointF v pk rx ry pre params
  let doubled := if is_first then acc else doubleE acc params
  let nextAcc := addE doubled tx params
  (nextAcc, false)

noncomputable def ecdsaPureLoopResultGeneralF {F : Type} [Field F] (acc : ProjectivePoint F) (is_first : Bool) (bi : List F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  let (finalAcc, _) := bi.foldl (fun state v => ecdsaLoopStepExactF state v pk rx ry pre params) (acc, is_first)
  finalAcc

noncomputable def ecdsaPureLoopResultF {F : Type} [Field F] (bi : List F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) : ProjectivePoint F :=
  ecdsaPureLoopResultGeneralF infinityPoint true bi pk rx ry pre params

/--
  Verification relation for the ZK circuit.
  Maps directly to the final boundary assertions at the end of `verify_signature3`:
  - `finalAcc.X = 0 ∧ finalAcc.Z = 0` maps to `lc_.assert0(ax)` and `lc_.assert0(az)`
    asserting the final accumulator is the point at infinity (0, Y, 0).
  - `reconstructE w.bi = e` maps to `lc_.assert_eq(est, e)`.
  - `reconstructR w.bi = w.rx` maps to `lc_.assert_eq(rst, w.rx)`.
  - `IsOnCurve pk` and `IsOnCurve w.rx` map to `is_on_curve(pk_x, pk_y)` and `is_on_curve(w.rx, w.ry)`.
  - `w.rx * w.rx_inv = 1` maps to `assert_nonzero(w.rx, w.rx_inv)`.
  - `reconstructS w.bi * w.s_inv = 1` maps to `assert_nonzero(sst, w.s_inv)`.
  - `pk.X * w.pk_inv = 1` maps to `assert_nonzero(pk_x, w.pk_inv)`.
  - `natR w.bi < order` and `natS w.bi < order` map to unit range checks:
    `auto r_range = lc_.vlt(r_bits, bits_n_); lc_.assert1(r_range);`
    `auto s_range = lc_.vlt(s_bits, bits_n_); lc_.assert1(s_range);`
-/
def ValidEcdsaWitness (w : EcdsaWitness F) (pk : AffinePoint F) (e : F) (order : Nat) (params : CurveParameters F) : Prop :=
  w.bi.length = params.kBits ∧
  w.int_x.length = params.kBits - 1 ∧
  w.int_y.length = params.kBits - 1 ∧
  w.int_z.length = params.kBits - 1 ∧
  w.pre.length = 8 ∧
  (∀ v ∈ w.bi, v = 0 ∨ v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7) ∧
  ValidPreComputationExact pk w.rx w.ry w.pre params ∧
  EcdsaLoopConstraintsF infinityPoint true w.bi w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params ∧
  let finalAcc := ecdsaLoopResultF infinityPoint true w.bi w.int_x w.int_y w.int_z pk w.rx w.ry w.pre params
  finalAcc.X = 0 ∧ finalAcc.Z = 0 ∧
  let bi_nat := w.bi.map val3
  reconstructE bi_nat = e ∧
  reconstructR bi_nat = w.rx ∧
  pk.IsOnCurve params ∧
  AffinePoint.IsOnCurve { X := w.rx, Y := w.ry } params ∧
  w.rx * w.rx_inv = 1 ∧
  reconstructS bi_nat * w.s_inv = 1 ∧
  pk.X * w.pk_inv = 1 ∧
  natR bi_nat < order ∧
  natS bi_nat < order

lemma val3_cast_eq
    (v : Nat) (h : v < 8) : val3 (v : F) = v := sorry

lemma map_val3_cast_eq
    (bi : List Nat) (h : ∀ v ∈ bi, v < 8) : (bi.map (fun (x : Nat) => (x : F))).map val3 = bi := sorry

lemma muxPointF_cast_eq
    (v : Nat) (h : v < 8) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) :
    muxPointF (v : F) pk rx ry pre params = muxPoint v pk rx ry pre params := sorry

lemma EcdsaLoopConstraintsF_cast_eq
    (bi : List Nat) (h : ∀ v ∈ bi, v < 8) (acc : ProjectivePoint F) (is_first : Bool)
    (wx wy wz : List F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) :
    EcdsaLoopConstraintsF acc is_first (bi.map (fun (x : Nat) => (x : F))) wx wy wz pk rx ry pre params ↔
    EcdsaLoopConstraints acc is_first bi wx wy wz pk rx ry pre params := sorry

lemma ecdsaLoopResultF_cast_eq
    (bi : List Nat) (h : ∀ v ∈ bi, v < 8) (acc : ProjectivePoint F) (is_first : Bool)
    (wx wy wz : List F) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) :
    ecdsaLoopResultF acc is_first (bi.map (fun (x : Nat) => (x : F))) wx wy wz pk rx ry pre params =
    ecdsaLoopResult acc is_first bi wx wy wz pk rx ry pre params := sorry

lemma cast_val3_eq
    (bi : List F) (h : ∀ v ∈ bi, v = 0 ∨ v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7) :
    (bi.map val3).map (fun (x : Nat) => (x : F)) = bi := sorry

lemma val3_bounds (v : F) (h : v = 0 ∨ v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7) :
    val3 v < 8 := sorry

lemma map_val3_bounds (bi : List F) (h : ∀ v ∈ bi, v = 0 ∨ v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7) :
    ∀ v ∈ bi.map val3, v < 8 := sorry

lemma map_cast_bounds (bi : List Nat) (h : ∀ v ∈ bi, v < 8) :
    ∀ v ∈ bi.map (fun (x : Nat) => (x : F)), v = 0 ∨ v = 1 ∨ v = 2 ∨ v = 3 ∨ v = 4 ∨ v = 5 ∨ v = 6 ∨ v = 7 := sorry

end ECDSA
