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

import ECDSA.ECBridge
import PkCircuit
import ECDSA.EcdsaSpec
import ECDSA.EcdsaCircuit

set_option linter.unusedVariables false
set_option linter.unusedSimpArgs false
set_option linter.unusedSectionVars false

/-!
# ECDSA Verification: Core Algebraic Bridging Lemmas

This file contains the mathematical library bridging the ZK circuit model
(defined in `ecdsa_circuit.lean`) and the standard ECDSA specification
(defined in `ecdsa_spec.lean`).

It contains the foundational algebraic equivalence proofs showing that the
circuit's multiplexed loop execution corresponds to the standard elliptic curve
scalar multiplications and additions.

## Section Overview

### Section 1: Generic Helper Lemmas
Provides basic utility lemmas used across both soundness and completeness proofs,
including list projection and zip properties for witness structures, and bit
reconstruction properties mapping bit-lists to natural numbers.

### Section 2: Completeness Proof Lemmas
Establishes the algebraic equivalence required for the completeness proof
(`ecdsa_complete.lean`), demonstrating that a valid signature can be mapped
to a valid circuit execution. This includes the correctness of the 3-bit point
multiplexer and inductive proofs showing the loop accumulator matches the
expected linear combination $e \cdot G + r \cdot PK + s \cdot R$.

### Section 3: Soundness Proof Lemmas
Establishes the algebraic equivalence required for the soundness proof
(`ecdsa_sound.lean`), proving that if the circuit accepts, the standard
verification equations must hold. This includes curve membership closure
under loop execution and the primary algebraic bridging theorem
(`ecdsa_algebraic_equivalence`).

-/

section ECDSA

variable {F : Type} [Field F] [NeZero (2 : F)] [NeZero (3 : F)]

/-!
# SECTION 1: Generic Helper Lemmas

This section contains generic helper lemmas used throughout the file,
including zip/projection properties, bit reconstruction, witness existence,
and modular arithmetic identities.
-/

/--
  Bridges the recursive `EcdsaLoopConstraints` check to the pure iterative
  `ecdsaPureLoopResultGeneral` function. It proves that if the intermediate
  witness values satisfy the recursive circuit relation, then the recursive
  `ecdsaLoopResult` evaluates to the same point as the foldl-based
  `ecdsaPureLoopResultGeneral`.
-/
theorem ecdsaLoopResult_eq_ecdsaPureLoopResult (acc : ProjectivePoint F) (is_first : Bool) (bi : List Nat) (wX wY wZ : List F)
    (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    (h : EcdsaLoopConstraints acc is_first bi wX wY wZ pk rx ry pre params) :
    ecdsaLoopResult acc is_first bi wX wY wZ pk rx ry pre params =
    let (finalAcc, _) := bi.foldl (fun state v => ecdsaLoopStepExact state v pk rx ry pre params) (acc, is_first)
    finalAcc := by
  induction bi generalizing acc is_first wX wY wZ with
  | nil =>
      cases wX <;> cases wY <;> cases wZ <;> rfl
  | cons v vs ih =>
    cases vs with
    | nil =>
        cases wX
        · cases wY
          · cases wZ
            · rfl
            · exact False.elim h
          · exact False.elim h
        · exact False.elim h
    | cons v_next vs_tail =>
        cases wX
        · exact False.elim h
        · case cons wx wxs =>
            cases wY
            · exact False.elim h
            · case cons wy wys =>
                cases wZ
                · exact False.elim h
                · case cons wz wzs =>
                    rcases h with ⟨h_next_x, h_next_y, h_next_z, h_tail⟩
                    have ih_app := ih { X := wx, Y := wy, Z := wz } false wxs wys wzs h_tail
                    have h_nextAcc_eq : ecdsaLoopStepExact (acc, is_first) v pk rx ry pre params = ({ X := wx, Y := wy, Z := wz }, false) := by
                      dsimp [ecdsaLoopStepExact]
                      congr 1
                      apply ProjectivePoint.ext
                      · exact h_next_x
                      · exact h_next_y
                      · exact h_next_z
                    dsimp [ecdsaLoopResult]
                    rw [ih_app]
                    dsimp
                    rw [h_nextAcc_eq]

/--
  Constructs the list of combined 3-bit multiplexer indices from the individual
  natural numbers representing signature/message parts `e`, `r`, and `s_nat`.
-/
def constructBi (e r s_nat : Nat) (k : Nat) : List Nat :=
  let bits_e := padBits (natToBits e) k
  let bits_r := padBits (natToBits r) k
  let bits_s := padBits (natToBits s_nat) k
  let zipped := List.zip (List.zip bits_e bits_r) bits_s
  zipped.map (fun ((be, br), bs) => (if be then 1 else 0) + (if br then 2 else 0) + (if bs then 4 else 0))

/--
  Proves that the length of the constructed multiplexer index list `bi` is
  exactly `k`.
-/
lemma constructBi_length (e r s_nat : Nat) (k : Nat) (he : e < 2^k) (hr : r < 2^k) (hs : s_nat < 2^k) :
    (constructBi e r s_nat k).length = k := by
  unfold constructBi
  dsimp
  have h_len_e : (padBits (natToBits e) k).length = k := by
    apply padBits_length
    exact natToBits_length e k he
  have h_len_r : (padBits (natToBits r) k).length = k := by
    apply padBits_length
    exact natToBits_length r k hr
  have h_len_s : (padBits (natToBits s_nat) k).length = k := by
    apply padBits_length
    exact natToBits_length s_nat k hs
  rw [List.length_map]
  rw [List.length_zip]
  rw [List.length_zip]
  rw [h_len_e, h_len_r, h_len_s]
  simp

/-- Combines three boolean bits into a single multiplexer selection index (0 to 7). -/
def combVal (be br bs : Bool) : Nat :=
  (if be then 1 else 0) + (if br then 2 else 0) + (if bs then 4 else 0)

lemma combVal_E (be br bs : Bool) : muxE (combVal be br bs) = if be then 1 else 0 := by
  cases be <;> cases br <;> cases bs <;> decide

lemma combVal_R (be br bs : Bool) : muxR (combVal be br bs) = if br then 1 else 0 := by
  cases be <;> cases br <;> cases bs <;> decide

lemma combVal_S (be br bs : Bool) : muxS (combVal be br bs) = if bs then 1 else 0 := by
  cases be <;> cases br <;> cases bs <;> decide

lemma foldl_zip_projection_E (as bs cs : List Bool) (acc : Nat) :
    as.length = bs.length → bs.length = cs.length →
    List.foldl (fun acc ((be, br), bs) => acc * 2 + muxE (combVal be br bs)) acc (List.zip (List.zip as bs) cs) =
    List.foldl (fun acc be => acc * 2 + if be then 1 else 0) acc as := by
  induction as generalizing bs cs acc with
  | nil =>
      intro h1 h2
      have h_bs : bs = [] := List.eq_nil_of_length_eq_zero h1.symm
      rw [h_bs] at h2
      have h_cs : cs = [] := List.eq_nil_of_length_eq_zero h2.symm
      rw [h_bs, h_cs]
      rfl
  | cons a as ih =>
      intro h1 h2
      cases bs with
      | nil => simp at h1
      | cons b bs =>
          cases cs with
          | nil => simp at h2
          | cons c cs =>
              dsimp [List.zip, List.foldl]
              rw [combVal_E]
              simp at h1 h2
              apply ih
              · exact h1
              · exact h2

lemma foldl_zip_projection_R (as bs cs : List Bool) (acc : Nat) :
    as.length = bs.length → bs.length = cs.length →
    List.foldl (fun acc ((be, br), bs) => acc * 2 + muxR (combVal be br bs)) acc (List.zip (List.zip as bs) cs) =
    List.foldl (fun acc br => acc * 2 + if br then 1 else 0) acc bs := by
  induction as generalizing bs cs acc with
  | nil =>
      intro h1 h2
      have h_bs : bs = [] := List.eq_nil_of_length_eq_zero h1.symm
      rw [h_bs] at h2
      have h_cs : cs = [] := List.eq_nil_of_length_eq_zero h2.symm
      rw [h_bs, h_cs]
      rfl
  | cons a as ih =>
      intro h1 h2
      cases bs with
      | nil => simp at h1
      | cons b bs =>
          cases cs with
          | nil => simp at h2
          | cons c cs =>
              dsimp [List.zip, List.foldl]
              rw [combVal_R]
              simp at h1 h2
              apply ih
              · exact h1
              · exact h2

lemma foldl_zip_projection_S (as bs cs : List Bool) (acc : Nat) :
    as.length = bs.length → bs.length = cs.length →
    List.foldl (fun acc ((be, br), bs) => acc * 2 + muxS (combVal be br bs)) acc (List.zip (List.zip as bs) cs) =
    List.foldl (fun acc bs => acc * 2 + if bs then 1 else 0) acc cs := by
  induction as generalizing bs cs acc with
  | nil =>
      intro h1 h2
      have h_bs : bs = [] := List.eq_nil_of_length_eq_zero h1.symm
      rw [h_bs] at h2
      have h_cs : cs = [] := List.eq_nil_of_length_eq_zero h2.symm
      rw [h_bs, h_cs]
      rfl
  | cons a as ih =>
      intro h1 h2
      cases bs with
      | nil => simp at h1
      | cons b bs =>
          cases cs with
          | nil => simp at h2
          | cons c cs =>
              dsimp [List.zip, List.foldl]
              rw [combVal_S]
              simp at h1 h2
              apply ih
              · exact h1
              · exact h2

lemma foldl_replicate_false (m : Nat) (f : Nat → Bool → Nat) (h_zero : f 0 false = 0) :
    List.foldl f 0 (List.replicate m false) = 0 := by
  induction m with
  | zero => rfl
  | succ m' ih =>
      dsimp [List.replicate]
      rw [h_zero]
      exact ih

lemma natToBitsAux_length_eq (n : Nat) (acc : List Bool) :
    (natToBitsAux n acc).length = (natToBitsAux n []).length + acc.length := by
  induction n using Nat.strong_induction_on generalizing acc
  rename_i n ih
  by_cases hn : n = 0
  · unfold natToBitsAux; simp [hn]
  · unfold natToBitsAux
    have hn_ne : ¬(n = 0) := hn
    rw [dif_neg hn_ne, dif_neg hn_ne]
    change (natToBitsAux (n / 2) ((n % 2 = 1) :: acc)).length = (natToBitsAux (n / 2) [n % 2 = 1]).length + acc.length
    have ih_call := ih (n / 2) (Nat.div_lt_self (Nat.pos_of_ne_zero hn_ne) (by decide)) ((n % 2 = 1) :: acc)
    rw [ih_call]
    have ih_call_empty := ih (n / 2) (Nat.div_lt_self (Nat.pos_of_ne_zero hn_ne) (by decide)) [n % 2 = 1]
    rw [ih_call_empty]
    dsimp
    omega

lemma foldl_natToBitsAux (n : Nat) (acc : List Bool) (val : Nat) :
    List.foldl (fun acc_f b => acc_f * 2 + if b then 1 else 0) val (natToBitsAux n acc) =
    List.foldl (fun acc_f b => acc_f * 2 + if b then 1 else 0) (val * 2^(natToBitsAux n []).length + n) acc := by
  induction n using Nat.strong_induction_on generalizing acc val
  rename_i n ih
  by_cases hn : n = 0
  · unfold natToBitsAux
    simp [hn]
  · unfold natToBitsAux
    have hn_ne : ¬(n = 0) := hn
    rw [dif_neg hn_ne, dif_neg hn_ne]
    change List.foldl (fun acc_f b => acc_f * 2 + if b then 1 else 0) val (natToBitsAux (n / 2) (decide (n % 2 = 1) :: acc)) =
           List.foldl (fun acc_f b => acc_f * 2 + if b then 1 else 0) (val * 2^(natToBitsAux (n / 2) [decide (n % 2 = 1)]).length + n) acc
    have ih_call := ih (n / 2) (Nat.div_lt_self (Nat.pos_of_ne_zero hn_ne) (by decide)) ((n % 2 = 1) :: acc) val
    rw [ih_call]
    rw [List.foldl_cons]
    have h_len_eq := natToBitsAux_length_eq (n / 2) [n % 2 = 1]
    have h_arith : (val * 2^(natToBitsAux (n / 2) []).length + n / 2) * 2 + (if decide (n % 2 = 1) then 1 else 0) = val * 2^((natToBitsAux (n / 2) []).length + 1) + n := by
      have h_mod : (if decide (n % 2 = 1) then 1 else 0) = n % 2 := by
        cases h_dec : decide (n % 2 = 1)
        · have h_mod_val : n % 2 = 0 := by
            have h_ne : n % 2 ≠ 1 := of_decide_eq_false h_dec
            have h_lt : n % 2 < 2 := Nat.mod_lt n (by decide)
            omega
          rw [h_mod_val]
          rfl
        · have h_mod_val : n % 2 = 1 := of_decide_eq_true h_dec
          rw [h_mod_val]
          rfl
      rw [h_mod]
      have h_pow_mul : val * 2^((natToBitsAux (n / 2) []).length + 1) = val * 2^(natToBitsAux (n / 2) []).length * 2 := by ring
      rw [h_pow_mul]
      rw [add_mul]
      omega
    rw [h_arith]
    rw [h_len_eq]
    rfl

lemma reconstruct_natToBits (n : Nat) (k : Nat) (h : n < 2^k) :
    List.foldl (fun acc b => acc * 2 + if b then 1 else 0) 0 (padBits (natToBits n) k) = n := by
  have h_len := foldl_replicate_false (k - (natToBits n).length) (fun acc b => acc * 2 + if b then 1 else 0) (by rfl)
  unfold padBits List.leftpad
  rw [List.foldl_append, h_len]
  rw [natToBits_eq_natToBitsAux]
  have h_aux := foldl_natToBitsAux n [] 0
  dsimp at h_aux
  rw [h_aux]
  simp

/-- Helper to calculate the length of left-padded bits of a natural number. -/
lemma padBits_natToBits_length (n k : Nat) (h : n < 2^k) : (padBits (natToBits n) k).length = k :=
  padBits_length (natToBits n) k (natToBits_length n k h)

/--
  Reconstruction property for the exponent component `e` of the multiplexed
  selection index. Shows that extracting the `e` component bits from the
  constructed index `bi` and reconstructing it as a natural number yields
  exactly the original `e`.
-/
lemma natE_constructBi (e r s_nat : Nat) {k : Nat} (he : e < 2^k) (hr : r < 2^k) (hs : s_nat < 2^k) :
    natE (constructBi e r s_nat k) = e := by
  unfold natE natReconstruct constructBi
  dsimp
  rw [List.foldl_map]
  have h_len_e : (padBits (natToBits e) k).length = k := by
    apply padBits_length
    exact natToBits_length e k he
  have h_len_r : (padBits (natToBits r) k).length = k := by
    apply padBits_length
    exact natToBits_length r k hr
  have h_len_s : (padBits (natToBits s_nat) k).length = k := by
    apply padBits_length
    exact natToBits_length s_nat k hs
  have h_len_er : (padBits (natToBits e) k).length = (padBits (natToBits r) k).length := by
    rw [h_len_e, h_len_r]
  have h_len_rs : (padBits (natToBits r) k).length = (padBits (natToBits s_nat) k).length := by
    rw [h_len_r, h_len_s]
  have h_proj := foldl_zip_projection_E (padBits (natToBits e) k) (padBits (natToBits r) k) (padBits (natToBits s_nat) k) 0 h_len_er h_len_rs
  unfold combVal at h_proj
  rw [h_proj]
  exact reconstruct_natToBits e k he

/--
  Reconstruction property for the signature component `r` of the multiplexed
  selection index. Shows that extracting the `r` component bits from the
  constructed index `bi` and reconstructing it as a natural number yields
  exactly the original `r`.
-/
lemma natR_constructBi (e r s_nat : Nat) {k : Nat} (he : e < 2^k) (hr : r < 2^k) (hs : s_nat < 2^k) :
    natR (constructBi e r s_nat k) = r := by
  unfold natR natReconstruct constructBi
  dsimp
  rw [List.foldl_map]
  have h_len_e : (padBits (natToBits e) k).length = k := by
    apply padBits_length
    exact natToBits_length e k he
  have h_len_r : (padBits (natToBits r) k).length = k := by
    apply padBits_length
    exact natToBits_length r k hr
  have h_len_s : (padBits (natToBits s_nat) k).length = k := by
    apply padBits_length
    exact natToBits_length s_nat k hs
  have h_len_er : (padBits (natToBits e) k).length = (padBits (natToBits r) k).length := by
    rw [h_len_e, h_len_r]
  have h_len_rs : (padBits (natToBits r) k).length = (padBits (natToBits s_nat) k).length := by
    rw [h_len_r, h_len_s]
  have h_proj := foldl_zip_projection_R (padBits (natToBits e) k) (padBits (natToBits r) k) (padBits (natToBits s_nat) k) 0 h_len_er h_len_rs
  unfold combVal at h_proj
  rw [h_proj]
  exact reconstruct_natToBits r k hr

/--
  Reconstruction property for the signature component `s` of the multiplexed
  selection index. Shows that extracting the `s` component bits from the
  constructed index `bi` and reconstructing it as a natural number yields
  exactly the original `s`.
-/
lemma natS_constructBi (e r s_nat : Nat) {k : Nat} (he : e < 2^k) (hr : r < 2^k) (hs : s_nat < 2^k) :
    natS (constructBi e r s_nat k) = s_nat := by
  unfold natS natReconstruct constructBi
  dsimp
  rw [List.foldl_map]
  have h_len_e : (padBits (natToBits e) k).length = k := by
    apply padBits_length
    exact natToBits_length e k he
  have h_len_r : (padBits (natToBits r) k).length = k := by
    apply padBits_length
    exact natToBits_length r k hr
  have h_len_s : (padBits (natToBits s_nat) k).length = k := by
    apply padBits_length
    exact natToBits_length s_nat k hs
  have h_len_er : (padBits (natToBits e) k).length = (padBits (natToBits r) k).length := by
    rw [h_len_e, h_len_r]
  have h_len_rs : (padBits (natToBits r) k).length = (padBits (natToBits s_nat) k).length := by
    rw [h_len_r, h_len_s]
  have h_proj := foldl_zip_projection_S (padBits (natToBits e) k) (padBits (natToBits r) k) (padBits (natToBits s_nat) k) 0 h_len_er h_len_rs
  unfold combVal at h_proj
  rw [h_proj]
  exact reconstruct_natToBits s_nat k hs

/--
  Constructs the ZK witness bit indices `bi` from bounds and shows that they
  correctly reconstruct back to the components `e`, `r`, and `s_nat`.
-/
lemma exists_bi (e r s_nat : Nat) {k : Nat} (he : e < 2^k) (hr : r < 2^k) (hs : s_nat < 2^k) : ∃ (bi : List Nat),
    bi.length = k ∧
    (∀ v ∈ bi, v < 8) ∧
    natE bi = e ∧
    natR bi = r ∧
    natS bi = s_nat := by
  let bi := constructBi e r s_nat k
  use bi
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · exact constructBi_length e r s_nat k he hr hs
  · intro v hv
    dsimp only [bi] at hv
    unfold constructBi at hv
    rcases List.mem_map.mp hv with ⟨⟨⟨be, br⟩, bs⟩, h_in, rfl⟩
    dsimp
    cases be <;> cases br <;> cases bs <;> decide
  · exact natE_constructBi e r s_nat he hr hs
  · exact natR_constructBi e r s_nat he hr hs
  · exact natS_constructBi e r s_nat he hr hs

/--
  Inductive proof demonstrating the existence of intermediate loop accumulators
  `int_x`, `int_y`, `int_z` satisfying the recursive circuit step equations.
-/
lemma exists_loop_witness_general (bi : List Nat) (acc : ProjectivePoint F) (is_first : Bool)
    (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) :
    ∃ (int_x int_y int_z : List F),
    int_x.length = bi.length - 1 ∧
    int_y.length = bi.length - 1 ∧
    int_z.length = bi.length - 1 ∧
    EcdsaLoopConstraints acc is_first bi int_x int_y int_z pk rx ry pre params := by
  induction bi generalizing acc is_first with
  | nil =>
      use [], [], []
      refine ⟨rfl, rfl, rfl, True.intro⟩
  | cons v vs ih =>
      cases vs with
      | nil =>
          use [], [], []
          refine ⟨rfl, rfl, rfl, True.intro⟩
      | cons v_next vs_tail =>
          let tx := muxPoint v pk rx ry pre params
          let doubled := if is_first then acc else doubleE acc params
          let nextAcc := addE doubled tx params
          have ⟨wxs, wys, wzs, hlen_x, hlen_y, hlen_z, h_constr⟩ :=
            ih (acc := nextAcc) (is_first := false)
          use nextAcc.X :: wxs, nextAcc.Y :: wys, nextAcc.Z :: wzs
          dsimp [EcdsaLoopConstraints]
          refine ⟨?_, ?_, ?_, ⟨rfl, rfl, rfl, h_constr⟩⟩
          · simp [hlen_x]
          · simp [hlen_y]
          · simp [hlen_z]

/--
  Witness existence specialized for starting the loop at the point at infinity
  and running for `params.kBits` iterations.
-/
lemma exists_loop_witness (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    (h_bi_len : bi.length = params.kBits) :
    ∃ (int_x int_y int_z : List F),
    int_x.length = params.kBits - 1 ∧
    int_y.length = params.kBits - 1 ∧
    int_z.length = params.kBits - 1 ∧
    EcdsaLoopConstraints infinityPoint true bi int_x int_y int_z pk rx ry pre params := by
  have ⟨int_x, int_y, int_z, h_len_x, h_len_y, h_len_z, h_loop⟩ :=
    exists_loop_witness_general bi infinityPoint true pk rx ry pre params
  use int_x, int_y, int_z
  rw [h_bi_len] at h_len_x h_len_y h_len_z
  exact ⟨h_len_x, h_len_y, h_len_z, h_loop⟩

/--
  Proves that under non-exceptional curve addition conditions, the precomputed
  table elements (containing representations of G+PK, R+G, R+PK, G+R+PK)
  can be successfully instantiated.
-/
lemma exists_pre_computation (pk : AffinePoint F) (rx ry : F) (params : CurveParameters F)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : let RPK := addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params;
      (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := RPK.X * RPK.Z⁻¹, Y := RPK.Y * RPK.Z⁻¹ : AffinePoint F }).toProjective params).Z ≠ 0) :
    ∃ (pre : List F),
    pre.length = 8 ∧
    ValidPreComputationExact pk rx ry pre params := by
  let GPK := addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params
  let GR := addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params
  let RPK := addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params
  let GRPK := addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := RPK.X * RPK.Z⁻¹, Y := RPK.Y * RPK.Z⁻¹ : AffinePoint F }).toProjective params
  let pre := [
    GPK.X * GPK.Z⁻¹, GPK.Y * GPK.Z⁻¹,
    GR.X * GR.Z⁻¹, GR.Y * GR.Z⁻¹,
    RPK.X * RPK.Z⁻¹, RPK.Y * RPK.Z⁻¹,
    GRPK.X * GRPK.Z⁻¹, GRPK.Y * GRPK.Z⁻¹
  ]
  use pre
  constructor
  · rfl
  · unfold ValidPreComputationExact IsPointEquality
    refine ⟨rfl, ?_⟩
    dsimp [pre, List.getD, getElem?, List.get?Internal, Option.getD]
    have h_GPK_Z_copy := h_GPK_Z
    have h_GPK_inv : GPK.Z * GPK.Z⁻¹ = 1 := mul_inv_cancel₀ h_GPK_Z_copy
    have h_GR_Z_copy := h_GR_Z
    have h_GR_inv : GR.Z * GR.Z⁻¹ = 1 := mul_inv_cancel₀ h_GR_Z_copy
    have h_RPK_Z_copy := h_RPK_Z
    have h_RPK_inv : RPK.Z * RPK.Z⁻¹ = 1 := mul_inv_cancel₀ h_RPK_Z_copy
    have h_GRPK_Z_copy := h_GRPK_Z
    have h_GRPK_inv : GRPK.Z * GRPK.Z⁻¹ = 1 := mul_inv_cancel₀ h_GRPK_Z_copy
    refine ⟨⟨?_, ?_⟩, ⟨?_, ?_⟩, ⟨?_, ?_⟩, ⟨?_, ?_⟩⟩
    · linear_combination - GPK.X * h_GPK_inv
    · linear_combination - GPK.Y * h_GPK_inv
    · linear_combination - GR.X * h_GR_inv
    · linear_combination - GR.Y * h_GR_inv
    · linear_combination - RPK.X * h_RPK_inv
    · linear_combination - RPK.Y * h_RPK_inv
    · linear_combination - GRPK.X * h_GRPK_inv
    · linear_combination - GRPK.Y * h_GRPK_inv

/--
  Proves that if a valid projective curve point satisfies `IsPointEquality`
  (meaning its X and Y coordinates map to the given `x` and `y` when dividing
  by `Z`), its Z-coordinate must be non-zero, since `(0, 0, 0)` is not a valid
  curve point.
-/
lemma z_ne_zero_of_point_equality_and_on_curve (p : ProjectivePoint F) (x y : F) (params : CurveParameters F)
    (h_on : p.IsOnCurve params) (h_eq : IsPointEquality p x y) : p.Z ≠ 0 := by
  intro hz
  have hy : p.Y = 0 := by rw [h_eq.2, hz, zero_mul]
  exact ProjectivePoint.Y_ne_zero_of_Z_eq_zero p params h_on hz hy

/--
  Proves that if a projective point satisfies `IsPointEquality` for `x` and `y`,
  then it is projectively equivalent to `{ X := x, Y := y, Z := 1 }`.
-/
lemma projective_equiv_of_point_equality (p : ProjectivePoint F) (x y : F)
    (hz : p.Z ≠ 0) (h_eq : IsPointEquality p x y) :
    ProjectiveEquiv { X := x, Y := y, Z := 1 } p := by
  use p.Z⁻¹
  refine ⟨inv_ne_zero hz, ?_⟩
  ext
  · dsimp; rw [h_eq.1, ← mul_assoc, inv_mul_cancel₀ hz, one_mul]
  · dsimp; rw [h_eq.2, ← mul_assoc, inv_mul_cancel₀ hz, one_mul]
  · dsimp; exact (inv_mul_cancel₀ hz).symm

/--
  Proves that if a valid projective point `p` satisfies `IsPointEquality`
  with `x` and `y`, then the normalized affine representation 
  `{ X := x, Y := y, Z := 1 }` is also on the curve.
-/
lemma projective_point_on_curve_of_point_equality (p : ProjectivePoint F) (x y : F) (params : CurveParameters F)
    (h_on : p.IsOnCurve params) (hz : p.Z ≠ 0) (h_eq : IsPointEquality p x y) :
    ProjectivePoint.IsOnCurve { X := x, Y := y, Z := 1 } params := by
  exact ProjectiveEquiv.isOnCurve params (projective_equiv_of_point_equality p x y hz h_eq) h_on

/--
  A modular arithmetic identity proving the existence of a modular inverse
  `s_inv` such that `(s * s_inv) % order = 1` for any `0 < s < order` where
  `order` is prime.
-/
lemma exists_mod_inv_of_prime_of_lt_of_pos {order : Nat} [h_prime : Fact (Nat.Prime order)] {s : Nat} (h_lt : s < order) (h_pos : s > 0) :
    ∃ (s_inv : Nat), (s * s_inv) % order = 1 := by
  have h_order_gt_1 : order > 1 := h_prime.out.two_le
  let s_zmod : ZMod order := (s : ZMod order)
  have h_s_ne_zero : s_zmod ≠ 0 := by
    intro hc
    have h_val := congr_arg ZMod.val hc
    rw [ZMod.val_natCast, ZMod.val_zero] at h_val
    rw [Nat.mod_eq_of_lt h_lt] at h_val
    omega
  have h_mul := mul_inv_cancel₀ h_s_ne_zero
  have h_val_mul := congr_arg ZMod.val h_mul
  rw [ZMod.val_mul, ZMod.val_one] at h_val_mul
  rw [ZMod.val_natCast, Nat.mod_eq_of_lt h_lt] at h_val_mul
  use s_zmod⁻¹.val

/--
  Helper identity for exponent modular arithmetic properties, facilitating the algebraic
  congruence checks needed for group verification equations.
-/
lemma ecdsa_exponent_modulo_identity (e_nat r_nat s_nat : Nat) (order : Nat) (s_inv : Nat)
    (hs_inv : ((order - s_nat) * s_inv) % order = 1) (he_lt : e_nat < order) :
    (s_nat * ((e_nat * s_inv) % order)) % order = (order - e_nat) % order := by
  by_cases h_order : order <= 1
  · by_cases ho0 : order = 0
    · subst ho0; omega
    · have ho1 : order = 1 := by omega
      subst ho1; omega
  · have h_order_gt : order > 1 := by omega
    have h_order_pos : order > 0 := by omega
    have h_snat_lt : s_nat < order := by
      by_contra h_ge
      have h_sub_zero : order - s_nat = 0 := by omega
      rw [h_sub_zero] at hs_inv
      simp at hs_inv
    have h_eq_zmod : ( (s_nat * ((e_nat * s_inv) % order) : Nat) : ZMod order ) = ( (order - e_nat : Nat) : ZMod order ) := by
      rw [Nat.cast_mul]
      rw [ZMod.natCast_mod]
      rw [Nat.cast_mul]
      rw [Nat.cast_sub (by omega)]
      simp
      have h_hs_inv_zmod : ((order - s_nat : Nat) : ZMod order) * (s_inv : ZMod order) = 1 := by
        have h_cast := congr_arg (fun (x : Nat) => (x : ZMod order)) hs_inv
        simp only [ZMod.natCast_mod] at h_cast
        rw [Nat.cast_mul] at h_cast
        rw [Nat.cast_one] at h_cast
        exact h_cast
      have h_sub_cast : ((order - s_nat : Nat) : ZMod order) = -s_nat := by
        rw [Nat.cast_sub (by omega)]
        simp
      rw [h_sub_cast] at h_hs_inv_zmod
      have h_mul_neg : (s_nat : ZMod order) * s_inv = -1 := by
        linear_combination -h_hs_inv_zmod
      have h_lhs_comm : (s_nat : ZMod order) * (e_nat * s_inv) = e_nat * (s_nat * s_inv) := by ring
      rw [h_lhs_comm, h_mul_neg]
      ring
    have h_val_eq := congr_arg ZMod.val h_eq_zmod
    rw [ZMod.val_natCast, ZMod.val_natCast] at h_val_eq
    exact h_val_eq


/-!
# SECTION 2: Completeness Proof Lemmas

This section contains key lemmas that bridge standard elliptic curve equations
to the circuit's multiplexed execution paths, demonstrating the ZK verification
completeness.
-/

/--
  Algebraic correctness of the 3-bit multiplexer. Proves that the circuit's
  multiplexer select point (`muxPoint v`) is projectively equivalent to the
  mathematically correct combined addition `e * G + r * PK + s * R`.
-/
lemma muxPoint_correctness (v : Nat) (hv : v < 8) (pk : AffinePoint F)
    (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
  (h_gy : params.gy ≠ 0)
  (h_pky : pk.Y ≠ 0)
  (h_ry : ry ≠ 0)
  (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
  (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
  (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
  let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj := pk.toProjective
  let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  let be := decide (v % 2 = 1)
  let br := decide ((v / 2) % 2 = 1)
  let bs := decide ((v / 4) % 2 = 1)
  let e_G := bsmul [be] G_proj params
  let r_PK := bsmul [br] PK_proj params
  let s_R := bsmul [bs] R_proj params
  ProjectiveEquiv (muxPoint v pk rx ry pre params) (addE (addE e_G r_PK params) s_R params) := by
  let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj := pk.toProjective
  let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  rcases v with _ | v1
  · -- case v = 0
    unfold muxPoint
    dsimp
    simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
    exact ProjectiveEquiv.refl (F := F) _
  · rcases v1 with _ | v2
    · -- case v = 1
      unfold muxPoint
      dsimp
      simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
      let e_G_val := addE infinityPoint G_proj params
      have h1 : ProjectiveEquiv e_G_val G_proj := addE_infinity_left G_proj params h_gy
      have he_y : e_G_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero h1 h_gy
      have h2 : ProjectiveEquiv (addE e_G_val infinityPoint params) e_G_val := by rw [addE_comm]; exact addE_infinity_left e_G_val params he_y
      let e_G_2 := addE e_G_val infinityPoint params
      have he_2_y : e_G_2.Y ≠ 0 := ProjectiveEquiv.y_ne_zero h2 he_y
      have h3 : ProjectiveEquiv (addE e_G_2 infinityPoint params) e_G_2 := by rw [addE_comm]; exact addE_infinity_left e_G_2 params he_2_y
      have h_trans1 : ProjectiveEquiv e_G_2 G_proj := ProjectiveEquiv.trans h2 h1
      have h_trans2 : ProjectiveEquiv (addE e_G_2 infinityPoint params) G_proj := ProjectiveEquiv.trans h3 h_trans1
      exact ProjectiveEquiv.symm h_trans2
    · rcases v2 with _ | v3
      · -- case v = 2
        unfold muxPoint
        dsimp
        simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
        let r_PK_val := addE infinityPoint PK_proj params
        have h1 : ProjectiveEquiv r_PK_val PK_proj := addE_infinity_left PK_proj params h_pky
        have hrpk_y : r_PK_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero h1 h_pky
        have h2 : ProjectiveEquiv (addE infinityPoint r_PK_val params) r_PK_val := addE_infinity_left r_PK_val params hrpk_y
        let acc_val := addE infinityPoint r_PK_val params
        have hacc_y : acc_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero h2 hrpk_y
        have h3 : ProjectiveEquiv (addE acc_val infinityPoint params) acc_val := by rw [addE_comm]; exact addE_infinity_left acc_val params hacc_y
        have h_trans1 : ProjectiveEquiv acc_val PK_proj := ProjectiveEquiv.trans h2 h1
        have h_trans2 : ProjectiveEquiv (addE acc_val infinityPoint params) PK_proj := ProjectiveEquiv.trans h3 h_trans1
        exact ProjectiveEquiv.symm h_trans2
      · rcases v3 with _ | v4
        · -- case v = 3 (Precomputed G + PK)
          unfold muxPoint
          dsimp
          simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
          let e_G_val := addE infinityPoint G_proj params
          let r_PK_val := addE infinityPoint PK_proj params
          let GPK := addE G_proj PK_proj params
          let GPK_pre := { X := pre.getD 0 0, Y := pre.getD 1 0, Z := 1 : ProjectivePoint F }
          have h_gpk_equiv : ProjectiveEquiv GPK_pre GPK := by
            use GPK.Z⁻¹
            have h_inv_ne : GPK.Z⁻¹ ≠ 0 := inv_ne_zero h_GPK_Z
            constructor
            · exact h_inv_ne
            · have h_inv_mul : GPK.Z⁻¹ * GPK.Z = 1 := inv_mul_cancel₀ h_GPK_Z
              rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
              rw [smul_projective]
              dsimp only [GPK] at *
              unfold IsPointEquality at h_gpk
              ext
              · rw [h_gpk.1]
                rw [←mul_assoc, h_inv_mul, one_mul]
              · rw [h_gpk.2]
                rw [←mul_assoc, h_inv_mul, one_mul]
              · exact h_inv_mul.symm
          have h_eg_equiv : ProjectiveEquiv G_proj e_G_val := ProjectiveEquiv.symm (addE_infinity_left G_proj params h_gy)
          have h_rpk_equiv : ProjectiveEquiv PK_proj r_PK_val := ProjectiveEquiv.symm (addE_infinity_left PK_proj params h_pky)
          have h_gpk_egr : ProjectiveEquiv GPK (addE e_G_val r_PK_val params) := h_eg_equiv.addE params h_rpk_equiv
          let mid_val := addE e_G_val r_PK_val params
          have h_e_G_on : ProjectivePoint.IsOnCurve e_G_val params :=
            addE_on_curve infinityPoint G_proj params (infinity_on_curve params) h_G_on
          have h_r_PK_on : ProjectivePoint.IsOnCurve r_PK_val params :=
            addE_on_curve infinityPoint PK_proj params (infinity_on_curve params) h_PK_on
          have h_mid_on : ProjectivePoint.IsOnCurve mid_val params :=
            addE_on_curve e_G_val r_PK_val params h_e_G_on h_r_PK_on
          have h_mid_y : mid_val.Y ≠ 0 := h_mid_on.Y_ne_zero
          have h_mid_equiv : ProjectiveEquiv mid_val (addE mid_val infinityPoint params) := ProjectiveEquiv.symm (by rw [addE_comm]; exact addE_infinity_left mid_val params h_mid_y)
          have h_trans1 : ProjectiveEquiv GPK_pre (addE e_G_val r_PK_val params) := ProjectiveEquiv.trans h_gpk_equiv h_gpk_egr
          exact ProjectiveEquiv.trans h_trans1 h_mid_equiv
        · rcases v4 with _ | v5
          · -- case v = 4
            unfold muxPoint
            dsimp
            simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
            let s_R_val := addE infinityPoint R_proj params
            have h1 : ProjectiveEquiv s_R_val R_proj := addE_infinity_left R_proj params h_ry
            have hsr_y : s_R_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero h1 h_ry
            have h2 : ProjectiveEquiv (addE infinityPoint s_R_val params) s_R_val := addE_infinity_left s_R_val params hsr_y
            have h_trans : ProjectiveEquiv (addE infinityPoint s_R_val params) R_proj := ProjectiveEquiv.trans h2 h1
            exact ProjectiveEquiv.symm h_trans
          · rcases v5 with _ | v6
            · -- case v = 5 (Precomputed G + R)
              unfold muxPoint
              dsimp
              simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
              let e_G_val := addE infinityPoint G_proj params
              let s_R_val := addE infinityPoint R_proj params
              let GR := addE G_proj R_proj params
              let GR_pre := { X := pre.getD 2 0, Y := pre.getD 3 0, Z := 1 : ProjectivePoint F }
              have h_gr_equiv : ProjectiveEquiv GR_pre GR := by
                dsimp only [GR]
                rw [addE_comm G_proj R_proj params]
                use (addE R_proj G_proj params).Z⁻¹
                have h_inv_ne : (addE R_proj G_proj params).Z⁻¹ ≠ 0 := inv_ne_zero h_GR_Z
                constructor
                · exact h_inv_ne
                · have h_inv_mul : (addE R_proj G_proj params).Z⁻¹ * (addE R_proj G_proj params).Z = 1 := inv_mul_cancel₀ h_GR_Z
                  rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
                  unfold IsPointEquality at h_gr
                  rw [smul_projective]
                  ext
                  · rw [h_gr.1]
                    rw [←mul_assoc, h_inv_mul, one_mul]
                  · rw [h_gr.2]
                    rw [←mul_assoc, h_inv_mul, one_mul]
                  · exact h_inv_mul.symm
              have h_eg_equiv : ProjectiveEquiv G_proj e_G_val := ProjectiveEquiv.symm (addE_infinity_left G_proj params h_gy)
              have h_sr_equiv : ProjectiveEquiv R_proj s_R_val := ProjectiveEquiv.symm (addE_infinity_left R_proj params h_ry)
              have heg_y : e_G_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero (ProjectiveEquiv.symm h_eg_equiv) h_gy
              have h_eg_inf : ProjectiveEquiv (addE e_G_val infinityPoint params) e_G_val := by rw [addE_comm]; exact addE_infinity_left e_G_val params heg_y
              have h_eg_inf_g : ProjectiveEquiv (addE e_G_val infinityPoint params) G_proj := ProjectiveEquiv.trans h_eg_inf (addE_infinity_left G_proj params h_gy)
              have h_gr_equiv2 : ProjectiveEquiv (addE (addE e_G_val infinityPoint params) s_R_val params) (addE G_proj R_proj params) :=
                h_eg_inf_g.addE params (ProjectiveEquiv.symm h_sr_equiv)
              exact ProjectiveEquiv.trans h_gr_equiv (ProjectiveEquiv.symm h_gr_equiv2)
            · rcases v6 with _ | v7
              · -- case v = 6 (Precomputed R + PK)
                unfold muxPoint
                dsimp
                simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
                let r_PK_val := addE infinityPoint PK_proj params
                let s_R_val := addE infinityPoint R_proj params
                let RPK := addE R_proj PK_proj params
                let RPK_pre := ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective
                have h_rpk_equiv : ProjectiveEquiv RPK_pre RPK := by
                  use RPK.Z⁻¹
                  have h_inv_ne : RPK.Z⁻¹ ≠ 0 := inv_ne_zero h_RPK_Z
                  constructor
                  · exact h_inv_ne
                  · have h_inv_mul : RPK.Z⁻¹ * RPK.Z = 1 := inv_mul_cancel₀ h_RPK_Z
                    rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
                    dsimp only [RPK] at *
                    unfold IsPointEquality at h_rpk
                    rw [smul_projective]
                    ext
                    · rw [h_rpk.1]
                      rw [←mul_assoc, h_inv_mul, one_mul]
                    · rw [h_rpk.2]
                      rw [←mul_assoc, h_inv_mul, one_mul]
                    · exact h_inv_mul.symm
                have h_rpk_equiv2 : ProjectiveEquiv PK_proj r_PK_val := ProjectiveEquiv.symm (addE_infinity_left PK_proj params h_pky)
                have h_sr_equiv : ProjectiveEquiv R_proj s_R_val := ProjectiveEquiv.symm (addE_infinity_left R_proj params h_ry)
                have hrpk_y : r_PK_val.Y ≠ 0 := ProjectiveEquiv.y_ne_zero (ProjectiveEquiv.symm h_rpk_equiv2) h_pky
                have h_inf_rpk : ProjectiveEquiv (addE infinityPoint r_PK_val params) r_PK_val := addE_infinity_left r_PK_val params hrpk_y
                have h_inf_rpk_pk : ProjectiveEquiv (addE infinityPoint r_PK_val params) PK_proj := ProjectiveEquiv.trans h_inf_rpk (addE_infinity_left PK_proj params h_pky)
                have h_comm : ProjectiveEquiv (addE R_proj PK_proj params) (addE PK_proj R_proj params) := by
                  rw [addE_comm]
                  exact ProjectiveEquiv.refl _
                have h_rpk_equiv3 : ProjectiveEquiv (addE (addE infinityPoint r_PK_val params) s_R_val params) (addE PK_proj R_proj params) :=
                  h_inf_rpk_pk.addE params (ProjectiveEquiv.symm h_sr_equiv)
                have h_trans1 : ProjectiveEquiv RPK_pre (addE PK_proj R_proj params) := ProjectiveEquiv.trans h_rpk_equiv h_comm
                exact ProjectiveEquiv.trans h_trans1 (ProjectiveEquiv.symm h_rpk_equiv3)
              · rcases v7 with _ | v8
                · -- case v = 7 (Precomputed G + R + PK)
                  unfold muxPoint
                  dsimp
                  simp [bsmul.singleton, doubleE_infinity, addE_infinity_infinity]
                  let e_G_val := addE infinityPoint G_proj params
                  let r_PK_val := addE infinityPoint PK_proj params
                  let s_R_val := addE infinityPoint R_proj params
                  let GRPK := addE G_proj ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective params
                  have h_GRPK_Z_rewritten : GRPK.Z ≠ 0 := by
                    rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
                    unfold IsPointEquality at h_rpk
                    let RPK_unrolled := addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params
                    have h_x_eq : RPK_unrolled.X * RPK_unrolled.Z⁻¹ = pre.getD 4 0 := by
                      dsimp [RPK_unrolled]
                      rw [h_rpk.1]
                      rw [mul_comm (RPK_unrolled.Z * pre.getD 4 0) RPK_unrolled.Z⁻¹]
                      rw [←mul_assoc]
                      have h_inv_mul : RPK_unrolled.Z⁻¹ * RPK_unrolled.Z = 1 := inv_mul_cancel₀ h_RPK_Z
                      rw [h_inv_mul, one_mul]
                    have h_y_eq : RPK_unrolled.Y * RPK_unrolled.Z⁻¹ = pre.getD 5 0 := by
                      dsimp [RPK_unrolled]
                      rw [h_rpk.2]
                      rw [mul_comm (RPK_unrolled.Z * pre.getD 5 0) RPK_unrolled.Z⁻¹]
                      rw [←mul_assoc]
                      have h_inv_mul : RPK_unrolled.Z⁻¹ * RPK_unrolled.Z = 1 := inv_mul_cancel₀ h_RPK_Z
                      rw [h_inv_mul, one_mul]
                    have h_GRPK_Z_copy := h_GRPK_Z
                    dsimp only [RPK_unrolled] at h_x_eq h_y_eq
                    rw [h_x_eq, h_y_eq] at h_GRPK_Z_copy
                    dsimp only [GRPK]
                    exact h_GRPK_Z_copy
                  have h_g_eq : ProjectiveEquiv { X := pre.getD 6 0, Y := pre.getD 7 0, Z := 1 } GRPK := by
                    use GRPK.Z⁻¹
                    have h_inv_ne : GRPK.Z⁻¹ ≠ 0 := inv_ne_zero h_GRPK_Z_rewritten
                    constructor
                    · exact h_inv_ne
                    · have h_inv_mul : GRPK.Z⁻¹ * GRPK.Z = 1 := inv_mul_cancel₀ h_GRPK_Z_rewritten
                      rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
                      dsimp only [GRPK] at *
                      unfold IsPointEquality at h_grpk
                      rw [smul_projective]
                      ext
                      · rw [h_grpk.1]
                        rw [←mul_assoc, h_inv_mul, one_mul]
                      · rw [h_grpk.2]
                        rw [←mul_assoc, h_inv_mul, one_mul]
                      · exact h_inv_mul.symm
                  have h_rpk_eq : ProjectiveEquiv ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params) := by
                    let RPK := addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params
                    use RPK.Z⁻¹
                    have h_inv_ne : RPK.Z⁻¹ ≠ 0 := inv_ne_zero h_RPK_Z
                    constructor
                    · exact h_inv_ne
                    · have h_inv_mul : RPK.Z⁻¹ * RPK.Z = 1 := inv_mul_cancel₀ h_RPK_Z
                      rcases h_pre with ⟨h_pre_len, h_gpk, h_gr, h_rpk, h_grpk⟩
                      dsimp only [RPK] at *
                      unfold IsPointEquality at h_rpk
                      rw [smul_projective]
                      ext
                      · rw [h_rpk.1]
                        rw [←mul_assoc, h_inv_mul, one_mul]
                      · rw [h_rpk.2]
                        rw [←mul_assoc, h_inv_mul, one_mul]
                      · exact h_inv_mul.symm
                  have h_geom_equiv : ProjectiveEquiv (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective ({ X := pre.getD 4 0, Y := pre.getD 5 0 : AffinePoint F }).toProjective params) (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params) params) := by
                    exact (ProjectiveEquiv.refl _).addE params h_rpk_eq
                  have h_comm : addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params = addE pk.toProjective ({ X := rx, Y := ry : AffinePoint F }).toProjective params := addE_comm _ _ params
                  have h_assoc : ProjectiveEquiv (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params) params) (addE (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params) ({ X := rx, Y := ry : AffinePoint F }).toProjective params) := by
                    have h_step1 : ProjectiveEquiv (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params) params) (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective (addE pk.toProjective ({ X := rx, Y := ry : AffinePoint F }).toProjective params) params) := by
                      rw [h_comm]
                      exact ProjectiveEquiv.refl _
                    have h_step2 := ProjectiveEquiv.symm (ProjectiveEquiv.addE_assoc ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective ({ X := rx, Y := ry : AffinePoint F }).toProjective params h_G_on h_PK_on h_R_on)
                    exact ProjectiveEquiv.trans h_step1 h_step2
                  have h_geom : ProjectiveEquiv GRPK (addE (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params) ({ X := rx, Y := ry : AffinePoint F }).toProjective params) := by
                    dsimp only [GRPK]
                    exact ProjectiveEquiv.trans h_geom_equiv h_assoc
                  have h_eg_equiv : ProjectiveEquiv G_proj e_G_val := ProjectiveEquiv.symm (addE_infinity_left G_proj params h_gy)
                  have h_rpk_equiv : ProjectiveEquiv PK_proj r_PK_val := ProjectiveEquiv.symm (addE_infinity_left PK_proj params h_pky)
                  have h_sr_equiv : ProjectiveEquiv R_proj s_R_val := ProjectiveEquiv.symm (addE_infinity_left R_proj params h_ry)
                  have h_gpk_equiv2 : ProjectiveEquiv (addE G_proj PK_proj params) (addE e_G_val r_PK_val params) :=
                    h_eg_equiv.addE params h_rpk_equiv
                  have h_grpk_equiv2 : ProjectiveEquiv (addE (addE G_proj PK_proj params) R_proj params) (addE (addE e_G_val r_PK_val params) s_R_val params) :=
                    h_gpk_equiv2.addE params h_sr_equiv
                  have h_trans1 : ProjectiveEquiv { X := pre.getD 6 0, Y := pre.getD 7 0, Z := 1 } (addE (addE G_proj PK_proj params) R_proj params) :=
                    ProjectiveEquiv.trans h_g_eq h_geom
                  exact ProjectiveEquiv.trans h_trans1 h_grpk_equiv2
                · -- case v >= 8 (Contradiction)
                  omega

/-- Proves that multiplexer point selections map to valid curve points. -/
lemma muxPoint_on_projective_curve (v : Nat) (hv : v < 8) (pk : AffinePoint F)
    (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
  (h_gy : params.gy ≠ 0)
  (h_pky : pk.Y ≠ 0)
  (h_ry : ry ≠ 0)
  (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
  (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
  (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
  ProjectivePoint.IsOnCurve (muxPoint v pk rx ry pre params) params := by
  have h_corr := muxPoint_correctness v hv pk rx ry pre params h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
  let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj := pk.toProjective
  let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  let be := decide (v % 2 = 1)
  let br := decide ((v / 2) % 2 = 1)
  let bs := decide ((v / 4) % 2 = 1)
  let e_G := bsmul [be] G_proj params
  let r_PK := bsmul [br] PK_proj params
  let s_R := bsmul [bs] R_proj params
  have h_eg_on : ProjectivePoint.IsOnCurve e_G params := bsmul_on_curve [be] G_proj params h_G_on
  have h_rpk_on : ProjectivePoint.IsOnCurve r_PK params := bsmul_on_curve [br] PK_proj params h_PK_on
  have h_sr_on : ProjectivePoint.IsOnCurve s_R params := bsmul_on_curve [bs] R_proj params h_R_on
  have h_sum1_on : ProjectivePoint.IsOnCurve (addE e_G r_PK params) params := addE_on_curve e_G r_PK params h_eg_on h_rpk_on
  have h_sum2_on : ProjectivePoint.IsOnCurve (addE (addE e_G r_PK params) s_R params) params := addE_on_curve (addE e_G r_PK params) s_R params h_sum1_on h_sr_on
  exact ProjectiveEquiv.isOnCurve params h_corr h_sum2_on

/--
  Inductive lemma proving that the iterative loop foldl result matches a
  mathematically scaled sum of the initial accumulator and the total multiplexer
  contribution: `acc_scaled + e_G + r_PK + s_R`.
-/
lemma ecdsaLoopResult_eq_tripleScalarMul_general (bi : List Nat) (acc_loop : ProjectivePoint F) (is_first_loop : Bool) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi_range : ∀ x ∈ bi, x < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
    (h_accy : acc_loop.Y ≠ 0)
    (h_acc_on : ProjectivePoint.IsOnCurve acc_loop params)
    (h_gy : params.gy ≠ 0)
    (h_pky : pk.Y ≠ 0)
    (h_ry : ry ≠ 0)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
    let e_nat := natE bi
    let r_nat := natR bi
    let s_nat := natS bi
    let e_G := bsmul (padBits (natToBits e_nat) bi.length) G_proj params
    let r_PK := bsmul (padBits (natToBits r_nat) bi.length) PK_proj params
    let s_R := bsmul (padBits (natToBits s_nat) bi.length) R_proj params
    let expected := addE (addE e_G r_PK params) s_R params
    let acc_scaled := bsmul ([true] ++ List.replicate (bi.length - if is_first_loop then 1 else 0) false) acc_loop params
    ProjectiveEquiv (ecdsaPureLoopResultGeneral acc_loop is_first_loop bi pk rx ry pre params) (addE acc_scaled expected params) := by
  induction bi generalizing acc_loop is_first_loop h_accy h_acc_on with
  | nil =>
      unfold ecdsaPureLoopResultGeneral bsmul padBits bitsToNat natE natR natS natReconstruct
      dsimp
      simp only [natToBits_zero, Nat.zero_sub]
      dsimp
      have h_one_eq : 1 = Nat.bit true 0 := rfl
      rw [h_one_eq]
      simp only [nsmulFastE_bit, nsmulFastE_zero, doubleE_infinity, addE_infinity_infinity, if_true]
      have h1 : ProjectiveEquiv (addE infinityPoint acc_loop params) acc_loop := addE_infinity_left acc_loop params h_accy
      have h_acc_scaled_y : (addE infinityPoint acc_loop params).Y ≠ 0 := ProjectiveEquiv.y_ne_zero h1 h_accy
      have h2 : ProjectiveEquiv (addE (addE infinityPoint acc_loop params) infinityPoint params) (addE infinityPoint acc_loop params) := by rw [addE_comm]; exact addE_infinity_left (addE infinityPoint acc_loop params) params h_acc_scaled_y
      have h_trans : ProjectiveEquiv (addE (addE infinityPoint acc_loop params) infinityPoint params) acc_loop := ProjectiveEquiv.trans h2 h1
      exact ProjectiveEquiv.symm h_trans
  | cons v vs ih =>
      unfold ecdsaPureLoopResultGeneral
      dsimp only
      have hv : v < 8 := h_bi_range v List.mem_cons_self
      have h_vs_range : ∀ x ∈ vs, x < 8 := fun x hx => h_bi_range x (List.mem_cons_of_mem v hx)
      let next_acc := addE (if is_first_loop then acc_loop else doubleE acc_loop params) (muxPoint v pk rx ry pre params) params
      have h_next_acc_on : ProjectivePoint.IsOnCurve next_acc params := by
        dsimp [next_acc]
        have h_doubled_on : ProjectivePoint.IsOnCurve (if is_first_loop then acc_loop else doubleE acc_loop params) params := by
          split
          · exact h_acc_on
          · exact doubleE_on_curve acc_loop params h_acc_on
        have h_tx_on : ProjectivePoint.IsOnCurve (muxPoint v pk rx ry pre params) params := by
          exact muxPoint_on_projective_curve v hv pk rx ry pre params h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
        exact addE_on_curve _ _ params h_doubled_on h_tx_on
      have h_next_acc_y : next_acc.Y ≠ 0 := h_next_acc_on.Y_ne_zero
      have h_ih := ih next_acc false h_vs_range h_next_acc_y h_next_acc_on
      have h_reconstruct : ProjectiveEquiv
        (addE
          (bsmul ([true] ++ List.replicate (vs.length - if false = true then 1 else 0) false)
            (addE (if is_first_loop = true then acc_loop else doubleE acc_loop params) (muxPoint v pk rx ry pre params) params) params)
          (addE
            (addE
              (bsmul (padBits (natToBits (natE vs)) vs.length) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
              (bsmul (padBits (natToBits (natR vs)) vs.length) pk.toProjective params) params)
            (bsmul (padBits (natToBits (natS vs)) vs.length) ({ X := rx, Y := ry : AffinePoint F }).toProjective params) params)
          params)
        (addE
          (bsmul ([true] ++ List.replicate ((v :: vs).length - if is_first_loop = true then 1 else 0) false) acc_loop params)
          (addE
            (addE
              (bsmul (padBits (natToBits (natE (v :: vs))) (v :: vs).length) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
              (bsmul (padBits (natToBits (natR (v :: vs))) (v :: vs).length) pk.toProjective params) params)
            (bsmul (padBits (natToBits (natS (v :: vs))) (v :: vs).length) ({ X := rx, Y := ry : AffinePoint F }).toProjective params) params)
          params) := by
        let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
        let PK_proj := pk.toProjective
        let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
        let n := vs.length
        let S_n := [true] ++ List.replicate n false
        let doubled := if is_first_loop = true then acc_loop else doubleE acc_loop params
        let tx := muxPoint v pk rx ry pre params
        
        let rec_G := bsmul (padBits (natToBits (natE vs)) n) G_proj params
        let rec_PK := bsmul (padBits (natToBits (natR vs)) n) PK_proj params
        let rec_R := bsmul (padBits (natToBits (natS vs)) n) R_proj params
        let rec_total := addE (addE rec_G rec_PK params) rec_R params
        
        have h_rec_G_on : rec_G.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
        have h_rec_PK_on : rec_PK.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
        have h_rec_R_on : rec_R.IsOnCurve params := bsmul_on_curve _ R_proj params h_R_on
        have h_rec_GPK_on : (addE rec_G rec_PK params).IsOnCurve params := addE_on_curve rec_G rec_PK params h_rec_G_on h_rec_PK_on
        have h_rec_total_on : rec_total.IsOnCurve params := addE_on_curve _ rec_R params h_rec_GPK_on h_rec_R_on
        
        have h_doubled_on : ProjectivePoint.IsOnCurve doubled params := by
          dsimp [doubled]
          split
          · exact h_acc_on
          · exact doubleE_on_curve acc_loop params h_acc_on
        have h_tx_on : ProjectivePoint.IsOnCurve tx params := by
          exact muxPoint_on_projective_curve v hv pk rx ry pre params h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
          
        have h_acc_scaled_on : (bsmul S_n doubled params).IsOnCurve params := bsmul_on_curve S_n doubled params h_doubled_on
        have h_tx_scaled_on : (bsmul S_n tx params).IsOnCurve params := bsmul_on_curve S_n tx params h_tx_on

        have h_ite_eq : (if false = true then 1 else 0) = 0 := rfl
        simp only [h_ite_eq, Nat.sub_zero]
        
        have h_acc_eq : ProjectiveEquiv (bsmul S_n doubled params)
                        (bsmul ([true] ++ List.replicate ((v :: vs).length - if is_first_loop = true then 1 else 0) false) acc_loop params) := by
          dsimp [doubled]
          cases is_first_loop
          · simp
            have h_double := bsmul_doubleE S_n acc_loop params h_acc_on
            have h_scale := bsmul_scale_double S_n acc_loop params
            have h_step1 : ProjectiveEquiv (bsmul S_n (doubleE acc_loop params) params) (bsmul (S_n ++ [false]) acc_loop params) := by
              exact ProjectiveEquiv.trans h_double (by rw [h_scale]; exact ProjectiveEquiv.refl _)
            have h_scale_eq : S_n ++ [false] = [true] ++ List.replicate (n+1) false := by
              simp [S_n, List.replicate_succ']
            rw [h_scale_eq] at h_step1
            exact h_step1
          · simp [S_n]
            exact ProjectiveEquiv.refl _
            
        have h_distrib := bsmul_addE S_n doubled tx params h_doubled_on h_tx_on
        have h_LHS_equiv : ProjectiveEquiv
          (addE (bsmul S_n (addE doubled tx params) params)
            (addE
              (addE
                (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
              (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
            params)
          (addE (addE (bsmul S_n doubled params) (bsmul S_n tx params) params)
            (addE
              (addE
                (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
              (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
            params) := by
          exact h_distrib.addE params (ProjectiveEquiv.refl _)
        
        have h_rem_equiv : ProjectiveEquiv
          (addE (bsmul S_n tx params)
            (addE
              (addE
                (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
              (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
            params)
          (addE
            (addE
              (bsmul (padBits (natToBits (natE (v :: vs))) (v :: vs).length) G_proj params)
              (bsmul (padBits (natToBits (natR (v :: vs))) (v :: vs).length) PK_proj params) params)
            (bsmul (padBits (natToBits (natS (v :: vs))) (v :: vs).length) R_proj params) params) := by
          have h_mux_corr := muxPoint_correctness v hv pk rx ry pre params h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
          let be := decide (v % 2 = 1)
          let br := decide ((v / 2) % 2 = 1)
          let bs := decide ((v / 4) % 2 = 1)
          let tx_G := bsmul [be] G_proj params
          let tx_PK := bsmul [br] PK_proj params
          let tx_R := bsmul [bs] R_proj params

          have h_tx_equiv : ProjectiveEquiv tx (addE (addE tx_G tx_PK params) tx_R params) := h_mux_corr
          
          have h_tx_scaled_equiv : ProjectiveEquiv
            (bsmul S_n tx params)
            (bsmul S_n (addE (addE tx_G tx_PK params) tx_R params) params) := by
            exact h_tx_equiv.bsmul S_n params

          have h_tx_G_on : ProjectivePoint.IsOnCurve tx_G params := bsmul_on_curve [be] G_proj params h_G_on
          have h_tx_PK_on : ProjectivePoint.IsOnCurve tx_PK params := bsmul_on_curve [br] PK_proj params h_PK_on
          have h_tx_R_on : ProjectivePoint.IsOnCurve tx_R params := bsmul_on_curve [bs] R_proj params h_R_on
          have h_tx_GPK_on : ProjectivePoint.IsOnCurve (addE tx_G tx_PK params) params := addE_on_curve tx_G tx_PK params h_tx_G_on h_tx_PK_on

          have h_tx_scaled_distrib : ProjectiveEquiv
            (bsmul S_n (addE (addE tx_G tx_PK params) tx_R params) params)
            (addE (addE (bsmul S_n tx_G params) (bsmul S_n tx_PK params) params) (bsmul S_n tx_R params) params) := by
            have h_outer := bsmul_addE S_n (addE tx_G tx_PK params) tx_R params h_tx_GPK_on h_tx_R_on
            have h_inner := bsmul_addE S_n tx_G tx_PK params h_tx_G_on h_tx_PK_on
            have h_congr := h_inner.addE params (ProjectiveEquiv.refl (bsmul S_n tx_R params))
            exact ProjectiveEquiv.trans h_outer h_congr

          let G_scaled := bsmul (padBits (natToBits (muxE v * 2^n)) (n+1)) G_proj params
          let PK_scaled := bsmul (padBits (natToBits (muxR v * 2^n)) (n+1)) PK_proj params
          let R_scaled := bsmul (padBits (natToBits (muxS v * 2^n)) (n+1)) R_proj params

          have h_G_scale_eq : ProjectiveEquiv (bsmul S_n tx_G params) G_scaled := by
            have h_be_eq : tx_G = bsmul (padBits (natToBits (muxE v)) 1) G_proj params := by
              have h_mux_decide : muxE v = if be then 1 else 0 := by
                dsimp [muxE, be]
                by_cases h : v % 2 = 1
                · simp [h]
                · simp [h]; omega
              rw [h_mux_decide]
              exact bsmul_bool_eq_nat be G_proj params
            have h_be_equiv : ProjectiveEquiv tx_G (bsmul (padBits (natToBits (muxE v)) 1) G_proj params) := by
              rw [h_be_eq]
              exact ProjectiveEquiv.refl _
            have h_scale := bsmul_scale_nat n (muxE v) G_proj params h_G_on
            have h_tx_G_scaled : ProjectiveEquiv (bsmul S_n tx_G params) (bsmul S_n (bsmul (padBits (natToBits (muxE v)) 1) G_proj params) params) := by
              exact h_be_equiv.bsmul S_n params
            exact ProjectiveEquiv.trans h_tx_G_scaled h_scale

          have h_PK_scale_eq : ProjectiveEquiv (bsmul S_n tx_PK params) PK_scaled := by
            have h_br_eq : tx_PK = bsmul (padBits (natToBits (muxR v)) 1) PK_proj params := by
              have h_mux_decide : muxR v = if br then 1 else 0 := by
                dsimp [muxR, br]
                by_cases h : (v / 2) % 2 = 1
                · simp [h]
                · simp [h]; omega
              rw [h_mux_decide]
              exact bsmul_bool_eq_nat br PK_proj params
            have h_br_equiv : ProjectiveEquiv tx_PK (bsmul (padBits (natToBits (muxR v)) 1) PK_proj params) := by
              rw [h_br_eq]
              exact ProjectiveEquiv.refl _
            have h_scale := bsmul_scale_nat n (muxR v) PK_proj params h_PK_on
            have h_tx_PK_scaled : ProjectiveEquiv (bsmul S_n tx_PK params) (bsmul S_n (bsmul (padBits (natToBits (muxR v)) 1) PK_proj params) params) := by
              exact h_br_equiv.bsmul S_n params
            exact ProjectiveEquiv.trans h_tx_PK_scaled h_scale

          have h_R_scale_eq : ProjectiveEquiv (bsmul S_n tx_R params) R_scaled := by
            have h_bs_eq : tx_R = bsmul (padBits (natToBits (muxS v)) 1) R_proj params := by
              have h_mux_decide : muxS v = if bs then 1 else 0 := by
                dsimp [muxS, bs]
                by_cases h : (v / 4) % 2 = 1
                · simp [h]
                · simp [h]; omega
              rw [h_mux_decide]
              exact bsmul_bool_eq_nat bs R_proj params
            have h_bs_equiv : ProjectiveEquiv tx_R (bsmul (padBits (natToBits (muxS v)) 1) R_proj params) := by
              rw [h_bs_eq]
              exact ProjectiveEquiv.refl _
            have h_scale := bsmul_scale_nat n (muxS v) R_proj params h_R_on
            have h_tx_R_scaled : ProjectiveEquiv (bsmul S_n tx_R params) (bsmul S_n (bsmul (padBits (natToBits (muxS v)) 1) R_proj params) params) := by
              exact h_bs_equiv.bsmul S_n params
            exact ProjectiveEquiv.trans h_tx_R_scaled h_scale

          have h_tx_scaled_combined : ProjectiveEquiv
            (bsmul S_n tx params)
            (addE (addE G_scaled PK_scaled params) R_scaled params) := by
            have h_step1 := ProjectiveEquiv.trans h_tx_scaled_equiv h_tx_scaled_distrib
            have h_congr1 : ProjectiveEquiv
              (addE (bsmul S_n tx_G params) (bsmul S_n tx_PK params) params)
              (addE G_scaled PK_scaled params) := by
              exact h_G_scale_eq.addE params h_PK_scale_eq
            have h_congr2 : ProjectiveEquiv
              (addE (addE (bsmul S_n tx_G params) (bsmul S_n tx_PK params) params) (bsmul S_n tx_R params) params)
              (addE (addE G_scaled PK_scaled params) R_scaled params) := by
              exact h_congr1.addE params h_R_scale_eq
            exact ProjectiveEquiv.trans h_step1 h_congr2

          let rec_G_padded := bsmul (padBits (natToBits (natE vs)) (n+1)) G_proj params
          let rec_PK_padded := bsmul (padBits (natToBits (natR vs)) (n+1)) PK_proj params
          let rec_R_padded := bsmul (padBits (natToBits (natS vs)) (n+1)) R_proj params

          have h_rec_G_pad : ProjectiveEquiv rec_G rec_G_padded := bsmul_pad_nat_equiv n (n+1) (natE vs) G_proj params
          have h_rec_PK_pad : ProjectiveEquiv rec_PK rec_PK_padded := bsmul_pad_nat_equiv n (n+1) (natR vs) PK_proj params
          have h_rec_R_pad : ProjectiveEquiv rec_R rec_R_padded := bsmul_pad_nat_equiv n (n+1) (natS vs) R_proj params

          have h_rec_padded : ProjectiveEquiv
            (addE (addE rec_G rec_PK params) rec_R params)
            (addE (addE rec_G_padded rec_PK_padded params) rec_R_padded params) := by
            exact (h_rec_G_pad.addE params h_rec_PK_pad).addE params h_rec_R_pad

          have h_LHS_equiv_padded : ProjectiveEquiv
            (addE (bsmul S_n tx params) (addE (addE rec_G rec_PK params) rec_R params) params)
            (addE (addE (addE G_scaled PK_scaled params) R_scaled params)
                  (addE (addE rec_G_padded rec_PK_padded params) rec_R_padded params) params) := by
            exact h_tx_scaled_combined.addE params h_rec_padded

          have h_G_scaled_on : G_scaled.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
          have h_PK_scaled_on : PK_scaled.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
          have h_R_scaled_on : R_scaled.IsOnCurve params := bsmul_on_curve _ R_proj params h_R_on
          have h_GPK_scaled_on : (addE G_scaled PK_scaled params).IsOnCurve params := addE_on_curve G_scaled PK_scaled params h_G_scaled_on h_PK_scaled_on
          
          have h_rec_G_padded_on : rec_G_padded.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
          have h_rec_PK_padded_on : rec_PK_padded.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
          have h_rec_R_padded_on : rec_R_padded.IsOnCurve params := bsmul_on_curve _ R_proj params h_R_on
          have h_rec_GPK_padded_on : (addE rec_G_padded rec_PK_padded params).IsOnCurve params := addE_on_curve rec_G_padded rec_PK_padded params h_rec_G_padded_on h_rec_PK_padded_on

          have h_regroup : ProjectiveEquiv
            (addE (addE (addE G_scaled PK_scaled params) R_scaled params) (addE (addE rec_G_padded rec_PK_padded params) rec_R_padded params) params)
            (addE (addE (addE G_scaled rec_G_padded params) (addE PK_scaled rec_PK_padded params) params) (addE R_scaled rec_R_padded params) params) := by
            have h_step1 := addE_rearrange (addE G_scaled PK_scaled params) R_scaled (addE rec_G_padded rec_PK_padded params) rec_R_padded params h_GPK_scaled_on h_R_scaled_on h_rec_GPK_padded_on h_rec_R_padded_on
            have h_rearrange_inner := addE_rearrange G_scaled PK_scaled rec_G_padded rec_PK_padded params h_G_scaled_on h_PK_scaled_on h_rec_G_padded_on h_rec_PK_padded_on
            have h_step2 := h_rearrange_inner.addE params (ProjectiveEquiv.refl (addE R_scaled rec_R_padded params))
            exact ProjectiveEquiv.trans h_step1 h_step2

          have h_E_combined : ProjectiveEquiv
            (addE G_scaled rec_G_padded params)
            (bsmul (padBits (natToBits (natE (v :: vs))) (v :: vs).length) G_proj params) := by
            have h_dist := bsmul_distrib_nat_gen (n+1) (muxE v * 2^n) (natE vs) G_proj params h_G_on
            have h_natE_eq : muxE v * 2^n + natE vs = natE (v :: vs) := by rw [natE_cons]
            rw [h_natE_eq] at h_dist
            exact ProjectiveEquiv.symm h_dist

          have h_PK_combined : ProjectiveEquiv
            (addE PK_scaled rec_PK_padded params)
            (bsmul (padBits (natToBits (natR (v :: vs))) (v :: vs).length) PK_proj params) := by
            have h_dist := bsmul_distrib_nat_gen (n+1) (muxR v * 2^n) (natR vs) PK_proj params h_PK_on
            have h_natR_eq : muxR v * 2^n + natR vs = natR (v :: vs) := by rw [natR_cons]
            rw [h_natR_eq] at h_dist
            exact ProjectiveEquiv.symm h_dist

          have h_R_combined : ProjectiveEquiv
            (addE R_scaled rec_R_padded params)
            (bsmul (padBits (natToBits (natS (v :: vs))) (v :: vs).length) R_proj params) := by
            have h_dist := bsmul_distrib_nat_gen (n+1) (muxS v * 2^n) (natS vs) R_proj params h_R_on
            have h_natS_eq : muxS v * 2^n + natS vs = natS (v :: vs) := by rw [natS_cons]
            rw [h_natS_eq] at h_dist
            exact ProjectiveEquiv.symm h_dist

          have h_all_combined : ProjectiveEquiv
            (addE (addE (addE G_scaled rec_G_padded params) (addE PK_scaled rec_PK_padded params) params) (addE R_scaled rec_R_padded params) params)
            (addE (addE (bsmul (padBits (natToBits (natE (v :: vs))) (v :: vs).length) G_proj params)
                        (bsmul (padBits (natToBits (natR (v :: vs))) (v :: vs).length) PK_proj params) params)
                  (bsmul (padBits (natToBits (natS (v :: vs))) (v :: vs).length) R_proj params) params) := by
            exact (h_E_combined.addE params h_PK_combined).addE params h_R_combined

          have h_step_trans1 := ProjectiveEquiv.trans h_LHS_equiv_padded h_regroup
          exact ProjectiveEquiv.trans h_step_trans1 h_all_combined
          
        have h_LHS_regroup : ProjectiveEquiv
          (addE (addE (bsmul S_n doubled params) (bsmul S_n tx params) params)
            (addE
              (addE
                (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
              (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
            params)
          (addE (bsmul S_n doubled params)
            (addE (bsmul S_n tx params)
              (addE
                (addE
                  (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                  (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
                (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
              params)
            params) := by
          exact ProjectiveEquiv.addE_assoc (bsmul S_n doubled params) (bsmul S_n tx params) rec_total params h_acc_scaled_on h_tx_scaled_on h_rec_total_on
          
        have h_final_step : ProjectiveEquiv
          (addE (bsmul S_n doubled params)
            (addE (bsmul S_n tx params)
              (addE
                (addE
                  (bsmul (padBits (natToBits (natE vs)) vs.length) G_proj params)
                  (bsmul (padBits (natToBits (natR vs)) vs.length) PK_proj params) params)
                (bsmul (padBits (natToBits (natS vs)) vs.length) R_proj params) params)
              params)
            params)
          (addE
            (bsmul ([true] ++ List.replicate ((v :: vs).length - if is_first_loop = true then 1 else 0) false) acc_loop params)
            (addE
              (addE
                (bsmul (padBits (natToBits (natE (v :: vs))) (v :: vs).length) G_proj params)
                (bsmul (padBits (natToBits (natR (v :: vs))) (v :: vs).length) PK_proj params) params)
              (bsmul (padBits (natToBits (natS (v :: vs))) (v :: vs).length) R_proj params) params)
            params) := by
          exact h_acc_eq.addE params h_rem_equiv
            
        have h_step1 := ProjectiveEquiv.trans h_LHS_equiv h_LHS_regroup
        exact ProjectiveEquiv.trans h_step1 h_final_step
      exact ProjectiveEquiv.trans h_ih h_reconstruct

/--
  Proves that starting loop execution at infinity yields a final pure
  accumulator that is projectively equivalent to the expected ECDSA linear
  combination of generator, key, and signature coordinate:
  `e_G + r_PK + s_R`.
-/
lemma loop_result_eq_linear_combination (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi : bi.length = params.kBits)
    (h_bi_range : ∀ x ∈ bi, x < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
    (h_gy : params.gy ≠ 0)
    (h_pky : pk.Y ≠ 0)
    (h_ry : ry ≠ 0)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
    let finalPure := ecdsaPureLoopResult bi pk rx ry pre params
    let e_nat := natE bi
    let r_nat := natR bi
    let s_nat := natS bi
    let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
    let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
    let s_R := bsmul (padBits (natToBits s_nat) params.kBits) R_proj params
    let expected := addE (addE e_G r_PK params) s_R params
    ProjectiveEquiv finalPure expected := by
  intro G_proj PK_proj R_proj finalPure e_nat r_nat s_nat e_G r_PK s_R expected
  have h_gen := ecdsaLoopResult_eq_tripleScalarMul_general bi infinityPoint true pk rx ry pre params h_bi_range h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z
    (by dsimp [infinityPoint]; exact one_ne_zero) (infinity_on_curve params) h_gy h_pky h_ry h_G_on h_PK_on h_R_on

  simp only [h_bi, bsmul_infinity] at h_gen
  have h_expected_on : ProjectivePoint.IsOnCurve expected params :=
    addE_on_curve (addE e_G r_PK params) s_R params
      (addE_on_curve e_G r_PK params
        (bsmul_on_curve _ G_proj params h_G_on)
        (bsmul_on_curve _ PK_proj params h_PK_on))
      (bsmul_on_curve _ R_proj params h_R_on)
  exact ProjectiveEquiv.trans h_gen (addE_infinity_left expected params h_expected_on.Y_ne_zero)

/--
  Pure algebraic bridging theorem: proves that under standard ECDSA verification
  equations, reconstructing the standard combination `e_G + r_PK + s_R` results
  in the point at infinity.
-/
lemma ecdsa_reconstruct_to_infinity (pk : AffinePoint F) (e_nat r_nat s_nat : Nat) (order : Nat) (params : CurveParameters F) (rx ry : F) (s_inv : Nat)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_std : StandardEcdsaVerify pk e_nat r_nat (order - s_nat) order params)
    (hs_inv : ((order - s_nat) * s_inv) % order = 1)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
    let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
    ProjectiveEquiv (addE (addE e_G r_PK params) (addE (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) params) params) infinityPoint := by
  intro G_proj PK_proj e_G r_PK
  have h_e_G_on : e_G.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
  have h_r_PK_on : r_PK.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
  rcases h_std with ⟨h_on_pk, h_pk_order, h_r_pos, h_r_lt, h_s_pos, h_s_lt, h_verify⟩
  have h_PK_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) PK_proj params) infinityPoint := by
    have h_std_pk_order := h_pk_order
    exact h_std_pk_order ▸ ProjectiveEquiv.refl _
  have h_G_order_proj : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) G_proj params) infinityPoint := h_G_order
  have h_order_pos : 0 < order := by omega
  have h_exp1 : (s_nat * ((e_nat % order * s_inv) % order)) % order = (order - (e_nat % order)) % order := by
    exact ecdsa_exponent_modulo_identity (e_nat % order) r_nat s_nat order s_inv hs_inv (Nat.mod_lt e_nat h_order_pos)
  have h_exp2 : (s_nat * ((r_nat * s_inv) % order)) % order = (order - r_nat) % order := by
    exact ecdsa_exponent_modulo_identity r_nat r_nat s_nat order s_inv hs_inv h_r_lt
  have h_neg_e : ProjectiveEquiv (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (order - (e_nat % order))) params.kBits) G_proj params) :=
    bsmul_equiv_of_mod_eq params.kBits (s_nat * ((e_nat % order * s_inv) % order)) (order - (e_nat % order)) G_proj params order h_G_on h_G_order_proj h_exp1
  have h_neg_r : ProjectiveEquiv (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) (bsmul (padBits (natToBits (order - r_nat)) params.kBits) PK_proj params) :=
    bsmul_equiv_of_mod_eq params.kBits (s_nat * ((r_nat * s_inv) % order)) (order - r_nat) PK_proj params order h_PK_on h_PK_order h_exp2
  let e_G_neg := bsmul (padBits (natToBits (order - (e_nat % order))) params.kBits) G_proj params
  let r_PK_neg := bsmul (padBits (natToBits (order - r_nat)) params.kBits) PK_proj params
  have h_e_G_neg_on : e_G_neg.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
  have h_r_PK_neg_on : r_PK_neg.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
  have h_sum_equiv : ProjectiveEquiv (addE (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) params) (addE e_G_neg r_PK_neg params) := by
    exact h_neg_e.addE params h_neg_r
  have h_main_equiv : ProjectiveEquiv (addE (addE e_G r_PK params) (addE (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) params) params) (addE (addE e_G r_PK params) (addE e_G_neg r_PK_neg params) params) := by
    exact (ProjectiveEquiv.refl _).addE params h_sum_equiv
  have h_regroup : ProjectiveEquiv (addE (addE e_G r_PK params) (addE e_G_neg r_PK_neg params) params) (addE (addE e_G e_G_neg params) (addE r_PK r_PK_neg params) params) := by
    exact addE_rearrange e_G r_PK e_G_neg r_PK_neg params h_e_G_on h_r_PK_on h_e_G_neg_on h_r_PK_neg_on
  have h_cancel_G : ProjectiveEquiv (addE e_G e_G_neg params) infinityPoint :=
    bsmul_add_neg_cancel params.kBits e_nat G_proj params order h_G_on h_G_order_proj h_order_pos
  have h_cancel_PK : ProjectiveEquiv (addE r_PK r_PK_neg params) infinityPoint := by
    dsimp only [r_PK, r_PK_neg]
    exact bsmul_inverse_gen r_nat h_r_lt h_PK_on h_PK_order
  have h_cancel_sum : ProjectiveEquiv (addE (addE e_G e_G_neg params) (addE r_PK r_PK_neg params) params) infinityPoint := by
    have h_step := h_cancel_G.addE params h_cancel_PK
    have h_inf_equiv : ProjectiveEquiv (addE infinityPoint infinityPoint params) infinityPoint := by
      rw [addE_infinity_infinity]
      exact ProjectiveEquiv.refl _
    exact ProjectiveEquiv.trans h_step h_inf_equiv
  exact ProjectiveEquiv.trans h_main_equiv (ProjectiveEquiv.trans h_regroup h_cancel_sum)

/--
  Shows that the expected linear combination constructed from the signature
  verifies and equates projectively to infinity, proving completeness.
-/
lemma expected_is_projectively_infinity (pk : AffinePoint F) (e_nat r_nat s_nat : Nat) (order : Nat) (params : CurveParameters F) (rx ry : F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_std : StandardEcdsaVerify pk e_nat r_nat (order - s_nat) order params)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_R_eq : ∃ (s_inv : Nat), ( (order - s_nat) * s_inv) % order = 1 ∧
      let z := e_nat % order
      let u1 := (z * s_inv) % order
      let u2 := (r_nat * s_inv) % order
      let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
      let PK_proj := pk.toProjective
      let R_std := addE (bsmul (padBits (natToBits u1) params.kBits) G_proj params) (bsmul (padBits (natToBits u2) params.kBits) PK_proj params) params
      ∃ (R_Z_inv : F), R_std.Z * R_Z_inv = 1 ∧
      rx = R_std.X * R_Z_inv ∧ ry = R_std.Y * R_Z_inv)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
    let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
    let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
    let s_R := bsmul (padBits (natToBits s_nat) params.kBits) R_proj params
    let expected := addE (addE e_G r_PK params) s_R params
    ProjectiveEquiv expected infinityPoint := by
  intro G_proj PK_proj R_proj e_G r_PK s_R expected
  rcases h_R_eq with ⟨s_inv, hs_inv, h_R_eq_std⟩
  dsimp only at h_R_eq_std
  rcases h_R_eq_std with ⟨R_Z_inv, h_RZ, h_rx, h_ry⟩
  let R_std := addE (bsmul (padBits (natToBits ((e_nat % order * s_inv) % order)) params.kBits) G_proj params) (bsmul (padBits (natToBits ((r_nat * s_inv) % order)) params.kBits) PK_proj params) params
  have h_R_proj_equiv : ProjectiveEquiv R_proj R_std := by
    use R_Z_inv
    refine ⟨?_, ?_⟩
    · -- R_Z_inv ≠ 0
      intro h_zero
      have h_contra : (R_std.Z * R_Z_inv) = 0 := by
        rw [h_zero]
        ring
      rw [h_RZ] at h_contra
      exact one_ne_zero h_contra
    · apply ProjectivePoint.ext
      · dsimp [R_proj, HSMul.hSMul, SMul.smul]
        rw [h_rx]
        ring
      · dsimp [R_proj, HSMul.hSMul, SMul.smul]
        rw [h_ry]
        ring
      · dsimp [R_proj, HSMul.hSMul, SMul.smul]
        rw [mul_comm, h_RZ]
  have h_s_R_equiv : ProjectiveEquiv s_R (bsmul (padBits (natToBits s_nat) params.kBits) R_std params) := by
    dsimp only [s_R]
    exact h_R_proj_equiv.bsmul (padBits (natToBits s_nat) params.kBits) params
  have h_u1_G_on : ProjectivePoint.IsOnCurve (bsmul (padBits (natToBits ((e_nat % order * s_inv) % order)) params.kBits) G_proj params) params :=
    bsmul_on_curve _ G_proj params h_G_on
  have h_u2_PK_on : ProjectivePoint.IsOnCurve (bsmul (padBits (natToBits ((r_nat * s_inv) % order)) params.kBits) PK_proj params) params :=
    bsmul_on_curve _ PK_proj params h_PK_on
  have h_distrib : ProjectiveEquiv (bsmul (padBits (natToBits s_nat) params.kBits) R_std params) (addE (bsmul (padBits (natToBits s_nat) params.kBits) (bsmul (padBits (natToBits ((e_nat % order * s_inv) % order)) params.kBits) G_proj params) params) (bsmul (padBits (natToBits s_nat) params.kBits) (bsmul (padBits (natToBits ((r_nat * s_inv) % order)) params.kBits) PK_proj params) params) params) := by
    dsimp only [R_std]
    exact bsmul_addE (padBits (natToBits s_nat) params.kBits) (bsmul (padBits (natToBits ((e_nat % order * s_inv) % order)) params.kBits) G_proj params) (bsmul (padBits (natToBits ((r_nat * s_inv) % order)) params.kBits) PK_proj params) params h_u1_G_on h_u2_PK_on
  have h_u1_assoc : ProjectiveEquiv (bsmul (padBits (natToBits s_nat) params.kBits) (bsmul (padBits (natToBits ((e_nat % order * s_inv) % order)) params.kBits) G_proj params) params) (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) := by
    exact bsmul_assoc_nat params.kBits s_nat ((e_nat % order * s_inv) % order) G_proj params h_G_on
  have h_u2_assoc : ProjectiveEquiv (bsmul (padBits (natToBits s_nat) params.kBits) (bsmul (padBits (natToBits ((r_nat * s_inv) % order)) params.kBits) PK_proj params) params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) := by
    exact bsmul_assoc_nat params.kBits s_nat ((r_nat * s_inv) % order) PK_proj params h_PK_on
  have h_s_R_unrolled : ProjectiveEquiv s_R (addE (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) params) := by
    have h_step1 := ProjectiveEquiv.trans h_s_R_equiv h_distrib
    have h_step2 := h_u1_assoc.addE params h_u2_assoc
    exact ProjectiveEquiv.trans h_step1 h_step2
  have h_main_equiv : ProjectiveEquiv expected (addE (addE e_G r_PK params) (addE (bsmul (padBits (natToBits (s_nat * ((e_nat % order * s_inv) % order))) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_nat * ((r_nat * s_inv) % order))) params.kBits) PK_proj params) params) params) := by
    dsimp only [expected]
    exact (ProjectiveEquiv.refl _).addE params h_s_R_unrolled
  have h_reconstruct := ecdsa_reconstruct_to_infinity pk e_nat r_nat s_nat order params rx ry s_inv h_std hs_inv h_G_order h_G_on h_PK_on
  exact ProjectiveEquiv.trans h_main_equiv h_reconstruct

lemma linear_combination_is_infinity (pk : AffinePoint F) (e_nat r_nat s_nat : Nat) (order : Nat) (params : CurveParameters F) (rx ry : F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_std : StandardEcdsaVerify pk e_nat r_nat (order - s_nat) order params)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_R_eq : ∃ (s_inv : Nat), ( (order - s_nat) * s_inv) % order = 1 ∧
      let z := e_nat % order
      let u1 := (z * s_inv) % order
      let u2 := (r_nat * s_inv) % order
      let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
      let PK_proj := pk.toProjective
      let R_std := addE (bsmul (padBits (natToBits u1) params.kBits) G_proj params) (bsmul (padBits (natToBits u2) params.kBits) PK_proj params) params
      ∃ (R_Z_inv : F), R_std.Z * R_Z_inv = 1 ∧
      rx = R_std.X * R_Z_inv ∧ ry = R_std.Y * R_Z_inv)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
    let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
    let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
    let s_R := bsmul (padBits (natToBits s_nat) params.kBits) R_proj params
    let expected := addE (addE e_G r_PK params) s_R params
    expected.X = 0 ∧ expected.Z = 0 := by
  intro G_proj PK_proj R_proj e_G r_PK s_R expected
  have h_expected_inf := expected_is_projectively_infinity pk e_nat r_nat s_nat order params rx ry h_std h_G_order h_R_eq h_G_on h_PK_on h_R_on
  dsimp only [expected, e_G, r_PK, s_R, G_proj, PK_proj, R_proj] at h_expected_inf ⊢
  rcases h_expected_inf with ⟨c, hc_ne, h_eq⟩
  constructor
  · rw [h_eq]
    dsimp [infinityPoint, HSMul.hSMul, SMul.smul]
    ring
  · rw [h_eq]
    dsimp [infinityPoint, HSMul.hSMul, SMul.smul]
    ring

/--
  The core Completeness bridge theorem: shows that under standard signature
  validation, the iterative foldl `ecdsaPureLoopResult` evaluates to the point
  at infinity (X=0, Z=0), matching the circuit's final state check.
-/
lemma pure_loop_result_is_infinity (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) (order : Nat)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi : bi.length = params.kBits)
    (h_bi_range : ∀ x ∈ bi, x < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
    (e_nat r_nat s_nat : Nat)
    (he : natE bi = e_nat) (hr : natR bi = r_nat) (hs : natS bi = s_nat)
    (h_std : StandardEcdsaVerify pk e_nat r_nat (order - s_nat) order params)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_R_eq : ∃ (s_inv : Nat), ( (order - s_nat) * s_inv) % order = 1 ∧
      let z := e_nat % order
      let u1 := (z * s_inv) % order
      let u2 := (r_nat * s_inv) % order
      let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
      let PK_proj := pk.toProjective
      let R_std := addE (bsmul (padBits (natToBits u1) params.kBits) G_proj params) (bsmul (padBits (natToBits u2) params.kBits) PK_proj params) params
      ∃ (R_Z_inv : F), R_std.Z * R_Z_inv = 1 ∧
      rx = R_std.X * R_Z_inv ∧ ry = R_std.Y * R_Z_inv)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    let finalPure := ecdsaPureLoopResult bi pk rx ry pre params
    finalPure.X = 0 ∧ finalPure.Z = 0 := by
  intro finalPure
  let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
  let PK_proj := pk.toProjective
  let R_proj := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
  let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
  let s_R := bsmul (padBits (natToBits s_nat) params.kBits) R_proj params
  have h_gy : params.gy ≠ 0 := h_G_on.Y_ne_zero
  have h_pky : pk.Y ≠ 0 := h_PK_on.Y_ne_zero
  have h_ry : ry ≠ 0 := h_R_on.Y_ne_zero
  have h_comb := loop_result_eq_linear_combination bi pk rx ry pre params h_bi h_bi_range h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on

  dsimp only at h_comb
  rw [he, hr, hs] at h_comb
  dsimp only [finalPure]
  rcases h_comb with ⟨c, hc_ne, h_eq⟩
  have h_inf := linear_combination_is_infinity pk e_nat r_nat s_nat order params rx ry h_std h_G_order h_R_eq h_G_on h_PK_on h_R_on
  dsimp only at h_inf
  constructor
  · rw [h_eq]
    change c * (addE (addE e_G r_PK params) s_R params).X = 0
    rw [h_inf.1]
    ring
  · rw [h_eq]
    change c * (addE (addE e_G r_PK params) s_R params).Z = 0
    rw [h_inf.2]
    ring

/-- Proves that the reconstructed standard signature point `R = u1 * G + u2 * PK`
 lies on the projective curve. -/
lemma R_point_on_projective_curve (pk : AffinePoint F) (e r : Nat) (s_inv : Nat) (order : Nat) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_on_pk : pk.IsOnCurve params)
    (h_G : AffinePoint.IsOnCurve { X := params.gx, Y := params.gy } params) :
    let G_proj := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj := pk.toProjective
    let z := e % order
    let u1 := (z * s_inv) % order
    let u2 := (r * s_inv) % order
    let u1_G := bsmul (padBits (natToBits u1) params.kBits) G_proj params
    let u2_PK := bsmul (padBits (natToBits u2) params.kBits) PK_proj params
    let R_point := addE u1_G u2_PK params
    ProjectivePoint.IsOnCurve R_point params := by
  intro G_proj PK_proj z u1 u2 u1_G u2_PK R_point
  have h_G_proj : ProjectivePoint.IsOnCurve G_proj params := by
    have h_eq_curve := IsOnCurve_implies_projective G_proj { X := params.gx, Y := params.gy } params (ProjectiveEquiv.refl G_proj) h_G
    refine ⟨h_eq_curve, ?_⟩
    intro h_zero
    change (({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective) = ({ X := 0, Y := 0, Z := 0 : ProjectivePoint F }) at h_zero
    injection h_zero with _ _ h_z
    exact one_ne_zero h_z
  have h_PK_proj : ProjectivePoint.IsOnCurve PK_proj params := by
    have h_eq_curve := IsOnCurve_implies_projective PK_proj pk params (ProjectiveEquiv.refl PK_proj) h_on_pk
    refine ⟨h_eq_curve, ?_⟩
    intro h_zero
    change (pk.toProjective) = ({ X := 0, Y := 0, Z := 0 : ProjectivePoint F }) at h_zero
    injection h_zero with _ _ h_z
    exact one_ne_zero h_z
  have h_u1_G : ProjectivePoint.IsOnCurve u1_G params := bsmul_on_curve (padBits (natToBits u1) params.kBits) G_proj params h_G_proj
  have h_u2_PK : ProjectivePoint.IsOnCurve u2_PK params := bsmul_on_curve (padBits (natToBits u2) params.kBits) PK_proj params h_PK_proj
  exact addE_on_curve u1_G u2_PK params h_u1_G h_u2_PK

/-!
# SECTION 3: Soundness Proof Lemmas

This section contains the formal proof of algebraic bridging soundness:
ZK loop accepts => Standard Spec holds.
-/

/--
  Inductive lemma proving that loop execution preserves curve membership.
  If the initial accumulator is a valid projective curve point, then the final
  accumulator after executing the foldl loop over any sequence of multiplexer
  indices (each < 8) is also a valid projective curve point.
-/
lemma ecdsaPureLoopResultGeneral_on_projective_curve (bi : List Nat) (acc_loop : ProjectivePoint F) (is_first_loop : Bool) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi_range : ∀ x ∈ bi, x < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
    (h_acc_on : ProjectivePoint.IsOnCurve acc_loop params)
    (h_gy : params.gy ≠ 0)
    (h_pky : pk.Y ≠ 0)
    (h_ry : ry ≠ 0)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
    ProjectivePoint.IsOnCurve (ecdsaPureLoopResultGeneral acc_loop is_first_loop bi pk rx ry pre params) params := by
  induction bi generalizing acc_loop is_first_loop with
  | nil =>
    unfold ecdsaPureLoopResultGeneral
    exact h_acc_on
  | cons v vs ih =>
    unfold ecdsaPureLoopResultGeneral
    dsimp only
    have hv : v < 8 := h_bi_range v List.mem_cons_self
    have h_vs_range : ∀ x ∈ vs, x < 8 := fun x hx => h_bi_range x (List.mem_cons_of_mem v hx)
    let next_acc := addE (if is_first_loop then acc_loop else doubleE acc_loop params) (muxPoint v pk rx ry pre params) params
    have h_next_acc_on : ProjectivePoint.IsOnCurve next_acc params := by
      dsimp [next_acc]
      have h_doubled_on : ProjectivePoint.IsOnCurve (if is_first_loop then acc_loop else doubleE acc_loop params) params := by
        split
        · exact h_acc_on
        · exact doubleE_on_curve acc_loop params h_acc_on
      have h_tx_on : ProjectivePoint.IsOnCurve (muxPoint v pk rx ry pre params) params := by
        exact muxPoint_on_projective_curve v hv pk rx ry pre params h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
      exact addE_on_curve _ _ params h_doubled_on h_tx_on
    exact ih next_acc false h_vs_range h_next_acc_on

lemma ecdsaPureLoopResult_on_projective_curve (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi_range : ∀ x ∈ bi, x < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
  (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
  (h_gy : params.gy ≠ 0)
  (h_pky : pk.Y ≠ 0)
  (h_ry : ry ≠ 0)
  (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
  (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
  (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params) :
  ProjectivePoint.IsOnCurve (ecdsaPureLoopResult bi pk rx ry pre params) params := by
  unfold ecdsaPureLoopResult
  exact ecdsaPureLoopResultGeneral_on_projective_curve bi infinityPoint true pk rx ry pre params
    h_bi_range h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z (infinity_on_curve params) h_gy h_pky h_ry h_G_on h_PK_on h_R_on

/--
  `ecdsa_algebraic_equivalence` is the primary algebraic bridging theorem for
  ECDSA verification. It proves the mathematical equivalence between the ZK
  circuit's loop result and the standard affine signature verification equations.
  
  Specifically, if:
  1. The loop execution starts at the point at infinity and runs for 
    `params.kBits` steps, terminating in the point at infinity (`h_final_inf`).
  2. The signature components `r = natR(bi)`, `s_nat = natS(bi)`, and 
     `e_nat = natE(bi)` are bounded and satisfy modular inversion relations
     `((order - s_nat) * s_inv) % order = 1`.
  3. The intermediate curve additions are well-defined and do not trigger
     exceptional Weierstrass additions.
  4. The base generator `G`, public key `PK`, and signature coordinate `R`
     are appropriately scaled under group multiplication (`order * P = O`).

  THEN, the standard verification point `R = u1 * G + u2 * PK` constructed
  using standard scalar projection equations is projectively equivalent to the
  affine coordinates `{ X := rx, Y := ry }` supplied by the prover, and its
  Z-coordinate is non-zero (`R.Z ≠ 0`).
-/
lemma ecdsa_algebraic_equivalence (bi : List Nat) (pk : AffinePoint F) (rx ry : F) (pre : List F) (params : CurveParameters F) (order : Nat)
    [h_ell : (params.toMathlib).IsElliptic]
    [CurveHasNoPointsOfOrder2 params]
    (h_bi_len : bi.length = params.kBits)
    (h_bi_bounds : ∀ v ∈ bi, v < 8)
    (h_pre : ValidPreComputationExact pk rx ry pre params)
    (h_GPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GR_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params).Z ≠ 0)
    (h_RPK_Z : (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z ≠ 0)
    (h_GRPK_Z : (addE ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective { X := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).X * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Y := (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Y * (addE ({ X := rx, Y := ry : AffinePoint F }).toProjective pk.toProjective params).Z⁻¹, Z := 1 } params).Z ≠ 0)
    (h_G_on : ProjectivePoint.IsOnCurve ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params)
    (h_PK_on : ProjectivePoint.IsOnCurve pk.toProjective params)
    (h_R_on : ProjectivePoint.IsOnCurve ({ X := rx, Y := ry : AffinePoint F }).toProjective params)
    (h_G_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective params) infinityPoint)
    (h_PK_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) pk.toProjective params) infinityPoint)
    (h_R_order : ProjectiveEquiv (bsmul (padBits (natToBits order) params.kBits) ({ X := rx, Y := ry : AffinePoint F }).toProjective params) infinityPoint)
    (h_final_inf : (ecdsaPureLoopResult bi pk rx ry pre params).X = 0 ∧ (ecdsaPureLoopResult bi pk rx ry pre params).Z = 0)
    (s_inv_val : Nat)
    (hs_inv : ((order - natS bi) * s_inv_val) % order = 1) :
    let G_proj : ProjectivePoint F := ({ X := params.gx, Y := params.gy : AffinePoint F }).toProjective
    let PK_proj : ProjectivePoint F := pk.toProjective
    let s_nat := natS bi
    let e_nat := natE bi
    let r_nat := natR bi
    let u1 := (e_nat % order * s_inv_val) % order
    let u2 := (r_nat * s_inv_val) % order
    let u1_G := bsmul (padBits (natToBits u1) params.kBits) G_proj params
    let u2_PK := bsmul (padBits (natToBits u2) params.kBits) PK_proj params
    let R := addE u1_G u2_PK params
    ProjectiveEquiv R ({ X := rx, Y := ry } : AffinePoint F).toProjective ∧ R.Z ≠ 0 := by
  intro G_proj PK_proj s_nat e_nat r_nat u1 u2 u1_G u2_PK R
  let R_proj : ProjectivePoint F := ({ X := rx, Y := ry : AffinePoint F }).toProjective
  have h_u1_G_on : u1_G.IsOnCurve params := bsmul_on_curve _ G_proj params h_G_on
  have h_u2_PK_on : u2_PK.IsOnCurve params := bsmul_on_curve _ PK_proj params h_PK_on
  have h_R_on_curve : R.IsOnCurve params := addE_on_curve u1_G u2_PK params h_u1_G_on h_u2_PK_on
  have h_s_scaled_on : (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params).IsOnCurve params := bsmul_on_curve _ R_proj params h_R_on
  have h_cancel_R_on : (addE (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params).IsOnCurve params := addE_on_curve _ R_proj params h_s_scaled_on h_R_on
  have h_gy : params.gy ≠ 0 := h_G_on.Y_ne_zero
  have h_pky : pk.Y ≠ 0 := h_PK_on.Y_ne_zero
  have h_ry : ry ≠ 0 := h_R_on.Y_ne_zero
  have h_order_gt_1 : order > 1 := by
    by_contra hc
    have h_zero_or_one : order = 0 ∨ order = 1 := by omega
    rcases h_zero_or_one with h_zero | h_one
    · subst h_zero
      have h_sub_zero : 0 - natS bi = 0 := by omega
      rw [h_sub_zero] at hs_inv
      have h_zero_mul : 0 * s_inv_val = 0 := zero_mul _
      rw [h_zero_mul] at hs_inv
      have h_zero_mod : 0 % 0 = 0 := rfl
      rw [h_zero_mod] at hs_inv
      contradiction
    · subst h_one
      have h_mod_one : ((1 - natS bi) * s_inv_val) % 1 = 0 := Nat.mod_one _
      rw [h_mod_one] at hs_inv
      contradiction
  let finalPure := ecdsaPureLoopResult bi pk rx ry pre params
  have h_finalPure_on : ProjectivePoint.IsOnCurve finalPure params :=
    ecdsaPureLoopResult_on_projective_curve bi pk rx ry pre params h_bi_bounds h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on
  have h_loop_inf : ProjectiveEquiv finalPure infinityPoint := by
    use finalPure.Y
    have h_y_ne : finalPure.Y ≠ 0 := h_finalPure_on.Y_ne_zero
    refine ⟨h_y_ne, ?_⟩
    dsimp [infinityPoint]
    change finalPure = { X := finalPure.Y * 0, Y := finalPure.Y * 1, Z := finalPure.Y * 0 }
    apply ProjectivePoint.ext
    · rw [h_final_inf.1]; ring
    · ring
    · rw [h_final_inf.2]; ring

  let e_G := bsmul (padBits (natToBits e_nat) params.kBits) G_proj params
  let r_PK := bsmul (padBits (natToBits r_nat) params.kBits) PK_proj params
  let s_R := bsmul (padBits (natToBits s_nat) params.kBits) R_proj params
  let expected := addE (addE e_G r_PK params) s_R params

  have h_loop_expected : ProjectiveEquiv finalPure expected := by
    exact loop_result_eq_linear_combination bi pk rx ry pre params h_bi_len h_bi_bounds h_pre h_GPK_Z h_GR_Z h_RPK_Z h_GRPK_Z h_gy h_pky h_ry h_G_on h_PK_on h_R_on

  have h_expected_inf : ProjectiveEquiv expected infinityPoint := by
    exact ProjectiveEquiv.trans (ProjectiveEquiv.symm h_loop_expected) h_loop_inf

  have h_e_G_on : ProjectivePoint.IsOnCurve e_G params := bsmul_on_curve _ G_proj params h_G_on
  have h_r_PK_on : ProjectivePoint.IsOnCurve r_PK params := bsmul_on_curve _ PK_proj params h_PK_on
  have h_s_R_on : ProjectivePoint.IsOnCurve s_R params := bsmul_on_curve _ R_proj params h_R_on
  have h_sum1_on : ProjectivePoint.IsOnCurve (addE e_G r_PK params) params := addE_on_curve e_G r_PK params h_e_G_on h_r_PK_on

  have h_scaled : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) expected params) infinityPoint := by
    have h_scale_eq := h_expected_inf.bsmul (padBits (natToBits s_inv_val) params.kBits) params
    have h_inf : bsmul (padBits (natToBits s_inv_val) params.kBits) infinityPoint params = infinityPoint := bsmul_infinity (padBits (natToBits s_inv_val) params.kBits) params
    exact h_inf ▸ h_scale_eq

  have h_scaled_distrib : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) expected params)
    (addE (bsmul (padBits (natToBits s_inv_val) params.kBits) (addE e_G r_PK params) params) (bsmul (padBits (natToBits s_inv_val) params.kBits) s_R params) params) := by
    dsimp [expected]
    exact bsmul_addE (padBits (natToBits s_inv_val) params.kBits) (addE e_G r_PK params) s_R params h_sum1_on h_s_R_on

  have h_scaled_distrib2 : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) (addE e_G r_PK params) params)
    (addE (bsmul (padBits (natToBits s_inv_val) params.kBits) e_G params) (bsmul (padBits (natToBits s_inv_val) params.kBits) r_PK params) params) := by
    exact bsmul_addE (padBits (natToBits s_inv_val) params.kBits) e_G r_PK params h_e_G_on h_r_PK_on

  have h_assoc_e : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) e_G params)
    (bsmul (padBits (natToBits (s_inv_val * e_nat)) params.kBits) G_proj params) := by
    exact bsmul_assoc_nat params.kBits s_inv_val e_nat G_proj params h_G_on
  have h_assoc_r : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) r_PK params)
    (bsmul (padBits (natToBits (s_inv_val * r_nat)) params.kBits) PK_proj params) := by
    exact bsmul_assoc_nat params.kBits s_inv_val r_nat PK_proj params h_PK_on
  have h_assoc_s : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) s_R params)
    (bsmul (padBits (natToBits (s_inv_val * s_nat)) params.kBits) R_proj params) := by
    exact bsmul_assoc_nat params.kBits s_inv_val s_nat R_proj params h_R_on

  have h_sum_assoc : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) (addE e_G r_PK params) params)
    (addE (bsmul (padBits (natToBits (s_inv_val * e_nat)) params.kBits) G_proj params) (bsmul (padBits (natToBits (s_inv_val * r_nat)) params.kBits) PK_proj params) params) := by
    have h_step1 := ProjectiveEquiv.trans h_scaled_distrib2 (h_assoc_e.addE params h_assoc_r)
    exact h_step1

  let e_scaled := bsmul (padBits (natToBits (s_inv_val * e_nat)) params.kBits) G_proj params
  let r_scaled := bsmul (padBits (natToBits (s_inv_val * r_nat)) params.kBits) PK_proj params
  let s_scaled := bsmul (padBits (natToBits (s_inv_val * s_nat)) params.kBits) R_proj params
  have h_final_sum_equiv : ProjectiveEquiv (bsmul (padBits (natToBits s_inv_val) params.kBits) expected params) (addE (addE e_scaled r_scaled params) s_scaled params) := by
    have h1 := h_sum_assoc.addE params h_assoc_s
    exact ProjectiveEquiv.trans h_scaled_distrib h1

  have h_lhs_inf : ProjectiveEquiv (addE (addE e_scaled r_scaled params) s_scaled params) infinityPoint := by
    exact ProjectiveEquiv.trans (ProjectiveEquiv.symm h_final_sum_equiv) h_scaled

  have h_u1_eq : ProjectiveEquiv e_scaled u1_G := by
    dsimp [e_scaled, u1_G]
    have h_mod : (s_inv_val * e_nat) % order = u1 := by
      dsimp [u1]
      have h1 : (s_inv_val * e_nat) % order = ((s_inv_val % order) * (e_nat % order)) % order := by rw [Nat.mul_mod]
      have h2 : (e_nat % order * s_inv_val) % order = ((e_nat % order % order) * (s_inv_val % order)) % order := by rw [Nat.mul_mod]
      rw [h1, h2]
      have h_mod_mod : e_nat % order % order = e_nat % order := Nat.mod_mod _ _
      rw [h_mod_mod]
      rw [Nat.mul_comm (s_inv_val % order) (e_nat % order)]
    have h_reduced := bsmul_mod_nat params.kBits (s_inv_val * e_nat) G_proj params order h_G_on h_G_order
    have h_reduced_symm := ProjectiveEquiv.symm h_reduced
    rw [h_mod] at h_reduced_symm
    exact h_reduced_symm

  have h_u2_eq : ProjectiveEquiv r_scaled u2_PK := by
    dsimp [r_scaled, u2_PK]
    have h_mod : (s_inv_val * r_nat) % order = u2 := by
      dsimp [u2]
      rw [Nat.mul_comm]
    have h_reduced := bsmul_mod_nat params.kBits (s_inv_val * r_nat) PK_proj params order h_PK_on h_PK_order
    have h_reduced_symm := ProjectiveEquiv.symm h_reduced
    rw [h_mod] at h_reduced_symm
    exact h_reduced_symm

  have h_us_eq : ProjectiveEquiv s_scaled (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) := by
    dsimp [s_scaled]
    have h_mod : (s_inv_val * s_nat) % order = order - 1 := by
      have h_mul_comm : s_inv_val * s_nat = s_nat * s_inv_val := Nat.mul_comm _ _
      rw [h_mul_comm]
      have h_snat_lt : s_nat < order := by
        have h_sub_pos : order - s_nat > 0 := by
          by_contra hc
          have h_zero : order - s_nat = 0 := by omega
          rw [h_zero] at hs_inv
          simp at hs_inv
        omega
      have h_identity_call := ecdsa_exponent_modulo_identity 1 1 s_nat order s_inv_val hs_inv (by omega)
      have h_one_mul : 1 * s_inv_val = s_inv_val := one_mul _
      rw [h_one_mul] at h_identity_call
      have h_sub_mod : (order - 1) % order = order - 1 := Nat.mod_eq_of_lt (by omega)
      rw [h_sub_mod] at h_identity_call
      have h_arith2 : (s_nat * s_inv_val) % order = (s_nat * (s_inv_val % order)) % order := by
        rw [Nat.mul_mod s_nat s_inv_val]
        rw [Nat.mul_mod s_nat (s_inv_val % order)]
        rw [Nat.mod_mod]
      rw [h_arith2]
      exact h_identity_call
    have h_reduced := bsmul_mod_nat params.kBits (s_inv_val * s_nat) R_proj params order h_R_on h_R_order
    have h_reduced_symm := ProjectiveEquiv.symm h_reduced
    rw [h_mod] at h_reduced_symm
    exact h_reduced_symm

  have h_scaled_sum_equiv : ProjectiveEquiv (addE (addE e_scaled r_scaled params) s_scaled params) (addE (addE u1_G u2_PK params) (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) := by
    exact (h_u1_eq.addE params h_u2_eq).addE params h_us_eq

  have h_lhs_inf2 : ProjectiveEquiv (addE R (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) infinityPoint := by
    dsimp [R]
    exact ProjectiveEquiv.trans (ProjectiveEquiv.symm h_scaled_sum_equiv) h_lhs_inf

  have h_cancel : ProjectiveEquiv (addE (addE R (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) R_proj params) (addE infinityPoint R_proj params) := by
    exact h_lhs_inf2.addE params (ProjectiveEquiv.refl _)

  have h_rhs_simpl : ProjectiveEquiv (addE infinityPoint R_proj params) R_proj := by
    exact addE_infinity_left R_proj params h_ry

  have h_lhs_assoc : ProjectiveEquiv (addE (addE R (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) R_proj params)
    (addE R (addE (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params) params) := by
    exact ProjectiveEquiv.addE_assoc R (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params h_R_on_curve h_s_scaled_on h_R_on

  have h_one_R_proj : ProjectiveEquiv (bsmul (padBits (natToBits 1) params.kBits) R_proj params) R_proj := by
    have h_eq1 : bsmul (padBits (natToBits 1) params.kBits) R_proj params = nsmulFastE 1 R_proj params := by
      unfold bsmul
      rw [bitsToNat_padBits 1 params.kBits]
    have h_eq2 : bsmul [true] R_proj params = nsmulFastE 1 R_proj params := by
      unfold bsmul
      rfl
    have h_equiv_one := bsmul_one R_proj params h_R_on
    rw [h_eq2] at h_equiv_one
    rw [← h_eq1] at h_equiv_one
    exact h_equiv_one

  have h_cancel_R : ProjectiveEquiv (addE (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params) infinityPoint := by
    have h_comm := addE_comm (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params
    have h_one_equiv : ProjectiveEquiv (addE R_proj (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) (addE (bsmul (padBits (natToBits 1) params.kBits) R_proj params) (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) params) := by
      exact (ProjectiveEquiv.symm h_one_R_proj).addE params (ProjectiveEquiv.refl _)
    have h_inv := bsmul_inverse_gen 1 (by omega) h_R_on h_R_order
    rw [h_comm]
    exact ProjectiveEquiv.trans h_one_equiv h_inv

  have h_lhs_simpl : ProjectiveEquiv (addE R (addE (bsmul (padBits (natToBits (order - 1)) params.kBits) R_proj params) R_proj params) params) R := by
    have h_step := (ProjectiveEquiv.refl R).addE params h_cancel_R
    have h_ry_ne : R.Y ≠ 0 := by
      exact h_R_on_curve.Y_ne_zero
    have h_id : ProjectiveEquiv (addE R infinityPoint params) R := by rw [addE_comm]; exact addE_infinity_left R params h_ry_ne
    exact ProjectiveEquiv.trans h_step h_id

  have h_R_equiv : ProjectiveEquiv R R_proj := by
    have h_lhs := ProjectiveEquiv.trans (ProjectiveEquiv.symm h_lhs_simpl) (ProjectiveEquiv.symm h_lhs_assoc)
    have h_total := ProjectiveEquiv.trans h_lhs h_cancel
    exact ProjectiveEquiv.trans h_total h_rhs_simpl

  have h_Z_ne : R.Z ≠ 0 := (projectiveEquiv_toProjective_iff R { X := rx, Y := ry }).mp h_R_equiv |>.2.2
  exact ⟨h_R_equiv, h_Z_ne⟩

/-- Extracts standard signature bounds and shows that component `r` is positive. -/
lemma r_nat_pos (w : EcdsaWitness F) (pk : AffinePoint F) (e : F) (order : Nat) (params : CurveParameters F)
    (h : ValidEcdsaWitness w pk e order params) : natR (w.bi.map val3) > 0 := by
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, h_rst, _, _, h_rx_inv, _, _, _, _⟩
  have h_rx_ne : w.rx ≠ 0 := by
    intro h_zero
    rw [h_zero, zero_mul] at h_rx_inv
    exact zero_ne_one h_rx_inv
  have h_rec_ne : @reconstructR F _ (w.bi.map val3) ≠ 0 := by
    rw [h_rst]
    exact h_rx_ne
  rw [reconstructR_eq_natR] at h_rec_ne
  have h_nat_ne_nat : natR (w.bi.map val3) ≠ 0 := by
    intro h_zero
    rw [h_zero, Nat.cast_zero] at h_rec_ne
    exact h_rec_ne rfl
  exact Nat.pos_of_ne_zero h_nat_ne_nat

/-- Extracts standard signature bounds and shows that component `s` is positive. -/
lemma s_nat_pos (w : EcdsaWitness F) (pk : AffinePoint F) (e : F) (order : Nat) (params : CurveParameters F)
    (h : ValidEcdsaWitness w pk e order params) : natS (w.bi.map val3) > 0 := by
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, h_s_inv, _, _, _⟩
  have h_rec_ne : @reconstructS F _ (w.bi.map val3) ≠ 0 := by
    intro h_zero
    rw [h_zero, zero_mul] at h_s_inv
    exact zero_ne_one h_s_inv
  rw [reconstructS_eq_natS] at h_rec_ne
  have h_nat_ne_nat : natS (w.bi.map val3) ≠ 0 := by
    intro h_zero
    rw [h_zero, Nat.cast_zero] at h_rec_ne
    exact h_rec_ne rfl
  exact Nat.pos_of_ne_zero h_nat_ne_nat

/-- Extracts standard signature bounds and proves modular validity range checks for `s`. -/
lemma s_range (w : EcdsaWitness F) (pk : AffinePoint F) (e : F) (order : Nat) (params : CurveParameters F)
    (h : ValidEcdsaWitness w pk e order params) : 0 < order - natS (w.bi.map val3) ∧ order - natS (w.bi.map val3) < order := by
  have h_s_pos := s_nat_pos w pk e order params h
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, h_s_lt⟩
  have h_order_pos : 0 < order := Nat.lt_trans h_s_pos h_s_lt
  constructor
  · exact Nat.sub_pos_of_lt h_s_lt
  · exact Nat.sub_lt h_order_pos h_s_pos

end ECDSA
