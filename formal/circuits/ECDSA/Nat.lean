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


/-!
## Natural Number and Bit-List Conversion Helpers

This section defines utility functions and establishes properties for converting
between natural numbers (`Nat`) and binary bit lists (`List Bool`), typically
represented in Most-Significant-Bit (MSB) first format.

Key definitions:
- `natToBits`: Converts a natural number to its binary representation as an MSB-first list of booleans.
- `padBits`: Left-pads a bit list with `false` values to a specified length.

Key lemmas prove upper bounds and identities on bit lengths and value preservation,
which are crucial for verifying correctness of the bit-level constraints in circuits.
-/

@[expose] public section

section NatHelpers

/--
  Convert a bit list (MSB-first) to a natural number.
-/
def bitsToNat (s : List Bool) : Nat :=
  s.foldl (fun acc b => acc * 2 + (if b then 1 else 0)) 0

/-- Helper for evaluating LSB-first bit lists. -/
def bitsToNatLSB (l : List Bool) : Nat :=
  match l with
  | [] => 0
  | b :: bs => (if b then 1 else 0) + 2 * bitsToNatLSB bs

/--
  Convert a natural number `n` to its binary representation as a list of booleans,
  with the most significant bit (MSB) first.
  Implemented as the reverse of the standard library's LSB-first `Nat.bits`.
-/
def natToBits (n : Nat) : List Bool :=
  (Nat.bits n).reverse

lemma natToBits_zero : natToBits 0 = [] := by simp [natToBits, Nat.bits]


def natToBitsAux (n : Nat) (acc : List Bool) : List Bool :=
  if h : n = 0 then
    acc
  else
    have : n / 2 < n := Nat.div_lt_self (Nat.pos_of_ne_zero h) (by decide)
    natToBitsAux (n / 2) ((n % 2 == 1) :: acc)

lemma nat_bit_decomp (n : Nat) : Nat.bit (n % 2 == 1) (n / 2) = n := by
  dsimp [Nat.bit]
  by_cases h : n % 2 = 1
  · have h2 : (n % 2 == 1) = true := by simp [h]
    rw [h2]
    dsimp
    omega
  · have h2 : (n % 2 == 1) = false := by simp [h]
    rw [h2]
    dsimp
    omega

lemma Nat.bits_succ (m : Nat) : Nat.bits (m + 1) = ((m + 1) % 2 == 1) :: Nat.bits ((m + 1) / 2) := by
  have h := Nat.bits_append_bit ((m + 1) / 2) ((m + 1) % 2 == 1)
  have h_cond : (m + 1) / 2 = 0 → ((m + 1) % 2 == 1) = true := by
    intro h_div
    have h_m : m + 1 = 1 := by
      have h_eq := Nat.div_add_mod (m + 1) 2
      rw [h_div] at h_eq
      simp at h_eq
      have h_mod : (m + 1) % 2 < 2 := Nat.mod_lt _ (by decide)
      omega
    rw [h_m]
    rfl
  have h2 := h h_cond
  rw [nat_bit_decomp] at h2
  exact h2

lemma natToBitsAux_eq_bits (n : Nat) (acc : List Bool) :
    natToBitsAux n acc = (Nat.bits n).reverse ++ acc := by
  induction n using Nat.strong_induction_on generalizing acc
  rename_i n ih
  unfold natToBitsAux
  by_cases hn : n = 0
  · simp [hn]
  · rw [dif_neg hn]
    have hn_ne : n ≠ 0 := hn
    have h_lt : n / 2 < n := Nat.div_lt_self (Nat.pos_of_ne_zero hn_ne) (by decide)
    rw [ih (n / 2) h_lt ((n % 2 == 1) :: acc)]
    cases n with
    | zero => contradiction
    | succ m =>
      rw [Nat.bits_succ m]
      simp

lemma natToBits_eq_natToBitsAux (n : Nat) :
    natToBits n = natToBitsAux n [] := by
  unfold natToBits
  rw [natToBitsAux_eq_bits]
  simp

def padBits (l : List Bool) (n : Nat) : List Bool :=
  List.leftpad n false l

lemma padBits_length (l : List Bool) (n : Nat) (h : l.length ≤ n) :
    (padBits l n).length = n := by
  unfold padBits List.leftpad
  rw [List.length_append, List.length_replicate]
  omega

lemma natToBits_length (n : Nat) (k : Nat) (h : n < 2^k) :
    (natToBits n).length ≤ k := by
  unfold natToBits
  rw [List.length_reverse, Nat.size_eq_bits_len n]
  exact Nat.size_le.mpr h

/-- Helper for bitsToNat on replicated false list (zeros have no value) -/
lemma foldl_bitsToNat_replicate_false (n : Nat) (acc : Nat) (hacc : acc = 0) :
    (List.replicate n false).foldl (fun acc b => acc * 2 + (if b then 1 else 0)) acc = 0 := by
  induction n generalizing acc with
  | zero =>
    exact hacc
  | succ n' ih =>
    subst hacc
    exact ih 0 rfl

/-- Left-padding false bits does not change the bitsToNat value -/
lemma bitsToNat_padBits_eq_bitsToNat (l : List Bool) (k : Nat) :
    bitsToNat (padBits l k) = bitsToNat l := by
  unfold bitsToNat padBits List.leftpad
  rw [List.foldl_append]
  have h_zero : (List.replicate (k - l.length) false).foldl (fun acc b => acc * 2 + (if b then 1 else 0)) 0 = 0 := by
    apply foldl_bitsToNat_replicate_false
    rfl
  rw [h_zero]

/-- General shift homomorphism for bitsToNat folding step -/
lemma foldl_bitsToNat_general (l : List Bool) (a : Nat) :
    l.foldl (fun acc b => acc * 2 + (if b then 1 else 0)) a =
    a * 2^l.length + l.foldl (fun acc b => acc * 2 + (if b then 1 else 0)) 0 := by
  induction l generalizing a with
  | nil =>
    dsimp
    ring
  | cons b l' ih =>
    dsimp
    rw [Nat.zero_add]
    rw [ih (a * 2 + (if b then 1 else 0))]
    rw [ih (if b then 1 else 0)]
    have h_pow : 2^(l'.length + 1) = 2^l'.length * 2 := rfl
    rw [h_pow]
    ring

theorem bitsToNatLSB_bits (n : Nat) : bitsToNatLSB (Nat.bits n) = n := by
  induction n using Nat.binaryRec' with
  | zero =>
    rw [Nat.zero_bits]
    rfl
  | bit b n h ih =>
    rw [Nat.bits_append_bit _ _ h]
    dsimp [bitsToNatLSB]
    rw [ih]
    cases b
    · dsimp [Nat.bit]
      ring
    · dsimp [Nat.bit]
      ring

lemma foldl_reverse_bitsToNat (l : List Bool) (a : Nat) :
    l.reverse.foldl (fun acc b => acc * 2 + (if b then 1 else 0)) a =
    a * 2^l.length + bitsToNatLSB l := by
  induction l generalizing a with
  | nil => simp [bitsToNatLSB]
  | cons b bs ih =>
    simp [bitsToNatLSB, ih]
    ring

lemma bitsToNat_natToBits (val : Nat) : bitsToNat (natToBits val) = val := by
  unfold bitsToNat natToBits
  have h := foldl_reverse_bitsToNat (Nat.bits val) 0
  rw [Nat.zero_mul, Nat.zero_add] at h
  rw [h]
  exact bitsToNatLSB_bits val

lemma bitsToNat_padBits (val : Nat) (k : Nat) : bitsToNat (padBits (natToBits val) k) = val := by
  rw [bitsToNat_padBits_eq_bitsToNat]
  exact bitsToNat_natToBits val

/-! ## Exponent Reconstruction Helpers -/

def muxE (v : Nat) : Nat := v % 2
def muxR (v : Nat) : Nat := (v / 2) % 2
def muxS (v : Nat) : Nat := (v / 4) % 2

def reconstructExponent {F : Type} [Field F] (bi : List Nat) (mux : Nat → F) : F :=
  bi.foldl (fun acc v => acc * 2 + mux v) 0

def reconstructE {F : Type} [Field F] (bi : List Nat) : F :=
  reconstructExponent bi (fun v => if v % 2 = 1 then 1 else 0)

def reconstructR {F : Type} [Field F] (bi : List Nat) : F :=
  reconstructExponent bi (fun v => if (v / 2) % 2 = 1 then 1 else 0)

def reconstructS {F : Type} [Field F] (bi : List Nat) : F :=
  reconstructExponent bi (fun v => if (v / 4) % 2 = 1 then 1 else 0)

def natReconstruct (bi : List Nat) (mux : Nat → Nat) : Nat :=
  bi.foldl (fun acc v => acc * 2 + mux v) 0

def natE (bi : List Nat) : Nat := natReconstruct bi muxE
def natR (bi : List Nat) : Nat := natReconstruct bi muxR
def natS (bi : List Nat) : Nat := natReconstruct bi muxS

/-! ## Homomorphism Lemmas for Exponent Reconstruction -/

/--
  Homomorphism lemma for exponent reconstruction.
  Proves that reconstructing an exponent using `foldl` in the field `F`
  is equivalent to reconstructing it in `Nat` and then casting the result to `F`.
-/
theorem foldl_reconstruct_hom {F : Type} [Field F] (bi : List Nat) (mux : Nat → Nat) (acc : Nat) :
    bi.foldl (fun (acc_f : F) v => acc_f * 2 + (((mux v : Nat) : F))) ((acc : Nat) : F) =
    ((((bi.foldl (fun (acc_n : Nat) v => acc_n * 2 + mux v) acc) : Nat) : F)) := by
  induction bi generalizing acc with
  | nil => rfl
  | cons v vs ih =>
      dsimp
      have h_acc : ((acc : Nat) : F) * 2 + (((mux v : Nat) : F)) = ((((acc * 2 + mux v : Nat) : F))) := by
        push_cast
        ring
      rw [h_acc]
      exact ih (acc * 2 + mux v)

/--
  General homomorphism lemma for multiplexers.
  Proves that if a multiplexer `mux` always outputs a value less than 2,
  then `if mux v = 1 then 1 else 0` in the field `F` is equal to `mux v` cast to `F`.
-/
lemma mux_hom_general {F : Type} [Field F] (mux : Nat → Nat) (hmux : ∀ v, mux v < 2) (v : Nat) :
    (if mux v = 1 then (1:F) else 0) = (((mux v : Nat) : F)) := by
  by_cases hx : mux v = 1
  · rw [if_pos hx, hx]
    simp
  · rw [if_neg hx]
    have h_bounds : mux v < 2 := hmux v
    have h_zero : mux v = 0 := by omega
    rw [h_zero]
    simp

/--
  General theorem for exponent reconstruction equivalence.
  Proves that reconstructing an exponent in the field `F` using a multiplexer is equivalent
  to reconstructing it in `Nat` and then casting to `F`, provided the multiplexer outputs
  values less than 2.
-/
theorem reconstruct_eq_nat_general {F : Type} [Field F] (bi : List Nat) (mux : Nat → Nat) (hmux : ∀ v, mux v < 2) :
    reconstructExponent bi (fun v => if mux v = 1 then 1 else 0) = ((natReconstruct bi mux : Nat) : F) := by
  unfold reconstructExponent natReconstruct
  have h_fun : (fun v => if mux v = 1 then (1:F) else 0) = (fun v => (((mux v : Nat) : F))) := by
    funext v; apply mux_hom_general mux hmux
  rw [h_fun]
  dsimp
  rw [←Nat.cast_zero]
  exact foldl_reconstruct_hom (F := F) bi mux 0

/--
  Equivalence of field-level and Nat-level reconstruction for exponent E.
-/
theorem reconstructE_eq_natE {F : Type} [Field F] (bi : List Nat) :
    reconstructE bi = ((natE bi : Nat) : F) :=
  reconstruct_eq_nat_general bi muxE (fun v => Nat.mod_lt v (by decide))

/--
  Equivalence of field-level and Nat-level reconstruction for exponent R.
-/
theorem reconstructR_eq_natR {F : Type} [Field F] (bi : List Nat) :
    reconstructR bi = ((natR bi : Nat) : F) :=
  reconstruct_eq_nat_general bi muxR (fun v => Nat.mod_lt (v / 2) (by decide))

/--
  Equivalence of field-level and Nat-level reconstruction for exponent S.
-/
theorem reconstructS_eq_natS {F : Type} [Field F] (bi : List Nat) :
    reconstructS bi = ((natS bi : Nat) : F) :=
  reconstruct_eq_nat_general bi muxS (fun v => Nat.mod_lt (v / 4) (by decide))

lemma foldl_reconstruct_acc (vs : List Nat) (mux : Nat → Nat) (acc : Nat) :
    vs.foldl (fun acc x => acc * 2 + mux x) acc = acc * 2^vs.length + vs.foldl (fun acc x => acc * 2 + mux x) 0 := by
  induction vs generalizing acc with
  | nil => simp
  | cons x xs ih =>
    dsimp [List.foldl]
    rw [ih (acc * 2 + mux x)]
    have h_zero : 0 * 2 + mux x = mux x := by omega
    rw [h_zero]
    rw [ih (mux x)]
    rw [Nat.add_mul]
    rw [Nat.mul_assoc]
    rw [Nat.pow_succ]
    rw [Nat.mul_comm 2 (2^xs.length)]
    omega

lemma natReconstruct_cons (v : Nat) (vs : List Nat) (mux : Nat → Nat) :
    natReconstruct (v :: vs) mux = mux v * 2^vs.length + natReconstruct vs mux := by
  unfold natReconstruct
  dsimp [List.foldl]
  have h_zero : 0 * 2 + mux v = mux v := by omega
  rw [h_zero]
  exact foldl_reconstruct_acc vs mux (mux v)

lemma natE_cons (v : Nat) (vs : List Nat) : natE (v :: vs) = muxE v * 2^vs.length + natE vs := by
  exact natReconstruct_cons v vs muxE

lemma natR_cons (v : Nat) (vs : List Nat) : natR (v :: vs) = muxR v * 2^vs.length + natR vs := by
  exact natReconstruct_cons v vs muxR

lemma natS_cons (v : Nat) (vs : List Nat) : natS (v :: vs) = muxS v * 2^vs.length + natS vs := by
  exact natReconstruct_cons v vs muxS

lemma natToBits_mul_two (val : Nat) (h : val > 0) :
    natToBits (val * 2) = natToBits val ++ [false] := by
  unfold natToBits
  have h_ne : val ≠ 0 := by omega
  have h_bit0 := Nat.bit0_bits val h_ne
  have h_comm : val * 2 = 2 * val := by ring
  rw [h_comm, h_bit0]
  simp

lemma padBits_scale_double (val : Nat) (n : Nat) :
    padBits (natToBits val) (n+1) ++ [false] = padBits (natToBits (val * 2)) (n+2) := by
  by_cases h_val : val = 0
  · subst h_val
    unfold natToBits padBits List.leftpad
    simp
    have h_rep_one : [false] = List.replicate 1 false := rfl
    rw [h_rep_one, ← List.replicate_add]
  · have h_gt : val > 0 := Nat.pos_of_ne_zero h_val
    have h_mul := natToBits_mul_two val h_gt
    rw [h_mul]
    unfold padBits List.leftpad
    rw [List.length_append]
    have h_len_false : [false].length = 1 := rfl
    rw [h_len_false]
    have h_len : n + 2 - ((natToBits val).length + 1) = n + 1 - (natToBits val).length := by omega
    rw [h_len]
    simp

lemma bitsToNat_append (s : List Bool) (b : Bool) :
    bitsToNat (s ++ [b]) = Nat.bit b (bitsToNat s) := by
  unfold bitsToNat
  rw [List.foldl_append]
  dsimp [List.foldl]
  cases b
  · dsimp [Nat.bit]
    ring
  · dsimp [Nat.bit]
    ring

end NatHelpers
