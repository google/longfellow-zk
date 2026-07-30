import Mathlib
import sumcheck_soundness
import types
import fiat_shamir

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

variable {F : Type} [Field F] [Fintype F]
variable {Circuit Input Witness : Type}
variable {Ω : Type} [Fintype Ω]
variable (C : Circuit) (x : Input)
variable (eval : Circuit → Input → Witness → Bool)
variable {nc nv : ℕ}
variable (eps_FSK eps_sumcheck : ℕ)

-- Helper to extract the i-th bit of a number
def bit_value (i : ℕ) (bit_idx : ℕ) : ℕ := (i / (2^bit_idx)) % 2


-- Multilinear basis polynomial evaluating to 1 at the binary representation of `i`
def eq_mle_basis {n : ℕ} {F : Type} [Field F] (i : ℕ) (x : Vector F n) : F :=
  ∏ j : Fin n, (if bit_value i j.val = 1 then x.get j else (1 - x.get j))


-- Multilinear extension of the identity matrix restricted to size `n`
-- This matches `Eq::eval` in `privacy/proofs/zk/lib/arrays/eq.h:L39`
def eq_matrix_mle {F : Type} [Field F] (n logn : ℕ) (x y : Vector F logn) : F :=
  ∑ i ∈ Finset.range n, (eq_mle_basis i x * eq_mle_basis i y)


/--
The exact polynomial checked during the multi-round sumcheck for a single layer.
This maps directly to `got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` in `verifier_layers.h:160`.
-/
noncomputable def layer_sumcheck_poly {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)]
  (Quad_mle : Vector F logv → Vector F logw → Vector F logw → F)
  (W_mle : Vector F logw → Vector F logc → F)
  (alpha : F)
  (q : Vector F logc) (g0 g1 : Vector F logv)
  (copy : Vector F logc) (l r : Vector F logw) : F :=
  -- EQ[Q, C] restricted to domain `nc`
  eq_matrix_mle nc logc q copy *
  -- QUAD[G | L, R] bound with alpha (matches `bind_gh_all` in `quad.h`)
  (∑ g ∈ (Finset.univ : Finset (Vector F logv)), Quad_mle g l r *
    (eq_matrix_mle nv logv g0 g + alpha * eq_matrix_mle nv logv g1 g)) *
  -- W[L, C] * W[R, C]
  W_mle l copy * W_mle r copy


-- Helper to concatenate and extract vectors
def extract_vars {logc logw : ℕ} {F : Type} [Field F] (concat : Vector F (logc + 2 * logw)) :
  Vector F logc × Vector F logw × Vector F logw :=
  let c := Vector.ofFn (fun (i : Fin logc) => concat.get ⟨i.val, by omega⟩)
  let w1 := Vector.ofFn (fun (i : Fin logw) => concat.get ⟨logc + i.val, by omega⟩)
  let w2 := Vector.ofFn (fun (i : Fin logw) => concat.get ⟨logc + logw + i.val, by omega⟩)
  (c, w1, w2)


noncomputable def layer_sumcheck_poly_concat {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)]
  (Quad_mle : Vector F logv → Vector F logw → Vector F logw → F)
  (W_mle : Vector F logw → Vector F logc → F)
  (alpha : F)
  (q : Vector F logc) (g0 g1 : Vector F logv)
  (concat : Vector F (logc + 2 * logw)) : F :=
  let (copy, l, r) := extract_vars concat
  layer_sumcheck_poly (nc := nc) (nv := nv) Quad_mle W_mle alpha q g0 g1 copy l r


-- Helper to prepend a fixed prefix, a free variable, and a boolean suffix
-- to form a full vector of length n.
def construct_assignment {n : ℕ} {F : Type} [Field F] (k : ℕ) (hk : k < n)
  (pref : Vector F k) (free_var : F) (suffix : Vector F (n - k - 1)) : Vector F n :=
  Vector.ofFn (fun i =>
    if h : i.val < k then pref.get ⟨i.val, h⟩
    else if h_eq : i.val = k then free_var
    else suffix.get ⟨i.val - k - 1, by omega⟩
  )


def boolean_vector {n : ℕ} {F : Type} [Field F] (i : ℕ) : Vector F n :=
  Vector.ofFn (fun j => if bit_value i j.val = 1 then 1 else 0)


def sumcheck_eval_round {n : ℕ} {F : Type} [Field F] (f : Vector F n → F) (k : ℕ) (hk : k < n)
  (challenges : Vector F k) (X : F) : F :=
  ∑ i : Fin (2^(n - k - 1)),
    f (construct_assignment k hk challenges X (boolean_vector i.val))


noncomputable def lagrange_basis {F : Type} [Field F] [Fintype F] [DecidableEq F] (a : F) : Polynomial F :=
  ∏ x ∈ (univ.erase a), (X - Polynomial.C x) * Polynomial.C ((a - x)⁻¹)


-- The true univariate polynomial for round k.
noncomputable def sumcheck_round_poly {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] (f : Vector F n → F) (k : ℕ) (hk : k < n) (challenges : Vector F k) : Polynomial F :=
  ∑ a : F, Polynomial.C (sumcheck_eval_round f k hk challenges a) * lagrange_basis a


-- Generate the list of true polynomials for all n rounds.
noncomputable def generate_true_polys {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] (f : Vector F n → F) (challenges : Vector F n) : List (Polynomial F) :=
  List.ofFn (fun (k : Fin n) => sumcheck_round_poly f k.val k.isLt (Vector.ofFn fun i => challenges.get ⟨i.val, by omega⟩))


/--
**Structure: ArithmetizedCircuit**

An abstract mathematical specification of a circuit arithmetization in the Longfellow ZK protocol.
An `ArithmetizedCircuit` bundles the multilinear extension maps (`Quad_mle`, `W_mle`) and the arithmetization soundness
property as first-class fields of the circuit object.

This keeps the formal proof abstract and modular: any concrete compiler or DSL that generates
valid multilinear polynomials and satisfies the arithmetization soundness condition can instantiate this structure.
-/
structure ArithmetizedCircuit (Circuit Input Witness : Type) (nc nv logv logw logc : ℕ) (F : Type) [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] where
  eval : Circuit → Input → Witness → Bool
  Quad_mle : Circuit → Vector F logv → Vector F logw → Vector F logw → F
  W_mle : Witness → Vector F logw → Vector F logc → F
  soundness : ∀ (c : Circuit) (inp : Input) (w : Witness)
    (eqq : F) (t : Transcript F) (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv),
    eval c inp w = false →
    ∃ (P_first : Polynomial F) (P_rest : List (Polynomial F)),
      generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (Quad_mle c) (W_mle w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) = P_first :: P_rest ∧
      List.length (P_first :: P_rest) = t.polys.length ∧
      t.challenges.length = t.polys.length ∧
      consistent_true_polys (P_first :: P_rest) t.challenges ∧
      0 ≠ P_first.eval 0 + P_first.eval 1 ∧
      get_last_eval (P_first :: P_rest) t.challenges = some (eqq * t.w_r_true * t.w_l_true)


-- Now `circuit_true_polys` is just `generate_true_polys` applied to the layer polynomial
noncomputable def circuit_true_polys {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv logv logw logc F)
  (c : Circuit) (w : Witness) (t : Transcript F)
  (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) : List (Polynomial F) :=
  generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0)


/--
**Structure: IsSumcheckCorrelationIntractable**

Formalizes the property that the sumcheck protocol transcript is correlation intractable under
the Fiat-Shamir heuristic, bounding the number of challenge sequences leading to a bad event by `eps_sumcheck`.

**Combinatorial Justification:**
In `sumcheck_soundness.lean`, we prove `combinatorial_fiat_shamir` and `combinatorial_fiat_shamir_soundness`,
which establish that for any `IsFiatShamirTranscript`, the total number of cheating challenge sequences
across all rounds is bounded by `n * d * |F|^(n-1)`, without any probability or random oracle axioms.
-/
structure IsSumcheckCorrelationIntractable {nc nv logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv logv logw logc F)
  (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
  (eqq : F) (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
  (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) (eps_sumcheck : ℕ) where
  ci_bound : event_card (Finset.filter (fun ω => ∃ w pad, E_L ω = some (w, pad) ∧
    multi_round_bad_event (circuit_true_polys AC c w ((T_p ω).decrypt pad var_dwR var_dwL) alpha q_challenge g0 g1) (T_p ω).polys (T_p ω).challenges) Finset.univ) ≤ eps_sumcheck

def builder_finalize {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)] (e : Expression M F) (eqq : F) (wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) : (Fin M → F) × F :=
  let rhs := eqq * wc0 * wc1 - e.1
  let lhs := fun i =>
    let base := e.2 i
    let step1 := if i = var_dwL then base - eqq * wc1 else base
    let step2 := if i = var_dwR then step1 - eqq * wc0 else step1
    if i = var_dwL_dwR then step2 - eqq else step2
  (lhs, rhs)


/--
Proves that the linear constraint generated by `builder_finalize` mathematically forces
the unpadded claim to equal the sumcheck multiplication check `EQQ * W_L * W_R`.
-/
theorem builder_finalize_soundness {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e : Expression M F) (pad : Fin M → F)
    (eqq : F) (wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) :
    let lr := builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR
    let lhs := lr.1
    let rhs := lr.2
    let claim_last := evaluates_to e pad
    (∑ i, lhs i * pad i = rhs) →
    (pad var_dwL_dwR = pad var_dwL * pad var_dwR) →
    claim_last = eqq * (wc0 + pad var_dwL) * (wc1 + pad var_dwR) := by
  intros lr lhs rhs claim_last h_sum h_quad
  dsimp [lr, builder_finalize, lhs, rhs, claim_last, evaluates_to] at *

  have h_lhs : (fun i => (if i = var_dwL_dwR then (if i = var_dwR then (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i) - eqq * wc0 else (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i)) - eqq else (if i = var_dwR then (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i) - eqq * wc0 else (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i))) * pad i) = fun i => e.2 i * pad i - (if i = var_dwL then eqq * wc1 * pad i else 0) - (if i = var_dwR then eqq * wc0 * pad i else 0) - (if i = var_dwL_dwR then eqq * pad i else 0) := by
    ext i
    split_ifs <;> ring
  rw [h_lhs] at h_sum
  rw [Finset.sum_sub_distrib, Finset.sum_sub_distrib, Finset.sum_sub_distrib] at h_sum
  have h_sum1 : (∑ i : Fin M, (if i = var_dwL then eqq * wc1 * pad i else 0)) = eqq * wc1 * pad var_dwL := by
    simp
  have h_sum2 : (∑ i : Fin M, (if i = var_dwR then eqq * wc0 * pad i else 0)) = eqq * wc0 * pad var_dwR := by
    simp
  have h_sum3 : (∑ i : Fin M, (if i = var_dwL_dwR then eqq * pad i else 0)) = eqq * pad var_dwL_dwR := by
    simp
  rw [h_sum1, h_sum2, h_sum3] at h_sum
  rw [h_quad] at h_sum

  calc e.1 + ∑ i : Fin M, e.2 i * pad i
    _ = e.1 + ((∑ i : Fin M, e.2 i * pad i) - eqq * wc1 * pad var_dwL - eqq * wc0 * pad var_dwR - eqq * (pad var_dwL * pad var_dwR) + eqq * wc1 * pad var_dwL + eqq * wc0 * pad var_dwR + eqq * (pad var_dwL * pad var_dwR)) := by ring
    _ = e.1 + (eqq * wc0 * wc1 - e.1 + eqq * wc1 * pad var_dwL + eqq * wc0 * pad var_dwR + eqq * (pad var_dwL * pad var_dwR)) := by rw [h_sum]
    _ = eqq * (wc0 + pad var_dwL) * (wc1 + pad var_dwR) := by ring


def input_constraint_row {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
  (got : F) (pub_binding : F) (beta alpha : F)
  (witness_binding : Fin M → F) (var_dwL var_dwR : Fin M) : (Fin M → F) × F :=
  let rhs := got - pub_binding
  let lhs := fun j =>
    let w_part := witness_binding j
    let p1 := if j = var_dwL then w_part - beta else w_part
    if j = var_dwR then p1 - alpha else p1
  (lhs, rhs)


/--
Proves that the linear constraint generated by `input_constraint_row` correctly binds
the witness evaluations to the padded transcript values.
-/
theorem input_constraint_soundness {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (pad : Fin M → F) (got : F) (pub_binding : F) (beta alpha : F)
    (witness_binding : Fin M → F) (var_dwL var_dwR : Fin M) :
    let lr := input_constraint_row got pub_binding beta alpha witness_binding var_dwL var_dwR
    let lhs := lr.1
    let rhs := lr.2
    (∑ i, lhs i * pad i = rhs) →
        (∑ i, witness_binding i * pad i) + pub_binding = got + beta * pad var_dwL + alpha * pad var_dwR := by
  intros lr lhs rhs h_sum
  dsimp [lr, input_constraint_row, lhs, rhs] at *
  have h_lhs : (fun j => (if j = var_dwR then (if j = var_dwL then witness_binding j - beta else witness_binding j) - alpha else (if j = var_dwL then witness_binding j - beta else witness_binding j)) * pad j) = fun j => witness_binding j * pad j - (if j = var_dwL then beta * pad j else 0) - (if j = var_dwR then alpha * pad j else 0) := by
    ext j
    split_ifs <;> ring
  rw [h_lhs] at h_sum
  rw [Finset.sum_sub_distrib, Finset.sum_sub_distrib] at h_sum
  have h_sum1 : (∑ j : Fin M, (if j = var_dwL then beta * pad j else 0)) = beta * pad var_dwL := by
    simp
  have h_sum2 : (∑ j : Fin M, (if j = var_dwR then alpha * pad j else 0)) = alpha * pad var_dwR := by
    simp
  rw [h_sum1, h_sum2] at h_sum

  calc (∑ i : Fin M, witness_binding i * pad i) + pub_binding
    _ = (∑ i : Fin M, witness_binding i * pad i) - beta * pad var_dwL - alpha * pad var_dwR + beta * pad var_dwL + alpha * pad var_dwR + pub_binding := by ring
    _ = got - pub_binding + beta * pad var_dwL + alpha * pad var_dwR + pub_binding := by
      rw [h_sum]
    _ = got + beta * pad var_dwL + alpha * pad var_dwR := by ring
