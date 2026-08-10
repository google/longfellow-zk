import Mathlib
import sumcheck_soundness
import types
import builder

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


/-- The boolean point of the hypercube indexed by `i` — a gate corner. -/
def boolean_vector {n : ℕ} {F : Type} [Field F] (i : ℕ) : Vector F n :=
  Vector.ofFn (fun j => if bit_value i j.val = 1 then 1 else 0)

/--
The exact polynomial checked during the multi-round sumcheck for a single layer.
This maps directly to `got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` in `verifier_layers.h:160`.
-/
noncomputable def layer_sumcheck_poly {F : Type} [Field F] [Fintype F]
  (Quad_mle : Vector F logv → Vector F logw → Vector F logw → F)
  (W_mle : Vector F logw → Vector F logc → F)
  (alpha : F)
  (q : Vector F logc) (g0 g1 : Vector F logv)
  (copy : Vector F logc) (l r : Vector F logw) : F :=
  -- EQ[Q, C] restricted to domain `nc`
  eq_matrix_mle nc logc q copy *
  -- QUAD[G | L, R] bound with alpha.  `bind_g` (`quad.h:L153`) iterates over the *gates*,
  -- looking each gate's corner `ec.g` up in `dot = raw_eq2(logv, nv, G0, G1, alpha)`, so the
  -- sum is over the `nv` gate corners — not over all of `F^logv`.
  (∑ i ∈ Finset.range nv, Quad_mle (boolean_vector i) l r *
    (eq_mle_basis i g0 + alpha * eq_mle_basis i g1)) *
  -- W[L, C] * W[R, C]
  W_mle l copy * W_mle r copy


-- Helper to concatenate and extract vectors
def extract_vars {logc logw : ℕ} {F : Type} [Field F] (concat : Vector F (logc + 2 * logw)) :
  Vector F logc × Vector F logw × Vector F logw :=
  let c := Vector.ofFn (fun (i : Fin logc) => concat.get ⟨i.val, by omega⟩)
  let w1 := Vector.ofFn (fun (i : Fin logw) => concat.get ⟨logc + i.val, by omega⟩)
  let w2 := Vector.ofFn (fun (i : Fin logw) => concat.get ⟨logc + logw + i.val, by omega⟩)
  (c, w1, w2)


noncomputable def layer_sumcheck_poly_concat {F : Type} [Field F] [Fintype F]
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
`lagrange_basis a` is the delta function at `a`: it evaluates to `1` at `a`
and to `0` at every other element of `F`.
-/
lemma lagrange_basis_eval {F : Type} [Field F] [Fintype F] [DecidableEq F] (a r : F) :
    (lagrange_basis a).eval r = if r = a then 1 else 0 := by
  rw [lagrange_basis, Polynomial.eval_prod]
  by_cases h : r = a
  · subst h
    rw [if_pos rfl]
    apply Finset.prod_eq_one
    intro x hx
    have hx' : x ≠ r := (Finset.mem_erase.mp hx).1
    have hne : r - x ≠ 0 := sub_ne_zero.mpr (Ne.symm hx')
    simp [hne]
  · rw [if_neg h]
    apply Finset.prod_eq_zero (i := r)
    · exact Finset.mem_erase.mpr ⟨h, Finset.mem_univ r⟩
    · simp

/--
`sumcheck_round_poly` is the interpolant of the round function: evaluating
it at any `r : F` returns the round-`k` partial sum with the free variable set to `r`.

This is what makes `generate_true_polys` the *honest* prover's round polynomials,
and it is the lemma that lets a concrete `ArithmetizedCircuit` discharge the
`get_last_eval` and `0 ≠ P.eval 0 + P.eval 1` obligations of `soundness` below.
-/
lemma sumcheck_round_poly_eval {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (f : Vector F n → F) (k : ℕ) (hk : k < n) (challenges : Vector F k) (r : F) :
    (sumcheck_round_poly f k hk challenges).eval r
      = sumcheck_eval_round f k hk challenges r := by
  rw [sumcheck_round_poly, Polynomial.eval_finsetSum]
  simp [lagrange_basis_eval]



/-!
## The hypercube-splitting lemmas

Everything below discharges what `ArithmetizedCircuit.soundness` used to assume about the
honest round polynomials.  The engine is the bijection `j ↦ (j / 2, j % 2)` between
`{0,…,2^(m+1)-1}` and `{0,…,2^m-1} × {0,1}`, matched against `boolean_vector` (whose bits
are read by `bit_value`) and `construct_assignment` (which splices a challenge prefix, a
free variable, and a boolean suffix).
-/

lemma bv_zero (i b : ℕ) (hb : b < 2) : bit_value (2 * i + b) 0 = b := by
  simp [bit_value]; omega

lemma bv_succ (i b t : ℕ) (hb : b < 2) : bit_value (2 * i + b) (t + 1) = bit_value i t := by
  simp only [bit_value, pow_succ']
  rw [← Nat.div_div_eq_div_mul]
  congr 2
  omega

/-- Extend a prefix by one more coordinate. -/
def prefSucc {k : ℕ} {F : Type} [Field F] (pref : Vector F k) (X : F) : Vector F (k + 1) :=
  Vector.ofFn (fun j => if h : j.val < k then pref.get ⟨j.val, h⟩ else X)

example {n : ℕ} (k : ℕ) (hk1 : k + 1 < n)
    (pref : Vector F k) (X : F) (i b : ℕ) (hb : b < 2) :
    construct_assignment (n := n) k (by omega) pref X (boolean_vector (2 * i + b))
      = construct_assignment (n := n) (k+1) hk1 (prefSucc pref X)
          (if b = 1 then (1:F) else 0) (boolean_vector i) := by
  ext m hm
  simp only [construct_assignment, boolean_vector, prefSucc, Vector.getElem_ofFn]
  rcases lt_trichotomy m k with h | h | h
  · rw [dif_pos h, dif_pos (by omega : m < k + 1)]
    simp [Vector.get, h]
  · subst h
    rw [dif_neg (by omega), dif_pos rfl, dif_pos (by omega : m < m + 1)]
    simp [Vector.get]
  · rw [dif_neg (by omega), dif_neg (by omega)]
    rcases eq_or_lt_of_le (show k + 1 ≤ m by omega) with h2 | h2
    · rw [dif_neg (by omega), dif_pos h2.symm]
      have hz : bit_value (2 * i + b) (m - k - 1) = b := by
        have he : m - k - 1 = 0 := by omega
        rw [he, bv_zero i b hb]
      simp [Vector.get, hz]
    · rw [dif_neg (by omega), dif_neg (by omega)]
      have hb2 : bit_value (2 * i + b) (m - k - 1) = bit_value i (m - (k + 1) - 1) := by
        have he : m - k - 1 = (m - (k + 1) - 1) + 1 := by omega
        rw [he, bv_succ i b _ hb]
      simp [Vector.get, hb2]

lemma ca_split {n : ℕ} {F : Type} [Field F] (k : ℕ) (hk1 : k + 1 < n)
    (pref : Vector F k) (X : F) (i b : ℕ) (hb : b < 2) :
    construct_assignment (n := n) k (by omega) pref X (boolean_vector (2 * i + b))
      = construct_assignment (n := n) (k+1) hk1 (prefSucc pref X)
          (if b = 1 then (1:F) else 0) (boolean_vector i) := by
  ext m hm
  simp only [construct_assignment, boolean_vector, prefSucc, Vector.getElem_ofFn]
  rcases lt_trichotomy m k with h | h | h
  · rw [dif_pos h, dif_pos (by omega : m < k + 1)]
    simp [Vector.get, h]
  · subst h
    rw [dif_neg (by omega), dif_pos rfl, dif_pos (by omega : m < m + 1)]
    simp [Vector.get]
  · rw [dif_neg (by omega), dif_neg (by omega)]
    rcases eq_or_lt_of_le (show k + 1 ≤ m by omega) with h2 | h2
    · rw [dif_neg (by omega), dif_pos h2.symm]
      have hz : bit_value (2 * i + b) (m - k - 1) = b := by
        have he : m - k - 1 = 0 := by omega
        rw [he, bv_zero i b hb]
      simp [Vector.get, hz]
    · rw [dif_neg (by omega), dif_neg (by omega)]
      have hb2 : bit_value (2 * i + b) (m - k - 1) = bit_value i (m - (k + 1) - 1) := by
        have he : m - k - 1 = (m - (k + 1) - 1) + 1 := by omega
        rw [he, bv_succ i b _ hb]
      simp [Vector.get, hb2]

lemma sum_range_two_mul {M : Type*} [AddCommMonoid M] (m : ℕ) (g : ℕ → M) :
    ∑ j ∈ Finset.range (2 * m), g j = ∑ i ∈ Finset.range m, (g (2 * i) + g (2 * i + 1)) := by
  induction m with
  | zero => simp
  | succ m ih =>
    have h : 2 * (m + 1) = 2 * m + 1 + 1 := by ring
    rw [h, Finset.sum_range_succ, Finset.sum_range_succ, ih, Finset.sum_range_succ]
    abel

lemma sumcheck_eval_round_range {n : ℕ} {F : Type} [Field F] (f : Vector F n → F) (k : ℕ) (hk : k < n)
    (ch : Vector F k) (X : F) :
    sumcheck_eval_round f k hk ch X
      = ∑ j ∈ Finset.range (2 ^ (n - k - 1)),
          f (construct_assignment k hk ch X (boolean_vector j)) :=
  Fin.sum_univ_eq_sum_range
    (fun j => f (construct_assignment k hk ch X (boolean_vector j))) _

lemma sumcheck_eval_round_split {n : ℕ} {F : Type} [Field F] (f : Vector F n → F) (k : ℕ) (hk1 : k + 1 < n)
    (ch : Vector F k) (X : F) :
    sumcheck_eval_round f (k+1) hk1 (prefSucc ch X) 0
      + sumcheck_eval_round f (k+1) hk1 (prefSucc ch X) 1
      = sumcheck_eval_round f k (by omega) ch X := by
  rw [sumcheck_eval_round_range, sumcheck_eval_round_range, sumcheck_eval_round_range]
  have hpow : 2 ^ (n - k - 1) = 2 * 2 ^ (n - (k+1) - 1) := by
    have he : n - k - 1 = (n - (k+1) - 1) + 1 := by omega
    rw [he, pow_succ']
  rw [hpow, sum_range_two_mul, Finset.sum_add_distrib]
  congr 1
  · refine Finset.sum_congr rfl (fun i _ => ?_)
    have hs := ca_split (F := F) (n := n) k hk1 ch X i 0 (by norm_num)
    simp only [Nat.add_zero] at hs
    rw [hs]; norm_num
  · refine Finset.sum_congr rfl (fun i _ => ?_)
    rw [ca_split (F := F) (n := n) k hk1 ch X i 1 (by norm_num)]
    norm_num

lemma ca_zero_split {n : ℕ} {F : Type} [Field F] (hn : 0 < n) (pref : Vector F 0) (i b : ℕ) (hb : b < 2) :
    construct_assignment (n := n) 0 hn pref (if b = 1 then (1:F) else 0) (boolean_vector i)
      = boolean_vector (2 * i + b) := by
  ext m hm
  simp only [construct_assignment, boolean_vector, Vector.getElem_ofFn]
  rcases Nat.eq_zero_or_pos m with h | h
  · subst h
    rw [dif_neg (by omega), dif_pos rfl]
    simp [bv_zero i b hb]
  · rw [dif_neg (by omega), dif_neg (by omega)]
    have hb2 : bit_value i (m - 1) = bit_value (2 * i + b) m := by
      have he : m = (m - 1) + 1 := by omega
      conv_rhs => rw [he]
      rw [bv_succ i b _ hb]
    simp [Vector.get, hb2]

lemma head_eval_hypercube {n : ℕ} {F : Type} [Field F] (f : Vector F n → F) (hn : 0 < n) (pref : Vector F 0) :
    sumcheck_eval_round f 0 hn pref 0 + sumcheck_eval_round f 0 hn pref 1
      = ∑ j ∈ Finset.range (2 ^ n), f (boolean_vector j) := by
  rw [sumcheck_eval_round_range, sumcheck_eval_round_range]
  have hpow : (2:ℕ) ^ n = 2 * 2 ^ (n - 0 - 1) := by
    have he : n = (n - 0 - 1) + 1 := by omega
    conv_lhs => rw [he]
    rw [pow_succ']
  rw [hpow, sum_range_two_mul, Finset.sum_add_distrib]
  congr 1
  · refine Finset.sum_congr rfl (fun i _ => ?_)
    have hs := ca_zero_split (F := F) (n := n) hn pref i 0 (by norm_num)
    norm_num at hs
    rw [hs]
  · refine Finset.sum_congr rfl (fun i _ => ?_)
    have hs := ca_zero_split (F := F) (n := n) hn pref i 1 (by norm_num)
    norm_num at hs
    rw [hs]

lemma consistent_of_pairwise {F : Type} [Field F] : ∀ (Ps : List (Polynomial F)) (rs : List F),
    (∀ k, k + 1 < Ps.length → k < rs.length →
      (Ps.getD (k+1) 0).eval 0 + (Ps.getD (k+1) 0).eval 1
        = (Ps.getD k 0).eval (rs.getD k 0)) →
    consistent_true_polys Ps rs := by
  intro Ps
  induction Ps with
  | nil => intro rs _; trivial
  | cons P1 Pt ih =>
    intro rs h
    cases Pt with
    | nil => cases rs <;> trivial
    | cons P2 Pt2 =>
      cases rs with
      | nil => trivial
      | cons r rt =>
        refine ⟨?_, ?_⟩
        · simpa using h 0 (by simp) (by simp)
        · refine ih rt (fun k hk hr => ?_)
          simpa using h (k+1) (by simpa using hk) (by simpa using hr)

lemma get_last_eval_ofFn {F : Type} [Field F] : ∀ (n : ℕ) (P : Fin (n+1) → Polynomial F) (rs : List F),
    rs.length = n + 1 →
    get_last_eval (List.ofFn P) rs = some ((P ⟨n, Nat.lt_succ_self n⟩).eval (rs.getD n 0)) := by
  intro n
  induction n with
  | zero =>
    intro P rs hrs
    obtain ⟨r, hr⟩ := List.length_eq_one_iff.mp hrs
    subst hr
    simp [List.ofFn_succ, get_last_eval]
  | succ n ih =>
    intro P rs hrs
    cases rs with
    | nil => simp at hrs
    | cons r rt =>
      have hrt : rt.length = n + 1 := by simpa using hrs
      rw [List.ofFn_succ, List.ofFn_succ]
      rw [show get_last_eval (P 0 :: (P (0:Fin (n+1)).succ :: List.ofFn fun i : Fin n => P i.succ.succ)) (r :: rt)
            = get_last_eval (P (0:Fin (n+1)).succ :: List.ofFn fun i : Fin n => P i.succ.succ) rt from ?_]
      · have hIH := ih (fun i : Fin (n+1) => P i.succ) rt hrt
        rw [List.ofFn_succ] at hIH
        rw [hIH]
        simp
      · cases rt with
        | nil => simp at hrt
        | cons s rs2 => rfl

lemma getD_ofFn {α : Type*} {m : ℕ} (g : Fin m → α) (k : ℕ) (h : k < m) (d : α) :
    (List.ofFn g).getD k d = g ⟨k, h⟩ := by
  rw [List.getD_eq_getElem _ _ (by simpa using h)]
  simp

/-- The length-`j` prefix of a challenge list, as a vector. -/
def chalVec {F : Type} [Field F] (chal : List F) (j : ℕ) : Vector F j :=
  Vector.ofFn (fun i : Fin j => chal.getD i.val 0)

lemma prefSucc_chalVec {F : Type} [Field F] (chal : List F) (k : ℕ) :
    prefSucc (chalVec chal k) (chal.getD k 0) = chalVec chal (k+1) := by
  ext m hm
  simp only [prefSucc, chalVec, Vector.getElem_ofFn]
  by_cases h : m < k
  · rw [dif_pos h]; simp [Vector.get]
  · rw [dif_neg h]
    have : m = k := by omega
    rw [this]

lemma head_generate {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] (f : Vector F n → F) (ch : Vector F n) (hn : 0 < n) :
    (generate_true_polys f ch).head!.eval 0 + (generate_true_polys f ch).head!.eval 1
      = ∑ j ∈ Finset.range (2 ^ n), f (boolean_vector j) := by
  obtain ⟨m, rfl⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  unfold generate_true_polys
  rw [List.ofFn_succ]
  simp only [List.head!_cons]
  rw [sumcheck_round_poly_eval, sumcheck_round_poly_eval]
  exact head_eval_hypercube f hn _

lemma consistent_generate {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] (f : Vector F n → F) (chal : List F) (_hlen : chal.length = n) :
    consistent_true_polys (generate_true_polys f (chalVec chal n)) chal := by
  apply consistent_of_pairwise
  intro k hk hr
  unfold generate_true_polys at hk ⊢
  simp only [List.length_ofFn] at hk
  rw [getD_ofFn _ _ (by omega), getD_ofFn _ _ (by omega),
      sumcheck_round_poly_eval, sumcheck_round_poly_eval, sumcheck_round_poly_eval]
  have hpref : ∀ j (hj : j < n), (Vector.ofFn fun i : Fin j => (chalVec chal n).get ⟨i.val, by omega⟩)
      = chalVec chal j := by
    intro j hj; ext i hi; simp [chalVec, Vector.get]
  rw [hpref k (by omega), hpref (k+1) (by omega), ← prefSucc_chalVec chal k]
  exact sumcheck_eval_round_split f k (by omega) (chalVec chal k) (chal.getD k 0)

lemma get_last_eval_generate {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] (f : Vector F n → F) (chal : List F)
    (_hlen : chal.length = n) (hn : 0 < n) :
    get_last_eval (generate_true_polys f (chalVec chal n)) chal = some (f (chalVec chal n)) := by
  obtain ⟨m, rfl⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  unfold generate_true_polys
  rw [get_last_eval_ofFn m _ chal (by omega)]
  congr 1
  rw [sumcheck_round_poly_eval]
  have hpref : (Vector.ofFn fun i : Fin m => (chalVec chal (m+1)).get ⟨i.val, by omega⟩)
      = chalVec chal m := by ext i hi; simp [chalVec, Vector.get]
  rw [hpref, sumcheck_eval_round_range]
  have hr : Finset.range (2 ^ (m + 1 - m - 1)) = Finset.range 1 := by
    congr 1
    rw [show m + 1 - m - 1 = 0 from by omega, pow_zero]
  rw [hr, Finset.sum_range_one]
  refine congrArg f ?_
  ext i hi
  simp only [construct_assignment, chalVec, Vector.getElem_ofFn]
  by_cases h : i < m
  · rw [dif_pos h]; simp [Vector.get]
  · rw [dif_neg h]
    have him : i = m := by omega
    rw [dif_pos him, him]


/-!
## The degree of the honest round polynomials

`combinatorial_fiat_shamir` needs `natDegree (P_func i pref) ≤ d`.  `sumcheck_round_poly` is
built from `lagrange_basis`, which is syntactically of degree `|F| - 1`, so that bound is not
free.  What is true — and what these lemmas establish — is that interpolation below `|F|` is
*unique*: if the round function agrees with a polynomial of degree `≤ d < |F|`, the
interpolant **is** that polynomial, so `d` can be taken from the arithmetization rather than
from the field size.
-/

/-- Each Lagrange basis polynomial has degree at most `|F| - 1`. -/
lemma lagrange_basis_natDegree {F : Type} [Field F] [Fintype F] [DecidableEq F] (a : F) :
    (lagrange_basis a).natDegree ≤ Fintype.card F - 1 := by
  rw [lagrange_basis]
  refine le_trans (Polynomial.natDegree_prod_le _ _) ?_
  calc ∑ x ∈ univ.erase a, ((X - Polynomial.C x) * Polynomial.C ((a - x)⁻¹)).natDegree
      ≤ ∑ _x ∈ univ.erase a, 1 := by
        refine Finset.sum_le_sum (fun x _ => ?_)
        refine le_trans (Polynomial.natDegree_mul_le) ?_
        simp
    _ = Fintype.card F - 1 := by
        simp [Finset.card_erase_of_mem, Finset.card_univ]

lemma sumcheck_round_poly_natDegree {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (f : Vector F n → F) (k : ℕ) (hk : k < n) (ch : Vector F k) :
    (sumcheck_round_poly f k hk ch).natDegree ≤ Fintype.card F - 1 := by
  rw [sumcheck_round_poly]
  refine Polynomial.natDegree_sum_le_of_forall_le _ _ (fun a _ => ?_)
  exact le_trans (Polynomial.natDegree_C_mul_le _ _) (lagrange_basis_natDegree a)

/--
**Interpolation is unique below `|F|`.**  If the round function agrees with a polynomial `g`
of degree `< |F|`, then `sumcheck_round_poly` *is* `g`.
-/
lemma sumcheck_round_poly_eq_of_agrees {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (f : Vector F n → F) (k : ℕ) (hk : k < n) (ch : Vector F k) (g : Polynomial F)
    (hdg : g.natDegree < Fintype.card F)
    (hag : ∀ a : F, g.eval a = sumcheck_eval_round f k hk ch a) :
    sumcheck_round_poly f k hk ch = g := by
  have hsub : sumcheck_round_poly f k hk ch - g = 0 := by
    refine eq_zero_of_natDegree_lt_card_of_eval_eq_zero' _ univ (fun a _ => ?_) ?_
    · rw [Polynomial.eval_sub, sumcheck_round_poly_eval, hag a, sub_self]
    · refine lt_of_le_of_lt (Polynomial.natDegree_sub_le _ _) ?_
      have hsr := sumcheck_round_poly_natDegree f k hk ch
      exact max_lt (lt_of_le_of_lt hsr (Nat.sub_lt Fintype.card_pos (by norm_num))) hdg
  exact sub_eq_zero.mp hsub

/-- **The degree bound, derived.** -/
lemma sumcheck_round_poly_natDegree_le {n : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (f : Vector F n → F) (k : ℕ) (hk : k < n) (ch : Vector F k) (g : Polynomial F) (d : ℕ)
    (hdg : g.natDegree ≤ d) (hd : d < Fintype.card F)
    (hag : ∀ a : F, g.eval a = sumcheck_eval_round f k hk ch a) :
    (sumcheck_round_poly f k hk ch).natDegree ≤ d := by
  rw [sumcheck_round_poly_eq_of_agrees f k hk ch g (by omega) hag]
  exact hdg

/-!
## Degree 2, derived

`combinatorial_fiat_shamir` is applied with a degree bound `d`; the implementation fixes it at
`2`, because the hand-round polynomial is `WPoly = Poly<3, Field>` — three evaluation points,
degree two (`sumcheck/circuit.h`).  That `2` is not a free parameter: the layer summand is
`EQ[Q,C] · QUAD[G|L,R] · W[L,C] · W[R,C]` with `QUAD` and `W` multilinear in the hand
variables, so binding one hand variable touches exactly two factors and leaves a quadratic.

This section turns that observation into `sumcheck_round_poly_natDegree_le_two`, which is what
`IsFiatShamirTranscript.hd` asks for.  Copy rounds are genuinely cubic (`CPoly = Poly<4>`);
the ZK path has none, since `zk_common.h:L72` asserts `logc == 0`.
-/

/-- Multilinear: freezing every coordinate but one leaves an affine function. -/
def IsMultilinear {n : ℕ} {F : Type} [Field F] (h : Vector F n → F) : Prop :=
  ∀ (v : Vector F n) (j : ℕ) (hj : j < n), ∃ a b : F, ∀ X : F, h (v.set j X hj) = a + b * X

/-- Quadratic in coordinate `j`: freezing every other coordinate leaves a degree-≤2 function. -/
def QuadraticAt {n : ℕ} {F : Type} [Field F] (h : Vector F n → F) (j : ℕ) (hj : j < n) : Prop :=
  ∀ v : Vector F n, ∃ a b c : F, ∀ X : F, h (v.set j X hj) = a + b * X + c * X ^ 2

/-- Quadratic: freezing every coordinate but one leaves a degree-≤2 function. -/
def IsQuadratic {n : ℕ} {F : Type} [Field F] (h : Vector F n → F) : Prop :=
  ∀ (j : ℕ) (hj : j < n), QuadraticAt h j hj

section closure
variable {n : ℕ} {F : Type} [Field F]

lemma IsMultilinear.const (k : F) : IsMultilinear (fun _ : Vector F n => k) :=
  fun _ _ _ => ⟨k, 0, fun _ => by ring⟩

lemma IsMultilinear.mul_const {h : Vector F n → F} (H : IsMultilinear h) (k : F) :
    IsMultilinear (fun v => h v * k) := by
  intro v j hj
  obtain ⟨a, b, hab⟩ := H v j hj
  exact ⟨a * k, b * k, fun X => by show h _ * k = _; rw [hab]; ring⟩

lemma IsMultilinear.sum {ι : Type} (s : Finset ι) (h : ι → Vector F n → F)
    (H : ∀ i, IsMultilinear (h i)) : IsMultilinear (fun v => ∑ i ∈ s, h i v) := by
  classical
  induction s using Finset.induction_on with
  | empty => intro v j hj; exact ⟨0, 0, fun X => by simp⟩
  | insert i s hi ih =>
      intro v j hj
      obtain ⟨a1, b1, h1⟩ := H i v j hj
      obtain ⟨a2, b2, h2⟩ := ih v j hj
      refine ⟨a1 + a2, b1 + b2, fun X => ?_⟩
      show ∑ i' ∈ insert i s, h i' _ = _
      rw [Finset.sum_insert hi, h1]
      have h2' := h2 X
      simp only [] at h2'
      rw [h2']; ring

/-- A product of two affine functions is quadratic.  This is the whole degree argument:
binding one hand variable of the layer polynomial touches exactly two factors. -/
lemma quadratic_of_two_affine {F : Type} [Field F] (K : F) (f g : F → F)
    (a1 b1 a2 b2 : F) (hf : ∀ X, f X = a1 + b1 * X) (hg : ∀ X, g X = a2 + b2 * X) :
    ∃ a b c : F, ∀ X : F, K * f X * g X = a + b * X + c * X ^ 2 :=
  ⟨K * a1 * a2, K * (a1 * b2 + b1 * a2), K * (b1 * b2), fun X => by rw [hf, hg]; ring⟩

end closure

section eqbasis
variable {n : ℕ} {F : Type} [Field F]

lemma eq_mle_basis_multilinear (i : ℕ) :
    IsMultilinear (fun x : Vector F n => eq_mle_basis i x) := by
  intro v j hj
  set jf : Fin n := ⟨j, hj⟩ with hjf
  set P : F := ∏ k ∈ (Finset.univ.erase jf),
      (if bit_value i k.val = 1 then v.get k else 1 - v.get k) with hP
  have key : ∀ X : F, eq_mle_basis i (v.set j X hj)
      = (if bit_value i j = 1 then X else 1 - X) * P := by
    intro X
    rw [eq_mle_basis, ← Finset.mul_prod_erase _ _ (Finset.mem_univ jf)]
    have hset : (v.set j X hj).get jf = X := by
      show (v.set j X hj)[j] = X
      rw [Vector.getElem_set hj hj]; simp
    have hrest : ∀ k ∈ Finset.univ.erase jf, (v.set j X hj).get k = v.get k := by
      intro k hk
      have hkne : k ≠ jf := (Finset.mem_erase.mp hk).1
      have hne : ¬ (j = k.val) := fun h => hkne (Fin.val_inj.mp h.symm)
      show (v.set j X hj)[k.val] = v[k.val]
      rw [Vector.getElem_set hj k.isLt, if_neg hne]
    rw [hset, hjf]
    exact congrArg _ (Finset.prod_congr rfl (fun k hk => by rw [hrest k hk]))
  by_cases hb : bit_value i j = 1
  · exact ⟨0, P, fun X => by show eq_mle_basis i _ = _; rw [key X, if_pos hb]; ring⟩
  · exact ⟨P, -P, fun X => by show eq_mle_basis i _ = _; rw [key X, if_neg hb]; ring⟩

end eqbasis

section extract
variable {logc logw : ℕ} {F : Type} [Field F]

lemma extract_vars_copy (cc : Vector F (logc + 2 * logw)) :
    (extract_vars cc).1 = Vector.ofFn (fun i : Fin logc => cc.get ⟨i.val, by omega⟩) := rfl

lemma extract_vars_l (cc : Vector F (logc + 2 * logw)) :
    (extract_vars cc).2.1 = Vector.ofFn (fun i : Fin logw => cc.get ⟨logc + i.val, by omega⟩) := rfl

lemma extract_vars_r (cc : Vector F (logc + 2 * logw)) :
    (extract_vars cc).2.2 = Vector.ofFn (fun i : Fin logw => cc.get ⟨logc + logw + i.val, by omega⟩) := rfl

/-- Setting a hand-`L` coordinate sets the corresponding coordinate of `L`. -/
lemma extract_set_L (cc : Vector F (logc + 2 * logw)) (j : ℕ) (hj : j < logc + 2 * logw)
    (hlo : logc ≤ j) (hhi : j < logc + logw) (X : F) :
    (extract_vars (cc.set j X hj)).2.1
      = (extract_vars cc).2.1.set (j - logc) X (by omega) := by
  rw [extract_vars_l, extract_vars_l]
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_set (by omega) ht, Vector.getElem_ofFn, Vector.getElem_ofFn]
  show (cc.set j X hj)[logc + t] = _
  rw [Vector.getElem_set hj (by omega)]
  by_cases h : j = logc + t
  · rw [if_pos h, if_pos (by omega)]
  · rw [if_neg h, if_neg (by omega)]; rfl

/-- Setting a hand-`R` coordinate leaves `L` alone. -/
lemma extract_set_L_const (cc : Vector F (logc + 2 * logw)) (j : ℕ) (hj : j < logc + 2 * logw)
    (hlo : logc + logw ≤ j) (X : F) :
    (extract_vars (cc.set j X hj)).2.1 = (extract_vars cc).2.1 := by
  rw [extract_vars_l, extract_vars_l]
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
  show (cc.set j X hj)[logc + t] = _
  rw [Vector.getElem_set hj (by omega), if_neg (by omega)]
  rfl

/-- Setting a hand-`R` coordinate sets the corresponding coordinate of `R`. -/
lemma extract_set_R (cc : Vector F (logc + 2 * logw)) (j : ℕ) (hj : j < logc + 2 * logw)
    (hlo : logc + logw ≤ j) (X : F) :
    (extract_vars (cc.set j X hj)).2.2
      = (extract_vars cc).2.2.set (j - logc - logw) X (by omega) := by
  rw [extract_vars_r, extract_vars_r]
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_set (by omega) ht, Vector.getElem_ofFn, Vector.getElem_ofFn]
  show (cc.set j X hj)[logc + logw + t] = _
  rw [Vector.getElem_set hj (by omega)]
  by_cases h : j = logc + logw + t
  · rw [if_pos h, if_pos (by omega)]
  · rw [if_neg h, if_neg (by omega)]; rfl

/-- Setting a hand-`L` coordinate leaves `R` alone. -/
lemma extract_set_R_const (cc : Vector F (logc + 2 * logw)) (j : ℕ) (hj : j < logc + 2 * logw)
    (hhi : j < logc + logw) (X : F) :
    (extract_vars (cc.set j X hj)).2.2 = (extract_vars cc).2.2 := by
  rw [extract_vars_r, extract_vars_r]
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
  show (cc.set j X hj)[logc + logw + t] = _
  rw [Vector.getElem_set hj (by omega), if_neg (by omega)]
  rfl

/-- Setting a hand coordinate leaves the copy block alone. -/
lemma extract_set_copy_const (cc : Vector F (logc + 2 * logw)) (j : ℕ) (hj : j < logc + 2 * logw)
    (hlo : logc ≤ j) (X : F) :
    (extract_vars (cc.set j X hj)).1 = (extract_vars cc).1 := by
  rw [extract_vars_copy, extract_vars_copy]
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
  show (cc.set j X hj)[t] = _
  rw [Vector.getElem_set hj (by omega), if_neg (by omega)]
  rfl

end extract

section layerquad
variable {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]

lemma layer_sumcheck_poly_concat_eq
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F) (alpha : F)
    (q : Vector F logc) (g0 g1 : Vector F logv) (cc : Vector F (logc + 2 * logw)) :
    layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad W alpha q g0 g1 cc
      = layer_sumcheck_poly (nc := nc) (nv := nv) Quad W alpha q g0 g1
          (extract_vars cc).1 (extract_vars cc).2.1 (extract_vars cc).2.2 := rfl

/--
**Every hand round of a layer's sumcheck is quadratic.**

The summand is `EQ[Q,C] · QUAD[G|L,R] · W[L,C] · W[R,C]`.  Binding a hand variable freezes
the copy block, so `EQ[Q,C]` and one of the two `W` factors are constants; the other two —
`QUAD` and the remaining `W` — are affine by multilinearity.  A product of two affine
factors has degree 2, which is exactly what `WPoly = Poly<3, Field>` encodes.
-/
lemma layer_quadratic_at_hand
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F) (alpha : F)
    (q : Vector F logc) (g0 g1 : Vector F logv)
    (hQl : ∀ g r, IsMultilinear (fun l => Quad g l r))
    (hQr : ∀ g l, IsMultilinear (fun r => Quad g l r))
    (hW : ∀ copy, IsMultilinear (fun l => W l copy))
    (j : ℕ) (hj : j < logc + 2 * logw) (hlo : logc ≤ j) :
    QuadraticAt (layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad W alpha q g0 g1) j hj := by
  intro cc
  set cpy := (extract_vars cc).1 with hcpy
  set L := (extract_vars cc).2.1 with hLdef
  set R := (extract_vars cc).2.2 with hRdef
  set E : ℕ → F := fun i => eq_mle_basis i g0 + alpha * eq_mle_basis i g1 with hE
  have hcopy : ∀ X : F, (extract_vars (cc.set j X hj)).1 = cpy :=
    fun X => extract_set_copy_const cc j hj hlo X
  by_cases hcase : j < logc + logw
  · -- an `L` round: `QUAD(·, R)` and `W(·, C)` are affine, `W(R, C)` is constant
    have hLset : ∀ X : F, (extract_vars (cc.set j X hj)).2.1 = L.set (j - logc) X (by omega) :=
      fun X => extract_set_L cc j hj hlo hcase X
    have hRc : ∀ X : F, (extract_vars (cc.set j X hj)).2.2 = R :=
      fun X => extract_set_R_const cc j hj hcase X
    have hQQ : IsMultilinear
        (fun l => ∑ i ∈ Finset.range nv, Quad (boolean_vector i) l R * E i) :=
      IsMultilinear.sum _ _ (fun i => (hQl (boolean_vector i) R).mul_const (E i))
    obtain ⟨a1, b1, e1⟩ := hQQ L (j - logc) (by omega)
    obtain ⟨a2, b2, e2⟩ := hW cpy L (j - logc) (by omega)
    have e1' : ∀ X : F,
        (∑ i ∈ Finset.range nv,
          Quad (boolean_vector i) (L.set (j - logc) X (by omega)) R * E i) = a1 + b1 * X := e1
    have e2' : ∀ X : F, W (L.set (j - logc) X (by omega)) cpy = a2 + b2 * X := e2
    obtain ⟨a, b, c, hq⟩ := quadratic_of_two_affine
      (eq_matrix_mle nc logc q cpy * W R cpy)
      (fun X => ∑ i ∈ Finset.range nv,
        Quad (boolean_vector i) (L.set (j - logc) X (by omega)) R * E i)
      (fun X => W (L.set (j - logc) X (by omega)) cpy) a1 b1 a2 b2 e1' e2'
    refine ⟨a, b, c, fun X => ?_⟩
    rw [layer_sumcheck_poly_concat_eq, hcopy X, hLset X, hRc X, layer_sumcheck_poly, ← hq X]
    ring
  · -- an `R` round: `QUAD(L, ·)` and `W(·, C)` are affine, `W(L, C)` is constant
    have hRset : ∀ X : F,
        (extract_vars (cc.set j X hj)).2.2 = R.set (j - logc - logw) X (by omega) :=
      fun X => extract_set_R cc j hj (by omega) X
    have hLc : ∀ X : F, (extract_vars (cc.set j X hj)).2.1 = L :=
      fun X => extract_set_L_const cc j hj (by omega) X
    have hQQ : IsMultilinear
        (fun r => ∑ i ∈ Finset.range nv, Quad (boolean_vector i) L r * E i) :=
      IsMultilinear.sum _ _ (fun i => (hQr (boolean_vector i) L).mul_const (E i))
    obtain ⟨a1, b1, e1⟩ := hQQ R (j - logc - logw) (by omega)
    obtain ⟨a2, b2, e2⟩ := hW cpy R (j - logc - logw) (by omega)
    have e1' : ∀ X : F,
        (∑ i ∈ Finset.range nv,
          Quad (boolean_vector i) L (R.set (j - logc - logw) X (by omega)) * E i)
          = a1 + b1 * X := e1
    have e2' : ∀ X : F, W (R.set (j - logc - logw) X (by omega)) cpy = a2 + b2 * X := e2
    obtain ⟨a, b, c, hq⟩ := quadratic_of_two_affine
      (eq_matrix_mle nc logc q cpy * W L cpy)
      (fun X => ∑ i ∈ Finset.range nv,
        Quad (boolean_vector i) L (R.set (j - logc - logw) X (by omega)) * E i)
      (fun X => W (R.set (j - logc - logw) X (by omega)) cpy) a1 b1 a2 b2 e1' e2'
    refine ⟨a, b, c, fun X => ?_⟩
    rw [layer_sumcheck_poly_concat_eq, hcopy X, hRset X, hLc X, layer_sumcheck_poly, ← hq X]
    ring

/--
**The ZK path is quadratic in every coordinate.**  `zk_common.h:L72` asserts `logc == 0`, so
there are no copy rounds and every sumcheck variable is a hand variable.
-/
lemma layer_quadratic
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F 0 → F) (alpha : F)
    (q : Vector F 0) (g0 g1 : Vector F logv)
    (hQl : ∀ g r, IsMultilinear (fun l => Quad g l r))
    (hQr : ∀ g l, IsMultilinear (fun r => Quad g l r))
    (hW : ∀ copy, IsMultilinear (fun l => W l copy)) :
    IsQuadratic (layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad W alpha q g0 g1) :=
  fun j hj => layer_quadratic_at_hand Quad W alpha q g0 g1 hQl hQr hW j hj (Nat.zero_le j)

end layerquad

section rounddeg
variable {n : ℕ} {F : Type} [Field F]

/-- `construct_assignment` writes the free variable into coordinate `k`, so varying it is
literally a `Vector.set` at `k`. -/
lemma construct_assignment_set (k : ℕ) (hk : k < n) (pref : Vector F k) (X X0 : F)
    (suf : Vector F (n - k - 1)) :
    construct_assignment k hk pref X suf = (construct_assignment k hk pref X0 suf).set k X hk := by
  refine Vector.ext (fun t ht => ?_)
  rw [Vector.getElem_set hk ht]
  simp only [construct_assignment, Vector.getElem_ofFn]
  by_cases h : k = t
  · subst h
    rw [if_pos rfl, dif_neg (Nat.lt_irrefl k), dif_pos rfl]
  · rw [if_neg h]
    by_cases h1 : t < k
    · rw [dif_pos h1, dif_pos h1]
    · rw [dif_neg h1, dif_neg h1, dif_neg (fun hc => h hc.symm), dif_neg (fun hc => h hc.symm)]

/-- The round function of a coordinate-`k`-quadratic `f` is a quadratic in the free variable:
the hypercube sum of quadratics is quadratic. -/
lemma sumcheck_eval_round_quadratic (f : Vector F n → F) (k : ℕ) (hk : k < n)
    (hf : QuadraticAt f k hk) (ch : Vector F k) :
    ∃ a b c : F, ∀ X : F, sumcheck_eval_round f k hk ch X = a + b * X + c * X ^ 2 := by
  classical
  choose a b c habc using fun i : Fin (2 ^ (n - k - 1)) =>
    hf (construct_assignment k hk ch 0 (boolean_vector i.val))
  refine ⟨∑ i, a i, ∑ i, b i, ∑ i, c i, fun X => ?_⟩
  have hterm : ∀ i : Fin (2 ^ (n - k - 1)),
      f (construct_assignment k hk ch X (boolean_vector i.val))
        = a i + b i * X + c i * X ^ 2 := by
    intro i
    rw [construct_assignment_set k hk ch X 0, habc i X]
  rw [sumcheck_eval_round, Finset.sum_congr rfl (fun i _ => hterm i),
      Finset.sum_add_distrib, Finset.sum_add_distrib, ← Finset.sum_mul, ← Finset.sum_mul]

variable [Fintype F] [DecidableEq F]

/-- **The degree bound, at the value the implementation uses.**  `WPoly = Poly<3, Field>`
carries three evaluation points, i.e. degree 2; this is that number, derived. -/
lemma sumcheck_round_poly_natDegree_le_two (f : Vector F n → F) (k : ℕ) (hk : k < n)
    (ch : Vector F k) (hf : QuadraticAt f k hk) (h3 : 2 < Fintype.card F) :
    (sumcheck_round_poly f k hk ch).natDegree ≤ 2 := by
  obtain ⟨a, b, c, habc⟩ := sumcheck_eval_round_quadratic f k hk hf ch
  refine sumcheck_round_poly_natDegree_le f k hk ch
    (Polynomial.C a + Polynomial.C b * Polynomial.X + Polynomial.C c * Polynomial.X ^ 2) 2
    (by compute_degree) h3 (fun r => ?_)
  rw [habc r]; simp

/-- A field carrying a `SumcheckInterp` instance has at least three elements: `0`, `1` and
the interpolation point `pt2`.  This is exactly the `2 < |F|` the degree bound needs. -/
lemma three_le_card [SumcheckInterp F] : 2 < Fintype.card F := by
  classical
  have hne0 : (0 : F) ∉ ({1, (pt2 : F)} : Finset F) := by
    simp only [Finset.mem_insert, Finset.mem_singleton, not_or]
    exact ⟨zero_ne_one, Ne.symm SumcheckInterp.pt2_ne_zero⟩
  have hne1 : (1 : F) ∉ ({(pt2 : F)} : Finset F) := by
    simp only [Finset.mem_singleton]
    exact Ne.symm SumcheckInterp.pt2_ne_one
  have hcard : ({0, 1, (pt2 : F)} : Finset F).card = 3 := by
    rw [Finset.card_insert_of_notMem hne0, Finset.card_insert_of_notMem hne1,
        Finset.card_singleton]
  calc (2 : ℕ) < 3 := by norm_num
    _ = ({0, 1, (pt2 : F)} : Finset F).card := hcard.symm
    _ ≤ Fintype.card F := Finset.card_le_univ _

end rounddeg


/-- The claim the layer's sumcheck starts from: the layer polynomial summed over the
boolean hypercube, as a function of the combination coefficient `alpha`. -/
noncomputable def layer_claim {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F)
    (alpha : F) (q : Vector F logc) (g0 g1 : Vector F logv) : F :=
  ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
    layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad W alpha q g0 g1 (boolean_vector j)

lemma layer_poly_affine {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F)
    (alpha : F) (q : Vector F logc) (g0 g1 : Vector F logv)
    (copy : Vector F logc) (l r : Vector F logw) :
    layer_sumcheck_poly (nc := nc) (nv := nv) Quad W alpha q g0 g1 copy l r
      = layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 0 q g0 g1 copy l r
        + alpha * (layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 1 q g0 g1 copy l r
                   - layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 0 q g0 g1 copy l r) := by
  simp only [layer_sumcheck_poly]
  have h : ∀ a : F, (∑ i ∈ Finset.range nv, Quad (boolean_vector i) l r *
        (eq_mle_basis i g0 + a * eq_mle_basis i g1))
      = (∑ i ∈ Finset.range nv, Quad (boolean_vector i) l r * eq_mle_basis i g0)
        + a * (∑ i ∈ Finset.range nv, Quad (boolean_vector i) l r * eq_mle_basis i g1) := by
    intro a
    rw [Finset.mul_sum, ← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl (fun i _ => by ring)
  rw [h, h, h]
  ring

/-- The layer claim is **affine in `alpha`**: `S(alpha) = S(0) + alpha * (S(1) - S(0))`.
This is what makes the degenerate randomness countable. -/
lemma layer_claim_affine {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F)
    (alpha : F) (q : Vector F logc) (g0 g1 : Vector F logv) :
    layer_claim (nc := nc) (nv := nv) Quad W alpha q g0 g1
      = layer_claim (nc := nc) (nv := nv) Quad W 0 q g0 g1
        + alpha * (layer_claim (nc := nc) (nv := nv) Quad W 1 q g0 g1
                   - layer_claim (nc := nc) (nv := nv) Quad W 0 q g0 g1) := by
  simp only [layer_claim, layer_sumcheck_poly_concat]
  rw [Finset.sum_congr rfl (fun j _ => layer_poly_affine Quad W alpha q g0 g1 _ _ _),
      Finset.sum_add_distrib, ← Finset.mul_sum, Finset.sum_sub_distrib]


/-- The layer polynomial is affine in the `QUAD` coefficients, hence in the layer's `beta`. -/
lemma layer_poly_affine_quad {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Q Q0 Q1 : Vector F logv → Vector F logw → Vector F logw → F) (b : F)
    (hq : ∀ g l r, Q g l r = Q0 g l r + b * (Q1 g l r - Q0 g l r))
    (W : Vector F logw → Vector F logc → F) (alpha : F) (q : Vector F logc)
    (g0 g1 : Vector F logv) (copy : Vector F logc) (l r : Vector F logw) :
    layer_sumcheck_poly (nc := nc) (nv := nv) Q W alpha q g0 g1 copy l r
      = layer_sumcheck_poly (nc := nc) (nv := nv) Q0 W alpha q g0 g1 copy l r
        + b * (layer_sumcheck_poly (nc := nc) (nv := nv) Q1 W alpha q g0 g1 copy l r
               - layer_sumcheck_poly (nc := nc) (nv := nv) Q0 W alpha q g0 g1 copy l r) := by
  simp only [layer_sumcheck_poly]
  have h : (∑ i ∈ Finset.range nv, Q (boolean_vector i) l r *
        (eq_mle_basis i g0 + alpha * eq_mle_basis i g1))
      = (∑ i ∈ Finset.range nv, Q0 (boolean_vector i) l r *
          (eq_mle_basis i g0 + alpha * eq_mle_basis i g1))
        + b * ((∑ i ∈ Finset.range nv, Q1 (boolean_vector i) l r *
            (eq_mle_basis i g0 + alpha * eq_mle_basis i g1))
          - ∑ i ∈ Finset.range nv, Q0 (boolean_vector i) l r *
            (eq_mle_basis i g0 + alpha * eq_mle_basis i g1)) := by
    rw [show ∀ (u v : F), u + b * (v - u) = u + (b * v - b * u) from fun u v => by ring,
        Finset.mul_sum, Finset.mul_sum, ← Finset.sum_sub_distrib, ← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl (fun i _ => by rw [hq (boolean_vector i) l r]; ring)
  rw [h]; ring

/-- The layer *claim* is affine in the `QUAD` coefficients, hence in `beta`. -/
lemma layer_claim_affine_quad {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Q Q0 Q1 : Vector F logv → Vector F logw → Vector F logw → F) (b : F)
    (hq : ∀ g l r, Q g l r = Q0 g l r + b * (Q1 g l r - Q0 g l r))
    (W : Vector F logw → Vector F logc → F) (alpha : F) (q : Vector F logc)
    (g0 g1 : Vector F logv) :
    layer_claim (nc := nc) (nv := nv) Q W alpha q g0 g1
      = layer_claim (nc := nc) (nv := nv) Q0 W alpha q g0 g1
        + b * (layer_claim (nc := nc) (nv := nv) Q1 W alpha q g0 g1
               - layer_claim (nc := nc) (nv := nv) Q0 W alpha q g0 g1) := by
  simp only [layer_claim, layer_sumcheck_poly_concat]
  rw [Finset.sum_congr rfl (fun j _ => layer_poly_affine_quad Q Q0 Q1 b hq W alpha q g0 g1 _ _ _),
      Finset.sum_add_distrib, ← Finset.mul_sum, Finset.sum_sub_distrib]

/-! ### The data an arithmetization is built from -/

/-- `prep_v` (`quad.h:L213`): a gate whose coefficient is `0` is an *assert-zero* gate, and
takes the layer's fresh random `beta` instead. -/
def prepV {F : Type} [Field F] [DecidableEq F] (v b : F) : F := if v = 0 then b else v

omit [Fintype F] in
/-- `prepV` is affine in `beta` — which is what makes the layer claim affine in it. -/
lemma prepV_affine {F : Type} [Field F] [DecidableEq F] (v b : F) :
    prepV v b = prepV v 0 + b * (prepV v 1 - prepV v 0) := by
  by_cases h : v = 0 <;> simp [prepV, h]

/--
One gate of `Quad<Field>`: an output corner `g`, two hand corners `h0`, `h1`, and a
coefficient `v`.  A coefficient of `0` marks an *assert-zero* gate, which `prep_v` replaces by
the layer's `beta`.

The list is **sparse**: a triple that is simply absent contributes nothing.  That is the
distinction a dense table cannot make — an absent gate and an explicit zero-coefficient gate
would both read as `0`, and `prep_v` would turn the former into a phantom `beta` term.
-/
structure GateTerm (F : Type) where
  g : ℕ
  h0 : ℕ
  h1 : ℕ
  v : F

/-- `Quad<Field>` as a multilinear extension of its **sparse** gate list.  `bind_g` iterates
the stored terms and applies `prep_v` to each (`quad.h:L171`; `hquad.rs` `for_each_term`);
absent triples never enter the sum. -/
noncomputable def quadMle {logv logw : ℕ} {F : Type} [Field F] [DecidableEq F]
    (gates : List (GateTerm F)) (b : F)
    (gv : Vector F logv) (l r : Vector F logw) : F :=
  ∑ i : Fin gates.length,
    prepV (gates.get i).v b * eq_mle_basis (gates.get i).g gv
      * eq_mle_basis (gates.get i).h0 l * eq_mle_basis (gates.get i).h1 r

/-- The full input wire vector: public wires from the verifier's own data, private wires from
the Ligero commitment.  `ZkCommon::input_constraint` splits exactly here — `i < npub` is
folded into the constant term, `i ≥ npub` becomes a committed column
(`zk_common.h:L414-L418`). -/
def wCol {ninp : ℕ} {F : Type} [Field F] (npub : ℕ) (pub priv : Fin ninp → F)
    (i : Fin ninp) : F :=
  if i.val < npub then pub i else priv i

/-- The multilinear extension of `wCol` in the hand variables, matching `Eqs<Field>::at`
(`arrays/eq.h`) and `Dense::bind_all`. -/
noncomputable def wMle {ninp logw : ℕ} {F : Type} [Field F] (npub : ℕ)
    (pub priv : Fin ninp → F) (g : Vector F logw) : F :=
  ∑ i : Fin ninp, eq_mle_basis i.val g * wCol npub pub priv i

/--
**Structure: ArithmetizedCircuit**

The data of a circuit arithmetization, and the one property of it the soundness proof needs.

Everything except `arith` is *data*, not an assumption: `Quad_mle` and `W_mle` are
*constructed* below as multilinear extensions of the gate table and the wire vector, so
their multilinearity, their affineness in the layer's `beta`, and the fact that the public
wires do not depend on the witness are all theorems.

* `gates c` — the sparse gate list of `Quad<Field>`.  A term with coefficient `0` is an
  assert-zero gate (`compiler.h:L177`), which `prepV` replaces by the layer's random `beta`;
  a triple absent from the list contributes nothing.
* `pub_col` — the public input wires, which the verifier supplies.
* `priv_col` — the private input wires, which Ligero commits and the extractor returns.

`arith` is the one assumption: the arithmetization faithfully encodes `eval`.  It says an
unsatisfied circuit has a claim that is non-zero at one of the four corners of
`(alpha, beta) ∈ {0,1}²` — equivalently, that the bilinear form `S(alpha, beta)` is not
identically zero.  This is the correctness of the circuit compiler
(`QuadCircuit::mkcircuit`), which is not modelled here.
-/
structure ArithmetizedCircuit (Circuit Input Witness : Type) (nc nv ninp npub logv logw logc : ℕ) (F : Type) [Field F] [Fintype F] [DecidableEq F] where
  eval : Circuit → Input → Witness → Bool
  gates : Circuit → List (GateTerm F)
  pub_col : Input → Vector F logc → Fin ninp → F
  priv_col : Witness → Vector F logc → Fin ninp → F
  arith : ∀ (c : Circuit) (inp : Input) (w : Witness)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv),
    eval c inp w = false →
    ¬ (layer_claim (nc := nc) (nv := nv) (quadMle (logv := logv) (logw := logw) (gates c) 0)
          (fun (g : Vector F logw) (cp : Vector F logc) => wMle npub (pub_col inp cp) (priv_col w cp) g) 0 q_challenge g0 g1 = 0 ∧
       layer_claim (nc := nc) (nv := nv) (quadMle (logv := logv) (logw := logw) (gates c) 0)
          (fun (g : Vector F logw) (cp : Vector F logc) => wMle npub (pub_col inp cp) (priv_col w cp) g) 1 q_challenge g0 g1 = 0 ∧
       layer_claim (nc := nc) (nv := nv) (quadMle (logv := logv) (logw := logw) (gates c) 1)
          (fun (g : Vector F logw) (cp : Vector F logc) => wMle npub (pub_col inp cp) (priv_col w cp) g) 0 q_challenge g0 g1 = 0 ∧
       layer_claim (nc := nc) (nv := nv) (quadMle (logv := logv) (logw := logw) (gates c) 1)
          (fun (g : Vector F logw) (cp : Vector F logc) => wMle npub (pub_col inp cp) (priv_col w cp) g) 1 q_challenge g0 g1 = 0)

/-- `Quad<Field>` after `prep_v`, as a function of the layer's `beta`. -/
noncomputable def ArithmetizedCircuit.Quad_mle {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (b : F) : Vector F logv → Vector F logw → Vector F logw → F :=
  quadMle (AC.gates c) b

/-- The input wire vector at a copy point. -/
def ArithmetizedCircuit.W_col {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w : Witness) (copy : Vector F logc) : Fin ninp → F :=
  wCol npub (AC.pub_col inp copy) (AC.priv_col w copy)

/-- Its multilinear extension in the hand variables. -/
noncomputable def ArithmetizedCircuit.W_mle {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w : Witness) (g : Vector F logw) (copy : Vector F logc) : F :=
  wMle npub (AC.pub_col inp copy) (AC.priv_col w copy) g

/-- **`W_mle` is a multilinear extension** — definitional, formerly the field
`W_mle_is_mle`. -/
lemma ArithmetizedCircuit.W_mle_is_mle {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w : Witness) (g : Vector F logw) (copy : Vector F logc) :
    AC.W_mle inp w g copy = ∑ i : Fin ninp, eq_mle_basis i.val g * AC.W_col inp w copy i := rfl

/-- **The public wires do not depend on the witness** — definitional, because the wire
vector *is* `pub ++ priv`.  The extractor returns `priv_col` only; the public half is the
verifier's own data. -/
lemma ArithmetizedCircuit.W_col_pub {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w w' : Witness) (copy : Vector F logc) (i : Fin ninp) (hi : i.val < npub) :
    AC.W_col inp w copy i = AC.W_col inp w' copy i := by
  simp [ArithmetizedCircuit.W_col, wCol, hi]

/-!
### The degree of *this* circuit's round polynomials

`d` is not an independent knob: it is read off the arithmetization.  `W_mle_is_mle` already
says `W_mle` is a multilinear extension, so its multilinearity is a theorem; `Quad_mle`'s is
the one assumption.  Together they give `natDegree ≤ 2` for every hand round, which is
`IsFiatShamirTranscript.hd` at `d = 2`.
-/

/-- **`W_mle` is multilinear**, because it is a multilinear extension. -/
lemma ArithmetizedCircuit.W_mle_multilinear {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w : Witness) (copy : Vector F logc) :
    IsMultilinear (fun l => AC.W_mle inp w l copy) := by
  have h : (fun l => AC.W_mle inp w l copy)
      = fun l => ∑ i : Fin ninp, eq_mle_basis i.val l * AC.W_col inp w copy i :=
    funext (fun l => AC.W_mle_is_mle inp w l copy)
  rw [h]
  exact IsMultilinear.sum _ _ (fun i => (eq_mle_basis_multilinear i.val).mul_const _)

/-- **`Quad_mle` is multilinear in the left hand** — derived, because it *is* a multilinear
extension of the gate list.  This was the assumption `Quad_mle_ml_l`. -/
lemma ArithmetizedCircuit.Quad_mle_ml_l {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (b : F) (g : Vector F logv) (r : Vector F logw) :
    IsMultilinear (fun l => AC.Quad_mle c b g l r) := by
  have h : (fun l => AC.Quad_mle c b g l r)
      = fun l => ∑ i : Fin (AC.gates c).length,
          eq_mle_basis ((AC.gates c).get i).h0 l
            * (prepV ((AC.gates c).get i).v b * eq_mle_basis ((AC.gates c).get i).g g
                * eq_mle_basis ((AC.gates c).get i).h1 r) := by
    funext l
    simp only [ArithmetizedCircuit.Quad_mle, quadMle]
    exact Finset.sum_congr rfl (fun i _ => by ring)
  rw [h]
  exact IsMultilinear.sum _ _ (fun i => (eq_mle_basis_multilinear _).mul_const _)

/-- **`Quad_mle` is multilinear in the right hand.**  This was the assumption
`Quad_mle_ml_r`. -/
lemma ArithmetizedCircuit.Quad_mle_ml_r {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (b : F) (g : Vector F logv) (l : Vector F logw) :
    IsMultilinear (fun r => AC.Quad_mle c b g l r) := by
  have h : (fun r => AC.Quad_mle c b g l r)
      = fun r => ∑ i : Fin (AC.gates c).length,
          eq_mle_basis ((AC.gates c).get i).h1 r
            * (prepV ((AC.gates c).get i).v b * eq_mle_basis ((AC.gates c).get i).g g
                * eq_mle_basis ((AC.gates c).get i).h0 l) := by
    funext r
    simp only [ArithmetizedCircuit.Quad_mle, quadMle]
    exact Finset.sum_congr rfl (fun i _ => by ring)
  rw [h]
  exact IsMultilinear.sum _ _ (fun i => (eq_mle_basis_multilinear _).mul_const _)

/-- **`Quad_mle` is affine in the layer's `beta`**, because `prep_v` is: a stored assert-zero
gate contributes `beta · (…)` and every other stored gate contributes a constant.  Absent
gates contribute nothing at all. -/
lemma ArithmetizedCircuit.Quad_mle_affine_beta {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (b : F) (g : Vector F logv) (l r : Vector F logw) :
    AC.Quad_mle c b g l r
      = AC.Quad_mle c 0 g l r + b * (AC.Quad_mle c 1 g l r - AC.Quad_mle c 0 g l r) := by
  simp only [ArithmetizedCircuit.Quad_mle, quadMle, Finset.mul_sum, ← Finset.sum_sub_distrib,
    ← Finset.sum_add_distrib]
  refine Finset.sum_congr rfl (fun i _ => ?_)
  rw [prepV_affine ((AC.gates c).get i).v b]; ring

/-- **The layer polynomial of a ZK layer is quadratic in every sumcheck coordinate.**
`logc = 0` on the ZK path (`zk_common.h:L72`), so there are no cubic copy rounds. -/
lemma ArithmetizedCircuit.layer_quadratic {nc nv ninp npub logv logw : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q : Vector F 0)
    (g0 g1 : Vector F logv) :
    IsQuadratic (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
      (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1) :=
  _root_.layer_quadratic (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1
    (AC.Quad_mle_ml_l c beta) (AC.Quad_mle_ml_r c beta) (AC.W_mle_multilinear inp w)

/--
**`d = 2`, derived.**

Every honest round polynomial of a ZK layer has `natDegree ≤ 2` — the degree
`WPoly = Poly<3, Field>` encodes.  Supplying this to `IsFiatShamirTranscript.hd` is what
removes `d` from the list of inputs; see `fsOfArithmetized` in `fiat_shamir.lean`.
-/
theorem ArithmetizedCircuit.round_poly_natDegree_le_two {nc nv ninp npub logv logw : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q : Vector F 0)
    (g0 g1 : Vector F logv) (k : ℕ) (hk : k < 0 + 2 * logw) (ch : Vector F k) :
    (sumcheck_round_poly (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
      (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1) k hk ch).natDegree ≤ 2 :=
  sumcheck_round_poly_natDegree_le_two _ k hk ch
    (AC.layer_quadratic c inp w alpha beta q g0 g1 k hk) three_le_card

/--
**Degenerate layer randomness.**

The verifier combines the two inherited claims as `claim[0] + alpha * claim[1]`
(`verifier_layers.h:L147`) and replaces the coefficient of every assert-zero gate by `beta`
(`prep_v`, `quad.h:L213`).  Both are fresh challenges drawn by `begin_layer`
(`transcript_sumcheck.h:L54`), and the honest claim `S(alpha, beta)` is affine in each, hence
a *bilinear form*.  An unlucky pair can collapse a non-zero claim to zero, and then the
sumcheck starts from a true claim of `0` even though the circuit is unsatisfied.

This is a counted event, not an assumption: `arith` says `S` is not identically zero, and
`bilinear_zero_card` bounds its zero set by `2·|F|` out of `|F|²`.
-/
def ArithmetizedCircuit.Degenerate {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q_challenge : Vector F logc)
    (g0 g1 : Vector F logv) : Prop :=
  layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1
    = 0

/-- Away from degenerate randomness, an unsatisfied circuit really does give a non-zero
starting claim. -/
lemma ArithmetizedCircuit.claim_ne_zero {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness)
    (alpha beta : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (hgood : ¬ AC.Degenerate c inp w alpha beta q_challenge g0 g1) :
    (0 : F) ≠ layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha
      q_challenge g0 g1 := fun h => hgood h.symm

/--
**The sumcheck-reduction interface, derived.**

This used to be the `soundness` *field* of `ArithmetizedCircuit`, bundling four assumptions
about the honest round polynomials.  Three of them (`consistent_true_polys`, the round-0
sum, `get_last_eval`) are now theorems about `generate_true_polys`; only the arithmetization
statement `arith` remains an assumption.
-/
theorem ArithmetizedCircuit.soundness {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness)
    (t : Transcript F) (alpha beta : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (target : F)
    (hgood : ¬ AC.Degenerate c inp w alpha beta q_challenge g0 g1)
    (hpos : 0 < logc + 2 * logw)
    (hlen1 : t.polys.length = logc + 2 * logw)
    (hlen2 : t.challenges.length = logc + 2 * logw)
    (htarget : target = layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1 (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0)) :
    ∃ (P_first : Polynomial F) (P_rest : List (Polynomial F)),
      generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) = P_first :: P_rest ∧
      List.length (P_first :: P_rest) = t.polys.length ∧
      t.challenges.length = t.polys.length ∧
      consistent_true_polys (P_first :: P_rest) t.challenges ∧
      0 ≠ P_first.eval 0 + P_first.eval 1 ∧
      get_last_eval (P_first :: P_rest) t.challenges = some target := by
  set n := logc + 2 * logw with hn
  set f := layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1 with hf
  have hchal : (Vector.ofFn (n := n) fun i => t.challenges.getD i.val 0) = chalVec t.challenges n := rfl
  -- the generated list is non-empty
  obtain ⟨m, hm⟩ : ∃ m, n = m + 1 := ⟨n - 1, by omega⟩
  have hne : generate_true_polys f (chalVec t.challenges n) ≠ [] := by
    intro h0
    have := congrArg List.length h0
    simp [generate_true_polys] at this
    omega
  obtain ⟨P_first, P_rest, hsplit⟩ : ∃ P Ps, generate_true_polys f (chalVec t.challenges n) = P :: Ps := by
    cases hcs : generate_true_polys f (chalVec t.challenges n) with
    | nil => exact absurd hcs hne
    | cons P Ps => exact ⟨P, Ps, rfl⟩
  refine ⟨P_first, P_rest, by rw [hchal]; exact hsplit, ?_, ?_, ?_, ?_, ?_⟩
  · rw [← hsplit, hlen1]
    simp [generate_true_polys, hn]
  · rw [hlen1, hlen2]
  · rw [← hsplit]; exact consistent_generate f t.challenges hlen2
  · have hh : P_first = (generate_true_polys f (chalVec t.challenges n)).head! := by rw [hsplit]; rfl
    rw [hh, head_generate f (chalVec t.challenges n) (by omega)]
    exact AC.claim_ne_zero c inp w alpha beta q_challenge g0 g1 hgood
  · rw [← hsplit, get_last_eval_generate f t.challenges hlen2 (by omega), htarget, hchal]

-- Now `circuit_true_polys` is just `generate_true_polys` applied to the layer polynomial
noncomputable def circuit_true_polys {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
  (c : Circuit) (inp : Input) (w : Witness) (t : Transcript F)
  (alpha beta : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) : List (Polynomial F) :=
  generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0)


/-!
## Splitting a transcript's challenge vector

The verifier reads `logc` copy challenges (`challenge->cb`) followed by the hand challenges
(`challenge->hb[0]`, `challenge->hb[1]`).  These three blocks are what the final layer
identity `got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` (`verifier_layers.h:L176-L185`) is
evaluated at, and they are also the points at which `ZkCommon::input_constraint` binds the
committed witness columns.

(Modelling note: the implementation interleaves the two hands — `for (round) for (hand)` —
while `extract_vars` takes them as two contiguous blocks.  That is a permutation of the
challenge indexing and is a separate discrepancy from the binding question handled here.)
-/

/-- The copy point and the two hand points of a transcript's challenge list. -/
noncomputable def challenge_split {logw logc : ℕ} {F : Type} [Field F] (chal : List F) :
    Vector F logc × Vector F logw × Vector F logw :=
  extract_vars (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)

/-- The honest evaluations `W[L,C]` and `W[R,C]` of the extracted witness at the
transcript's own challenge point.  These are the values `Transcript.checkV` compares the
prover's claims against. -/
noncomputable def true_evals {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
  (inp : Input) (w : Witness) (chal : List F) : F × F :=
  let s := challenge_split (logw := logw) (logc := logc) chal
  (AC.W_mle inp w s.2.1 s.1, AC.W_mle inp w s.2.2 s.1)

/-- The coefficients `b_i = eq0.at(i) + alpha * eq1.at(i)` that `ZkCommon::input_constraint`
places on the committed input columns (`zk_common.h:L415`), at a transcript's own hand
challenge points. -/
noncomputable def input_row_coeffs {ninp logw logc : ℕ} {F : Type} [Field F]
    (alpha : F) (chal : List F) : Fin ninp → F :=
  fun i =>
    eq_mle_basis i.val (challenge_split (logw := logw) (logc := logc) chal).2.1
      + alpha * eq_mle_basis i.val (challenge_split (logw := logw) (logc := logc) chal).2.2

/-- The scalar `EQQ = EQ[Q,C] * QUAD[G|R,L]` that the verifier recomputes at the end of a
layer.  **Code Reference**: `Elt eqq = F.mulf(eqv, quad)` at `zk_common.h:L109-L111`,
matching `got = Eq<Field>::eval(...) * EQUAD->scalar()` at `verifier_layers.h:L176-L178`.

This is a verifier-side computation, not a prover claim, so callers instantiate the `eqq`
parameter of `Transcript.checkV` with it rather than assuming anything about it. -/
noncomputable def layer_eqq {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
  (c : Circuit) (alpha beta : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
  (chal : List F) : F :=
  let s := challenge_split (logw := logw) (logc := logc) chal
  eq_matrix_mle nc logc q_challenge s.1 *
    ∑ i ∈ Finset.range nv, AC.Quad_mle c beta (boolean_vector i) s.2.1 s.2.2 *
      (eq_mle_basis i g0 + alpha * eq_mle_basis i g1)

/--
The layer polynomial evaluated at a transcript's challenge point factors as
`EQQ * W[L,C] * W[R,C]`.

This is the identity that used to be assumed as `IsBoundTranscript.final_binding`.  It is
now a definitional unfolding: `layer_eqq` *is* the verifier's `EQQ` and `true_evals` *are*
the honest witness evaluations.  All the content moved to `input_row_binds_hands`, which
proves the prover's *claimed* evaluations equal these honest ones.
-/
lemma layer_poly_factors {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q_challenge : Vector F logc)
    (g0 g1 : Vector F logv) (chal : List F) :
    layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q_challenge g0 g1
        (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)
      = layer_eqq AC c alpha beta q_challenge g0 g1 chal
          * (true_evals AC inp w chal).1 * (true_evals AC inp w chal).2 := by
  rfl


/--
**Structure: IsSumcheckCorrelationIntractable**

Formalizes the property that the sumcheck protocol transcript is correlation intractable under
the Fiat-Shamir heuristic, bounding the number of challenge sequences leading to a bad event by `eps_sumcheck`.

**Combinatorial Justification:**
In `sumcheck_soundness.lean`, we prove `combinatorial_fiat_shamir`,
which establishes that for any `IsFiatShamirTranscript`, the total number of cheating challenge sequences
across all rounds is bounded by `n * d * |F|^(n-1)`, without any probability or random oracle axioms.
-/
structure IsSumcheckCorrelationIntractable {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
  (accepts : Ω → Prop)
  (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
  (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
  (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) (eps_sumcheck : ℕ) : Prop where
  ci_bound : event_card (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    multi_round_bad_event (circuit_true_polys AC c inp w ((T_p ω).decrypt pad var_dwR var_dwL (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2) (alpha ω) (beta ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ) ≤ eps_sumcheck

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


/--
**The converse: the honest prover's assignment satisfies the row.**

`builder_finalize_soundness` runs the row *forwards* — the row plus the quadratic pad
relation force the final claim.  Zero-knowledge needs the other direction: an honest prover,
whose final claim really is `EQQ · W[L] · W[R]`, produces an assignment the row accepts.

Both are the same algebraic identity, so the proof is the same rearrangement.
-/
theorem builder_finalize_complete {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e : Expression M F) (pad : Fin M → F)
    (eqq : F) (wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) :
    (pad var_dwL_dwR = pad var_dwL * pad var_dwR) →
    evaluates_to e pad = eqq * (wc0 + pad var_dwL) * (wc1 + pad var_dwR) →
    (∑ i, (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).1 i * pad i)
      = (builder_finalize e eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR).2 := by
  intro h_quad h_claim
  dsimp [builder_finalize, evaluates_to] at *
  have h_lhs : (fun i => (if i = var_dwL_dwR then (if i = var_dwR then (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i) - eqq * wc0 else (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i)) - eqq else (if i = var_dwR then (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i) - eqq * wc0 else (if i = var_dwL then e.2 i - eqq * wc1 else e.2 i))) * pad i) = fun i => e.2 i * pad i - (if i = var_dwL then eqq * wc1 * pad i else 0) - (if i = var_dwR then eqq * wc0 * pad i else 0) - (if i = var_dwL_dwR then eqq * pad i else 0) := by
    ext i
    split_ifs <;> ring
  rw [h_lhs, Finset.sum_sub_distrib, Finset.sum_sub_distrib, Finset.sum_sub_distrib]
  have h_sum1 : (∑ i : Fin M, (if i = var_dwL then eqq * wc1 * pad i else 0))
      = eqq * wc1 * pad var_dwL := by simp
  have h_sum2 : (∑ i : Fin M, (if i = var_dwR then eqq * wc0 * pad i else 0))
      = eqq * wc0 * pad var_dwR := by simp
  have h_sum3 : (∑ i : Fin M, (if i = var_dwL_dwR then eqq * pad i else 0))
      = eqq * pad var_dwL_dwR := by simp
  rw [h_sum1, h_sum2, h_sum3, h_quad]
  linear_combination h_claim

/-!
The pad-only `input_constraint_row` that used to live here has been removed.  It summed
over pad variables alone and so bound nothing about the extracted witness; it is superseded
by `ligero_input_row` in `ligero.lean`, which places its coefficients on the committed
input columns exactly as `ZkCommon::input_constraint` (`zk_common.h:L406`) does.
-/
