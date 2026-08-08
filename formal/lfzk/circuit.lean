import Mathlib
import sumcheck_soundness
import types
import fiat_shamir
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

/-- The claim the layer's sumcheck starts from: the layer polynomial summed over the
boolean hypercube, as a function of the combination coefficient `alpha`. -/
noncomputable def layer_claim {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)]
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F)
    (alpha : F) (q : Vector F logc) (g0 g1 : Vector F logv) : F :=
  ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
    layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad W alpha q g0 g1 (boolean_vector j)

lemma layer_poly_affine {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)]
    (Quad : Vector F logv → Vector F logw → Vector F logw → F)
    (W : Vector F logw → Vector F logc → F)
    (alpha : F) (q : Vector F logc) (g0 g1 : Vector F logv)
    (copy : Vector F logc) (l r : Vector F logw) :
    layer_sumcheck_poly (nc := nc) (nv := nv) Quad W alpha q g0 g1 copy l r
      = layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 0 q g0 g1 copy l r
        + alpha * (layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 1 q g0 g1 copy l r
                   - layer_sumcheck_poly (nc := nc) (nv := nv) Quad W 0 q g0 g1 copy l r) := by
  simp only [layer_sumcheck_poly]
  have h : ∀ a : F, (∑ g ∈ (Finset.univ : Finset (Vector F logv)), Quad g l r *
        (eq_matrix_mle nv logv g0 g + a * eq_matrix_mle nv logv g1 g))
      = (∑ g ∈ (Finset.univ : Finset (Vector F logv)), Quad g l r * eq_matrix_mle nv logv g0 g)
        + a * (∑ g ∈ (Finset.univ : Finset (Vector F logv)), Quad g l r * eq_matrix_mle nv logv g1 g) := by
    intro a
    rw [Finset.mul_sum, ← Finset.sum_add_distrib]
    exact Finset.sum_congr rfl (fun g _ => by ring)
  rw [h, h, h]
  ring

/-- The layer claim is **affine in `alpha`**: `S(alpha) = S(0) + alpha * (S(1) - S(0))`.
This is what makes the degenerate randomness countable. -/
lemma layer_claim_affine {nc nv logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)]
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


/--
**Structure: ArithmetizedCircuit**

An abstract mathematical specification of a circuit arithmetization in the Longfellow ZK protocol.
An `ArithmetizedCircuit` bundles the multilinear extension maps (`Quad_mle`, `W_mle`) and the arithmetization soundness
property as first-class fields of the circuit object.

This keeps the formal proof abstract and modular: any concrete compiler or DSL that generates
valid multilinear polynomials and satisfies the arithmetization soundness condition can instantiate this structure.

The hypotheses below are exactly the facts the verifier itself establishes about a transcript it accepts:

* `hlen_polys` / `hlen_challenges`: the verifier reads exactly one round
  polynomial and one challenge per sumcheck variable
  (`for (round = 0; round < logw; ++round) for (hand ...)` in
  `verifier_layers.h:L119`, plus `logc` copy rounds).
* `htarget`: `target` is the value the verifier's final layer identity
  `got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` (`verifier_layers.h:L176-L185`)
  pins the last claim to.  Callers instantiate it with `eqq * w_r_true * w_l_true`.
* `hgood`: the layer randomness is not degenerate — see `degenerate` below.
-/
structure ArithmetizedCircuit (Circuit Input Witness : Type) (nc nv ninp logv logw logc : ℕ) (F : Type) [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] where
  eval : Circuit → Input → Witness → Bool
  Quad_mle : Circuit → Vector F logv → Vector F logw → Vector F logw → F
  W_mle : Witness → Vector F logw → Vector F logc → F
  /--
  The input wire values that Ligero commits to, at a given copy point.

  `ZkCommon::input_constraint` (`zk_common.h:L406`) places its coefficients
  `b_i = eq0.at(i) + alpha * eq1.at(i)` on exactly these columns — that is what ties the
  extracted witness to the transcript.  Indices `i < npub` are the public wires; the rest
  are the committed private wires (`a.push_back(Llc{ci, i - pub_inputs, b_i})`).
  -/
  W_col : Witness → Vector F logc → Fin ninp → F
  /--
  `W_mle` is the multilinear extension of `W_col` in the hand variables, matching
  `Eqs<Field>::at` (`arrays/eq.h`) and `Dense::bind_all`.

  This is what makes the input constraint say something about `W_mle`, and hence about the
  final layer identity `CLAIM = EQQ * W[R,C] * W[L,C]`.
  -/
  W_mle_is_mle : ∀ (w : Witness) (g : Vector F logw) (copy : Vector F logc),
    W_mle w g copy = ∑ i : Fin ninp, eq_mle_basis i.val g * W_col w copy i
  /--
  **Arithmetization soundness.**  Unlike the previous version this no longer mentions the
  layer randomness at all: an unsatisfied circuit has a non-zero output *claim vector*
  `(S(0), S(1) - S(0))`, where `S` is the hypercube sum as a function of `alpha`.

  Everything the sumcheck reduction needs — `consistent_true_polys`, the round-0 sum, and
  `get_last_eval` — is derived from this in `ArithmetizedCircuit.soundness` below.
  -/
  arith : ∀ (c : Circuit) (inp : Input) (w : Witness)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv),
    eval c inp w = false →
    (layer_claim (nc := nc) (nv := nv) (Quad_mle c) (W_mle w) 0 q_challenge g0 g1 ≠ 0 ∨
      layer_claim (nc := nc) (nv := nv) (Quad_mle c) (W_mle w) 1 q_challenge g0 g1
        - layer_claim (nc := nc) (nv := nv) (Quad_mle c) (W_mle w) 0 q_challenge g0 g1 ≠ 0)

/--
**Degenerate layer randomness.**

The verifier combines the two inherited claims as `claim[0] + alpha * claim[1]`
(`verifier_layers.h:L147`).  Because the honest claim is affine in `alpha`
(`layer_claim_affine`), a single unlucky `alpha` can collapse a non-zero output claim vector
to zero — and then the sumcheck starts from a *true* claim of `0` even though the circuit is
unsatisfied, and nothing can be concluded.

This used to be an abstract `degenerate` field plus a hypothesis `¬ degenerate`.  It is now
concrete and `InputBindingBad`-shaped, so `input_binding_bad_card` bounds the bad set by one
element and `alpha_bad_card` turns it into a `1/|F|` error term.
-/
def ArithmetizedCircuit.Degenerate {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (w : Witness) (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) : Prop :=
  InputBindingBad
    (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) 0 q_challenge g0 g1)
    (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) 1 q_challenge g0 g1
      - layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) 0 q_challenge g0 g1)
    0 0 alpha

/-- Away from the degenerate `alpha`, an unsatisfied circuit really does give a non-zero
starting claim. -/
lemma ArithmetizedCircuit.claim_ne_zero {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness)
    (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (hev : AC.eval c inp w = false)
    (hgood : ¬ AC.Degenerate c w alpha q_challenge g0 g1) :
    (0 : F) ≠ layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1 := by
  intro hzero
  refine hgood ⟨AC.arith c inp w q_challenge g0 g1 hev, ?_⟩
  rw [← layer_claim_affine]
  linear_combination -hzero

/--
**The sumcheck-reduction interface, derived.**

This used to be the `soundness` *field* of `ArithmetizedCircuit`, bundling four assumptions
about the honest round polynomials.  Three of them (`consistent_true_polys`, the round-0
sum, `get_last_eval`) are now theorems about `generate_true_polys`; only the arithmetization
statement `arith` remains an assumption.
-/
theorem ArithmetizedCircuit.soundness {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (inp : Input) (w : Witness)
    (t : Transcript F) (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (target : F)
    (hev : AC.eval c inp w = false)
    (hgood : ¬ AC.Degenerate c w alpha q_challenge g0 g1)
    (hpos : 0 < logc + 2 * logw)
    (hlen1 : t.polys.length = logc + 2 * logw)
    (hlen2 : t.challenges.length = logc + 2 * logw)
    (htarget : target = layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1 (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0)) :
    ∃ (P_first : Polynomial F) (P_rest : List (Polynomial F)),
      generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) = P_first :: P_rest ∧
      List.length (P_first :: P_rest) = t.polys.length ∧
      t.challenges.length = t.polys.length ∧
      consistent_true_polys (P_first :: P_rest) t.challenges ∧
      0 ≠ P_first.eval 0 + P_first.eval 1 ∧
      get_last_eval (P_first :: P_rest) t.challenges = some target := by
  set n := logc + 2 * logw with hn
  set f := layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1 with hf
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
    exact AC.claim_ne_zero c inp w alpha q_challenge g0 g1 hev hgood
  · rw [← hsplit, get_last_eval_generate f t.challenges hlen2 (by omega), htarget, hchal]

-- Now `circuit_true_polys` is just `generate_true_polys` applied to the layer polynomial
noncomputable def circuit_true_polys {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
  (c : Circuit) (w : Witness) (t : Transcript F)
  (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) : List (Polynomial F) :=
  generate_true_polys (layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1) (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0)


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
noncomputable def true_evals {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
  (w : Witness) (chal : List F) : F × F :=
  let s := challenge_split (logw := logw) (logc := logc) chal
  (AC.W_mle w s.2.1 s.1, AC.W_mle w s.2.2 s.1)

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
noncomputable def layer_eqq {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
  (c : Circuit) (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
  (chal : List F) : F :=
  let s := challenge_split (logw := logw) (logc := logc) chal
  eq_matrix_mle nc logc q_challenge s.1 *
    ∑ g ∈ (Finset.univ : Finset (Vector F logv)), AC.Quad_mle c g s.2.1 s.2.2 *
      (eq_matrix_mle nv logv g0 g + alpha * eq_matrix_mle nv logv g1 g)

/--
The layer polynomial evaluated at a transcript's challenge point factors as
`EQQ * W[L,C] * W[R,C]`.

This is the identity that used to be assumed as `IsBoundTranscript.final_binding`.  It is
now a definitional unfolding: `layer_eqq` *is* the verifier's `EQQ` and `true_evals` *are*
the honest witness evaluations.  All the content moved to `input_row_binds_hands`, which
proves the prover's *claimed* evaluations equal these honest ones.
-/
lemma layer_poly_factors {nc nv ninp logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (w : Witness) (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (chal : List F) :
    layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w) alpha q_challenge g0 g1
        (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)
      = layer_eqq AC c alpha q_challenge g0 g1 chal
          * (true_evals AC w chal).1 * (true_evals AC w chal).2 := by
  rfl


/--
**Structure: IsSumcheckCorrelationIntractable**

Formalizes the property that the sumcheck protocol transcript is correlation intractable under
the Fiat-Shamir heuristic, bounding the number of challenge sequences leading to a bad event by `eps_sumcheck`.

**Combinatorial Justification:**
In `sumcheck_soundness.lean`, we prove `combinatorial_fiat_shamir` and `combinatorial_fiat_shamir_soundness`,
which establish that for any `IsFiatShamirTranscript`, the total number of cheating challenge sequences
across all rounds is bounded by `n * d * |F|^(n-1)`, without any probability or random oracle axioms.
-/
structure IsSumcheckCorrelationIntractable {nc nv ninp logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
  (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
  (accepts : Ω → Prop)
  (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
  (c : Circuit) (E_L : Ω → Option (AugmentedWitness M F Witness))
  (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv) (eps_sumcheck : ℕ) : Prop where
  ci_bound : event_card (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    multi_round_bad_event (circuit_true_polys AC c w ((T_p ω).decrypt pad var_dwR var_dwL (true_evals AC w (T_p ω).challenges).1 (true_evals AC w (T_p ω).challenges).2) (alpha ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ) ≤ eps_sumcheck

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


/-!
The pad-only `input_constraint_row` that used to live here has been removed.  It summed
over pad variables alone and so bound nothing about the extracted witness; it is superseded
by `ligero_input_row` in `ligero.lean`, which places its coefficients on the committed
input columns exactly as `ZkCommon::input_constraint` (`zk_common.h:L406`) does.
-/
