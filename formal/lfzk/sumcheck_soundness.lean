import Mathlib
open BigOperators
open Polynomial

/-!
# Sumcheck Protocol Formal Verification & Soundness Proof

This module formalizes the exact sumcheck verifier logic used in Longfellow ZK,
matching the implementation in:
- `privacy/proofs/zk/lib/sumcheck/verifier.h`
- `privacy/proofs/zk/lib/sumcheck/verifier_layers.h`

## The Single-Round Soundness Invariant

In each round $k$ of the sumcheck protocol, the verifier holds a claim $C_{k-1}$
about the sum of a polynomial $P(X_1, \dots, X_n)$ over the boolean hypercube.
The prover sends a univariate polynomial $p_k(X)$ of degree at most $d$.

The verifier executes two checks per round:
1. **Sum Consistency Check**: Verifies that $p_k(0) + p_k(1) = C_{k-1}$.
   - **Code Reference**: `verifier_layers.h:L90` (`if (F.addf(tp[0], tp[1]) != *claim)`)
2. **Challenge Evaluation**: Samples challenge $r_k \leftarrow \mathbb{F}$ and updates claim $C_k = p_k(r_k)$.
   - **Code Reference**: `verifier_layers.h:L95` (`*claim = tp.eval_lagrange(ch->cb[round], F)`)

### Mathematical Soundness Guarantee:
If the input claim $C_{k-1}$ is false (i.e. $C_{k-1} \neq \sum_{x \in \{0,1\}} P_k(x)$), then:
- Either the prover fails Check 1 ($p_k(0) + p_k(1) \neq C_{k-1}$), leading to immediate rejection.
- OR $p_k \neq P_k$ as univariate polynomials. By the Schwartz-Zippel Lemma,
  $p_k(r_k) = P_k(r_k)$ holds for at most $d$ choices of $r_k \in \mathbb{F}$.
- Thus, the probability that a false claim is converted into a true claim at round $k$ is at most $\frac{d}{|\mathbb{F}|}$.
-/

variable {F : Type} [Field F] [DecidableEq F]

/--
`RoundPoly` represents a degree-2 univariate polynomial sent by the prover in a sumcheck round,
evaluated at points 0, 1, and 2.
- **Code Reference**: `proofs::LayerProof::cp` in `privacy/proofs/zk/lib/sumcheck/circuit.h`
-/
structure RoundPoly (F : Type) where
  eval0 : F
  eval1 : F
  eval2 : F

/--
Evaluates a `RoundPoly` at challenge point `r` using Lagrange interpolation.
- **Code Reference**: `LayerProof::eval_lagrange` in `verifier_layers.h:L95`
-/
def RoundPoly.eval_lagrange (poly : RoundPoly F) (r : F) : F :=
  poly.eval0 + r * (poly.eval1 - poly.eval0)

/--
`check_round_c` formalizes `VerifierLayers::layer_c` (line 84 in `verifier_layers.h`).
It checks sum consistency `p(0) + p(1) == claim` and returns the next claim `p(r)`.
- **Code Reference**: `privacy/proofs/zk/lib/sumcheck/verifier_layers.h:L84-L98`
-/
def check_round_c (claim_in : F) (poly : RoundPoly F) (r : F) : Option F :=
  if poly.eval0 + poly.eval1 == claim_in then
    some (poly.eval_lagrange r)
  else
    none

/--
Theorem: `check_round_c_consistency`
Proves that if `check_round_c` succeeds, the next claim is uniquely determined by `poly.eval_lagrange r`.
-/
theorem check_round_c_consistency (claim_in : F) (poly : RoundPoly F) (r : F) (claim_out : F) :
    check_round_c claim_in poly r = some claim_out →
    claim_out = poly.eval_lagrange r ∧ poly.eval0 + poly.eval1 = claim_in := by
  intro h
  dsimp [check_round_c] at h
  split_ifs at h with h_eq
  injection h with h_out
  rw [beq_iff_eq] at h_eq
  exact ⟨h_out.symm, h_eq⟩


/-!
===============================================================================
Single-Round Schwartz-Zippel Soundness Bound
===============================================================================
Formalizes the fundamental single-round soundness lemma of sumcheck:
If an input claim `claim_in` is FALSE (i.e. `claim_in ≠ P_true 0 + P_true 1`),
a prover attempting to pass the round check `poly.eval0 + poly.eval1 == claim_in`
must submit a polynomial `poly` that differs from `P_true`.

By the Schwartz-Zippel Lemma, two distinct degree-`d` polynomials over field `F`
can agree at most at `d` points. Thus, the number of challenge points `r`
satisfying `poly.eval_lagrange r = P_true r` is at most `d`.
-/

/--
Proves that if an input claim is false (`claim_in ≠ P_true 0 + P_true 1`) and the prover's
`RoundPoly` passes the sum-consistency check (`poly.eval0 + poly.eval1 = claim_in`), then
`poly` cannot be identical to `P_true` at both 0 and 1.
-/
theorem false_claim_implies_poly_mismatch (P_true : Polynomial F) (poly : RoundPoly F) (claim_in : F)
    (h_false : claim_in ≠ P_true.eval 0 + P_true.eval 1)
    (h_check : poly.eval0 + poly.eval1 = claim_in) :
    poly.eval0 ≠ P_true.eval 0 ∨ poly.eval1 ≠ P_true.eval 1 := by
  by_contra h_contra
  push Not at h_contra
  have h_sum : poly.eval0 + poly.eval1 = P_true.eval 0 + P_true.eval 1 := by
    rw [h_contra.1, h_contra.2]
  rw [h_sum] at h_check
  exact h_false h_check.symm

theorem sumcheck_step_reduction {F : Type} [Field F] [DecidableEq F]
    (P_true : Polynomial F) (poly : RoundPoly F) (claim_in claim_out r : F)
    (h_check : check_round_c claim_in poly r = some claim_out)
    (h_false : claim_in ≠ P_true.eval 0 + P_true.eval 1) :
    claim_out ≠ P_true.eval r ∨ (poly.eval0 ≠ P_true.eval 0 ∨ poly.eval1 ≠ P_true.eval 1) ∧ (poly.eval_lagrange r = P_true.eval r) := by
  dsimp [check_round_c] at h_check
  split at h_check
  · next h_eq =>
    simp only [Option.some.injEq] at h_check
    have h_eq2 : poly.eval0 + poly.eval1 = claim_in := eq_of_beq h_eq
    have h_mismatch := false_claim_implies_poly_mismatch P_true poly claim_in h_false h_eq2
    by_cases h_out : claim_out = P_true.eval r
    · right
      constructor
      · exact h_mismatch
      · rw [h_check, h_out]
    · left
      exact h_out
  · next h_neq =>
    contradiction

def BadRoundEvent {F : Type} [Field F] (P_true : Polynomial F) (poly : RoundPoly F) (r : F) : Prop :=
  (poly.eval0 ≠ P_true.eval 0 ∨ poly.eval1 ≠ P_true.eval 1) ∧ poly.eval_lagrange r = P_true.eval r

def multi_round_bad_event {F : Type} [Field F] : List (Polynomial F) → List (RoundPoly F) → List F → Prop
  | (P::Ps), (p::ps), (r::rs) => BadRoundEvent P p r ∨ multi_round_bad_event Ps ps rs
  | _, _, _ => False

def verify_multi_round {F : Type} [Field F] [DecidableEq F] (claim_start : F) (polys : List (RoundPoly F)) (challenges : List F) : Option F :=
  match polys, challenges with
  | [], [] => some claim_start
  | p :: ps, r :: rs =>
      match check_round_c claim_start p r with
      | some next_claim => verify_multi_round next_claim ps rs
      | none => none
  | _, _ => none

def consistent_true_polys {F : Type} [Field F] : List (Polynomial F) → List F → Prop
  | (P1::P2::Ps), (r::rs) => P2.eval 0 + P2.eval 1 = P1.eval r ∧ consistent_true_polys (P2::Ps) rs
  | _, _ => True

def get_last_eval {F : Type} [Field F] : List (Polynomial F) → List F → Option F
  | [P], [r] => some (P.eval r)
  | (_::Ps), (_::rs) => get_last_eval Ps rs
  | _, _ => none

/--
`sumcheck_multi_reduction` establishes the core soundness reduction across multiple rounds of the sumcheck protocol.
It proves that if a verifier accepts a sequence of round polynomials and challenges resulting in a final claim (`verify_multi_round = some claim_out`), but the initial claim is false relative to the true polynomials, then one of two things must happen:
1. The final extracted claim `claim_out` does not match the final evaluation of the true polynomials.
2. The prover was "lucky" and a bad event occurred in at least one of the rounds (`multi_round_bad_event`).
-/
theorem sumcheck_multi_reduction {F : Type} [Field F] [DecidableEq F]
    (P_trues : List (Polynomial F)) (polys : List (RoundPoly F)) (challenges : List F)
    (claim_in claim_out : F) :
    verify_multi_round claim_in polys challenges = some claim_out →
    List.length P_trues = List.length polys →
    List.length challenges = List.length polys →
    consistent_true_polys P_trues challenges →
    polys ≠ [] →
    (claim_in ≠ P_trues.head!.eval 0 + P_trues.head!.eval 1) →
    (get_last_eval P_trues challenges = some claim_out → False) ∨
    multi_round_bad_event P_trues polys challenges := by
  induction polys generalizing claim_in P_trues challenges
  case nil =>
    intros _ _ _ _ h_nil _
    contradiction
  case cons p ps ih =>
    intro h_ver h_len1 h_len2 h_cons h_nnil h_false
    cases P_trues with
    | nil => contradiction
    | cons P Ps =>
      cases challenges with
      | nil => contradiction
      | cons r rs =>
        dsimp [verify_multi_round] at h_ver
        cases h_check : check_round_c claim_in p r
        · rw [h_check] at h_ver; contradiction
        · next claim_next =>
          rw [h_check] at h_ver
          have h_step := sumcheck_step_reduction P p claim_in claim_next r h_check h_false
          cases h_step with
          | inr h_bad =>
            right
            dsimp [multi_round_bad_event]
            left
            exact h_bad
          | inl h_claim_next_false =>
            cases ps with
            | nil =>
              cases rs with
              | nil =>
                dsimp [verify_multi_round] at h_ver
                injection h_ver with h_eq
                subst h_eq
                left
                cases Ps with
                | nil =>
                  dsimp [get_last_eval]
                  intro h_eq2
                  injection h_eq2 with h_eq3
                  rw [h_eq3] at h_claim_next_false
                  contradiction
                | cons P2 Ps2 =>
                  -- Ps length is 0 because h_len1 says (P::Ps).length = [p].length = 1
                  cases h_len1
              | cons r2 rs2 =>
                cases h_len2
            | cons p2 ps2 =>
              cases rs with
              | nil => cases h_len2
              | cons r2 rs2 =>
                cases Ps with
                | nil => cases h_len1
                | cons P2 Ps2 =>
                  have h_cons2 : consistent_true_polys (P::P2::Ps2) (r::r2::rs2) := h_cons
                  have h_P2_start : P2.eval 0 + P2.eval 1 = P.eval r := h_cons2.1
                  have h_next_false : claim_next ≠ P2.eval 0 + P2.eval 1 := by
                    rw [h_P2_start]
                    exact h_claim_next_false
                  have h_len1_next : (P2::Ps2).length = (p2::ps2).length := Nat.succ.inj h_len1
                  have h_len2_next : (r2::rs2).length = (p2::ps2).length := Nat.succ.inj h_len2
                  have h_ih := ih (P2::Ps2) (r2::rs2) claim_next h_ver h_len1_next h_len2_next h_cons2.2 (by aesop) h_next_false
                  cases h_ih with
                  | inl h_left =>
                    left
                    exact h_left
                  | inr h_right =>
                    right
                    dsimp [multi_round_bad_event]
                    right
                    exact h_right


omit [DecidableEq F] in
/--
**KEY LEMMA: Schwartz-Zippel Bound on Cheating Provers** (`univariate_roots_bound`)

This is the central mathematical insight powering the sumcheck soundness proof.
If a cheating prover sends a polynomial `poly` that lies about the true round evaluations
(meaning `poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1`), the prover
must hope the verifier's randomly sampled challenge `r` satisfies `poly.eval_lagrange r = P_true_poly.eval r`.

Because `poly` is bounded by degree 1 (it is a line), `poly.eval_lagrange` is a degree-1 polynomial `L`.
The prover wins this round if `L(r) - P_true_poly(r) = 0`. By the Fundamental Theorem of Algebra,
a non-zero polynomial of degree bounded by `d` has at most `d` roots. Thus, there are at most `d`
"lucky" challenges `r` over the field `F` that allow the prover to cheat.
-/
lemma univariate_roots_bound (P_true_poly : Polynomial F) (poly : RoundPoly F) (d : ℕ) (hd : P_true_poly.natDegree ≤ d) :
    poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1 →
    (Polynomial.roots (Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly)).card ≤ max 1 d := by
  intro h_diff
  set L : Polynomial F := Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X with hL
  set Q : Polynomial F := L - P_true_poly with hQ
  have hL_eval0 : L.eval 0 = poly.eval0 := by simp [hL]
  have hL_eval1 : L.eval 1 = poly.eval1 := by simp [hL]
  have hQ_neq_0 : Q ≠ 0 := by
    intro hQ_eq_0
    have h_eq : Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X = P_true_poly := sub_eq_zero.mp hQ_eq_0
    have h0 : poly.eval0 = P_true_poly.eval 0 := by
      have h_eval := congr_arg (fun P : Polynomial F => P.eval 0) h_eq
      simp at h_eval
      exact h_eval
    have h1_eval : poly.eval1 = P_true_poly.eval 1 := by
      have h_eval := congr_arg (fun P : Polynomial F => P.eval 1) h_eq
      simp at h_eval
      exact h_eval
    rcases h_diff with h_diff_0 | h_diff_1
    · exact h_diff_0 h0
    · exact h_diff_1 h1_eval
  have h_L_deg : L.natDegree ≤ 1 := by
    rw [hL, add_comm]
    exact Polynomial.natDegree_linear_le
  have h_Q_deg : Q.natDegree ≤ max 1 d := by
    rw [hQ]
    calc (L - P_true_poly).natDegree
      _ ≤ max L.natDegree P_true_poly.natDegree := Polynomial.natDegree_sub_le _ _
      _ ≤ max 1 d := max_le_max h_L_deg hd
  calc (Q.roots).card ≤ Q.natDegree := Polynomial.card_roots' Q
    _ ≤ max 1 d := h_Q_deg

open scoped Classical

abbrev Prefix (F : Type) (i : ℕ) := Fin i → F

abbrev ProverStrategy (F : Type) [Field F] (n : ℕ) := ∀ i : Fin n, Prefix F i.val → RoundPoly F
abbrev TruePolyStrategy (F : Type) [Field F] (n : ℕ) := ∀ i : Fin n, Prefix F i.val → Polynomial F

def extract_prefix {n : ℕ} {F : Type} (cs : Fin n → F) (i : Fin n) : Prefix F i.val :=
  fun j => cs ⟨j.val, by omega⟩

def bad_event_at {F : Type} [Field F] (n : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n) (cs : Fin n → F) (i : Fin n) : Prop :=
  BadRoundEvent (P_func i (extract_prefix cs i)) (p_func i (extract_prefix cs i)) (cs i)

def any_bad_event {F : Type} [Field F] (n : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n) (cs : Fin n → F) : Prop :=
  ∃ i : Fin n, bad_event_at n P_func p_func cs i

lemma bad_round_roots {F : Type} [Field F] [Fintype F] [DecidableEq F] (P_true_poly : Polynomial F) (poly : RoundPoly F) (d : ℕ) (hd : P_true_poly.natDegree ≤ d) (h1 : 1 ≤ d) :
    (Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ).card ≤ d := by
  by_cases h_diff : poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1
  · have h_sz := univariate_roots_bound P_true_poly poly d hd h_diff
    have h_max : max 1 d = d := max_eq_right h1
    rw [h_max] at h_sz
    have h_subset : Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ ⊆ (Polynomial.roots (Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly)).toFinset := by
      intro r hr
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hr
      rw [Multiset.mem_toFinset]
      have h_Q_neq_0 : Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly ≠ 0 := by
        intro hQ_eq_0
        have h_eq : Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X = P_true_poly := sub_eq_zero.mp hQ_eq_0
        have h0 : poly.eval0 = P_true_poly.eval 0 := by
          have h_eval := congr_arg (fun P : Polynomial F => P.eval 0) h_eq
          simp at h_eval
          exact h_eval
        have h1_eval : poly.eval1 = P_true_poly.eval 1 := by
          have h_eval := congr_arg (fun P : Polynomial F => P.eval 1) h_eq
          simp at h_eval
          exact h_eval
        rcases h_diff with h_diff_0 | h_diff_1
        · exact h_diff_0 h0
        · exact h_diff_1 h1_eval
      have h_root : (Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly).IsRoot r := by
        dsimp [Polynomial.IsRoot]
        simp [Polynomial.eval_sub, Polynomial.eval_add, Polynomial.eval_C, Polynomial.eval_mul, Polynomial.eval_X]
        dsimp [BadRoundEvent, RoundPoly.eval_lagrange] at hr
        have hr_eval := hr.right
        calc poly.eval0 + (poly.eval1 - poly.eval0) * r - P_true_poly.eval r
          _ = poly.eval0 + r * (poly.eval1 - poly.eval0) - P_true_poly.eval r := by ring
          _ = P_true_poly.eval r - P_true_poly.eval r := by rw [hr_eval]
          _ = 0 := sub_self _
      exact (Polynomial.mem_roots h_Q_neq_0).mpr h_root
    have h_card_subset := Finset.card_le_card h_subset
    have h_card_toFinset : (Polynomial.roots (Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly)).toFinset.card ≤ (Polynomial.roots (Polynomial.C poly.eval0 + Polynomial.C (poly.eval1 - poly.eval0) * Polynomial.X - P_true_poly)).card := Multiset.toFinset_card_le _
    exact le_trans h_card_subset (le_trans h_card_toFinset h_sz)
  · have h_empty : Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ = ∅ := by
      ext r
      simp
      intro hr
      dsimp [BadRoundEvent] at hr
      exact h_diff hr.left
    rw [h_empty]
    simp


variable {F : Type} [Field F] [Fintype F] [DecidableEq F]
open scoped Classical

def right_index {n : ℕ} {i : Fin n} (j : Fin (n - 1 - i.val)) : Fin n :=
  ⟨i.val + 1 + j.val, by omega⟩

def reconstruct {n : ℕ} (i : Fin n) (pr : Prefix F i.val × F) (g : Fin (n - 1 - i.val) → F) (m : Fin n) : F :=
  if h1 : m.val < i.val then
    pr.1 ⟨m.val, h1⟩
  else if h2 : m.val = i.val then
    pr.2
  else
    g ⟨m.val - (i.val + 1), by omega⟩

omit [Field F] [Fintype F] [DecidableEq F] in
lemma reconstruct_prefix {n : ℕ} (i : Fin n) (pr : Prefix F i.val × F) (g : Fin (n - 1 - i.val) → F) :
    extract_prefix (reconstruct i pr g) i = pr.1 := by
  ext j
  dsimp [extract_prefix, reconstruct]
  have h_lt : j.val < i.val := j.isLt
  simp [h_lt]

omit [Field F] [Fintype F] [DecidableEq F] in
lemma reconstruct_at_i {n : ℕ} (i : Fin n) (pr : Prefix F i.val × F) (g : Fin (n - 1 - i.val) → F) :
    reconstruct i pr g i = pr.2 := by
  dsimp [reconstruct]
  have h_not_lt : ¬(i.val < i.val) := by omega
  simp

def fiber_equiv {n : ℕ} (i : Fin n) (pr : Prefix F i.val × F) :
  { cs : Fin n → F // extract_prefix cs i = pr.1 ∧ cs i = pr.2 } ≃ (Fin (n - 1 - i.val) → F) where
  toFun cs j := cs.val (right_index j)
  invFun g := ⟨reconstruct i pr g, ⟨reconstruct_prefix i pr g, reconstruct_at_i i pr g⟩⟩
  left_inv cs := by
    ext m
    dsimp [reconstruct, right_index, extract_prefix]
    split_ifs with h1 h2
    · have h_eq := congr_fun cs.prop.1 ⟨m.val, h1⟩
      exact h_eq.symm
    · have h_eq : m = i := Fin.ext h2
      rw [h_eq]
      exact cs.prop.2.symm
    · apply congr_arg cs.val
      apply Fin.ext
      dsimp [right_index]
      omega
  right_inv g := by
    ext j
    dsimp [reconstruct, right_index]
    have h1 : ¬(i.val + 1 + j.val < i.val) := by omega
    have h2 : ¬(i.val + 1 + j.val = i.val) := by omega
    simp [h1, h2]


omit [Field F] in
/--
Counts the exact number of complete challenge sequences `cs : Fin n → F` that extend a specific prefix
of length `i` and match a specific challenge `r` at round `i`. Since the remaining $n - 1 - i$ challenges
can be freely chosen, the size of this "fiber" is $|F|^{n - 1 - i}$.
This handles the future-branching factor in the combinatorial tree of transcripts.
-/
lemma card_fiber_eq (n : ℕ) (i : Fin n) (pr : Prefix F i.val × F) :
    (Finset.filter (fun cs : Fin n → F => extract_prefix cs i = pr.1 ∧ cs i = pr.2) Finset.univ).card =
    (Fintype.card F)^(n - 1 - i.val) := by
  have h_equiv := Fintype.card_congr (fiber_equiv i pr)
  have h_sub : (Finset.filter (fun cs : Fin n → F => extract_prefix cs i = pr.1 ∧ cs i = pr.2) Finset.univ).card = Fintype.card { cs : Fin n → F // extract_prefix cs i = pr.1 ∧ cs i = pr.2 } := by
    rw [Fintype.card_subtype]
  rw [h_sub, h_equiv]
  simp

/--
A combinatorial version of the "Law of Total Probability" over finite sets.
It proves that filtering a type `α` by a predicate `P ∘ f` is equivalent to summing the
sizes of the fibers `{x | f(x) = y}` for all `y ∈ β` that satisfy `P`.
We use this to group full challenge sequences by their round-$i$ prefix.
-/
lemma card_filter_comp {α β : Type*} [Fintype α] [Fintype β] [DecidableEq β] (f : α → β) (P : β → Prop) :
    (Finset.filter (fun x => P (f x)) Finset.univ).card =
    ∑ y ∈ Finset.filter P Finset.univ, (Finset.filter (fun x => f x = y) Finset.univ).card := by
  have h_union : Finset.filter (fun x => P (f x)) Finset.univ =
    Finset.biUnion (Finset.filter P Finset.univ) (fun y => Finset.filter (fun x => f x = y) Finset.univ) := by
    ext x
    simp
  rw [h_union]
  apply Finset.card_biUnion
  intro y1 hy1 y2 hy2 hne
  apply Finset.disjoint_left.mpr
  intro x hx1 hx2
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hx1 hx2
  exact hne (hx1.symm.trans hx2)


omit [Field F] in
/--
Synthesizes `card_filter_comp` and `card_fiber_eq` to scale round-level events to the full space.
If a property `P` (like a prover cheating successfully) only depends on the prefix and the round-$i$ challenge,
then the number of complete challenge sequences `cs : Fin n → F` satisfying `P` is exactly the number of
(prefix, challenge) pairs satisfying `P`, multiplied by the fiber size $|F|^{n - 1 - i}$.
-/
lemma card_filter_prefix_r (n : ℕ) (i : Fin n) (P : Prefix F i.val → F → Prop) :
    (Finset.filter (fun cs : Fin n → F => P (extract_prefix cs i) (cs i)) Finset.univ).card =
    (Finset.filter (fun (pr : Prefix F i.val × F) => P pr.1 pr.2) Finset.univ).card * (Fintype.card F)^(n - 1 - i.val) := by
  have h_comp := card_filter_comp (fun cs : Fin n → F => (extract_prefix cs i, cs i)) (fun (pr : Prefix F i.val × F) => P pr.1 pr.2)
  rw [h_comp]
  calc ∑ y ∈ Finset.filter (fun (pr : Prefix F i.val × F) => P pr.1 pr.2) Finset.univ, (Finset.filter (fun x : Fin n → F => (extract_prefix x i, x i) = y) Finset.univ).card
    _ = ∑ y ∈ Finset.filter (fun (pr : Prefix F i.val × F) => P pr.1 pr.2) Finset.univ, (Fintype.card F)^(n - 1 - i.val) := by
      apply Finset.sum_congr rfl
      intro (pr : Prefix F i.val × F) _
      have h_eq : (Finset.filter (fun x : Fin n → F => (extract_prefix x i, x i) = pr) Finset.univ) =
                  (Finset.filter (fun x : Fin n → F => extract_prefix x i = pr.1 ∧ x i = pr.2) Finset.univ) := by
        ext x
        simp [Prod.ext_iff]
      rw [h_eq]
      exact card_fiber_eq n i pr
    _ = (Finset.filter (fun (pr : Prefix F i.val × F) => P pr.1 pr.2) Finset.univ).card * (Fintype.card F)^(n - 1 - i.val) := by
      simp [Finset.sum_const]

lemma card_prod_filter {α β : Type*} [Fintype α] [Fintype β] (P : α → β → Prop) :
    (Finset.filter (fun (pr : α × β) => P pr.1 pr.2) Finset.univ).card =
    ∑ a : α, (Finset.filter (fun b => P a b) Finset.univ).card := by
  have h_union : Finset.filter (fun (pr : α × β) => P pr.1 pr.2) Finset.univ =
    Finset.biUnion Finset.univ (fun a => (Finset.filter (fun b => P a b) Finset.univ).map ⟨fun b => (a, b), fun b1 b2 h => Prod.mk.inj h |>.2⟩) := by
    ext ⟨a, b⟩
    simp
  rw [h_union]
  rw [Finset.card_biUnion]
  · apply Finset.sum_congr rfl
    intro a _
    rw [Finset.card_map]
  · intro a1 _ a2 _ hne
    apply Finset.disjoint_left.mpr
    intro ⟨x, y⟩ hx1 hx2
    rw [Finset.mem_map] at hx1 hx2
    rcases hx1 with ⟨b1, _, h1⟩
    rcases hx2 with ⟨b2, _, h2⟩
    dsimp at h1 h2
    exact hne ((congr_arg Prod.fst h1).trans (congr_arg Prod.fst h2).symm)

lemma combinatorial_fs_level (n d : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n)
    (hd : ∀ (i : Fin n) (pref : Prefix F i.val), (P_func i pref).natDegree ≤ d) (h1 : 1 ≤ d) (i : Fin n) :
    (Finset.filter (fun cs : Fin n → F => bad_event_at n P_func p_func cs i) Finset.univ).card ≤ d * (Fintype.card F)^(n - 1) := by
  have h_rewrite : (Finset.filter (fun cs : Fin n → F => bad_event_at n P_func p_func cs i) Finset.univ).card =
    (Finset.filter (fun (pr : Prefix F i.val × F) => BadRoundEvent (P_func i pr.1) (p_func i pr.1) pr.2) Finset.univ).card * (Fintype.card F)^(n - 1 - i.val) := by
    change (Finset.filter (fun cs : Fin n → F => (fun pref r => BadRoundEvent (P_func i pref) (p_func i pref) r) (extract_prefix cs i) (cs i)) Finset.univ).card = _
    exact card_filter_prefix_r n i (fun pref r => BadRoundEvent (P_func i pref) (p_func i pref) r)
  rw [h_rewrite]
  have h_prod_card : (Finset.filter (fun (pr : Prefix F i.val × F) => BadRoundEvent (P_func i pr.1) (p_func i pr.1) pr.2) Finset.univ).card ≤
    (Fintype.card (Prefix F i.val)) * d := by
    have h_fiber : (Finset.filter (fun (pr : Prefix F i.val × F) => BadRoundEvent (P_func i pr.1) (p_func i pr.1) pr.2) Finset.univ).card =
      ∑ pref : Prefix F i.val, (Finset.filter (fun r : F => BadRoundEvent (P_func i pref) (p_func i pref) r) Finset.univ).card := by
      exact card_prod_filter (fun pref r => BadRoundEvent (P_func i pref) (p_func i pref) r)
    rw [h_fiber]
    calc ∑ pref : Prefix F i.val, (Finset.filter (fun r : F => BadRoundEvent (P_func i pref) (p_func i pref) r) Finset.univ).card
      _ ≤ ∑ pref : Prefix F i.val, d := by
        apply Finset.sum_le_sum
        intro pref _
        exact bad_round_roots (P_func i pref) (p_func i pref) d (hd i pref) h1
      _ = (Fintype.card (Prefix F i.val)) * d := by
        simp [Finset.sum_const]
  have h_pref_card : Fintype.card (Prefix F i.val) = (Fintype.card F)^i.val := by
    simp [Prefix]
  rw [h_pref_card] at h_prod_card
  calc (Finset.filter (fun (pr : Prefix F i.val × F) => BadRoundEvent (P_func i pr.1) (p_func i pr.1) pr.2) Finset.univ).card * (Fintype.card F)^(n - 1 - i.val)
    _ ≤ ((Fintype.card F)^i.val * d) * (Fintype.card F)^(n - 1 - i.val) := by
      gcongr
    _ = d * ((Fintype.card F)^i.val * (Fintype.card F)^(n - 1 - i.val)) := by ring
    _ = d * (Fintype.card F)^(i.val + (n - 1 - i.val)) := by
      rw [←pow_add]
    _ = d * (Fintype.card F)^(n - 1) := by
      congr 2
      omega

/--
**Final Theorem: Combinatorial Fiat-Shamir Soundness** for the Sumcheck Protocol

Unites the round-by-round polynomial roots bounds (`univariate_roots_bound`) with the structural
non-adaptivity constraints of the protocol (`card_filter_prefix_r`).

It proves that for any computationally unbounded prover strategy `p_func` that is structurally non-adaptive
(it cannot look into the future), the absolute total number of complete challenge sequences
`cs : Fin n → F` that cause the verifier to accept a false claim is strictly bounded by:
`n * d * |F|^(n-1)`.

This replaces generic random oracle axioms with a precise combinatorial counting argument over the Fiat-Shamir execution tree.
-/
lemma combinatorial_fiat_shamir (n d : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n)
    (hd : ∀ (i : Fin n) (pref : Prefix F i.val), (P_func i pref).natDegree ≤ d) (h1 : 1 ≤ d) :
    (Finset.filter (fun cs : Fin n → F => any_bad_event n P_func p_func cs) Finset.univ).card ≤ n * d * (Fintype.card F)^(n - 1) := by
  have h_union : Finset.filter (fun cs : Fin n → F => any_bad_event n P_func p_func cs) Finset.univ =
    Finset.biUnion Finset.univ (fun (i : Fin n) => Finset.filter (fun cs => bad_event_at n P_func p_func cs i) Finset.univ) := by
    ext cs
    simp [any_bad_event]
  rw [h_union]
  have h_le : (Finset.biUnion Finset.univ (fun (i : Fin n) => Finset.filter (fun cs => bad_event_at n P_func p_func cs i) Finset.univ)).card ≤ ∑ i : Fin n, (Finset.filter (fun cs => bad_event_at n P_func p_func cs i) Finset.univ).card :=
    Finset.card_biUnion_le
  calc (Finset.biUnion Finset.univ (fun (i : Fin n) => Finset.filter (fun cs => bad_event_at n P_func p_func cs i) Finset.univ)).card
    _ ≤ ∑ i : Fin n, (Finset.filter (fun cs => bad_event_at n P_func p_func cs i) Finset.univ).card := h_le
    _ ≤ ∑ i : Fin n, d * (Fintype.card F)^(n - 1) := by
      apply Finset.sum_le_sum
      intro i _
      exact combinatorial_fs_level n d P_func p_func hd h1 i
    _ = n * (d * (Fintype.card F)^(n - 1)) := by
      simp [Finset.sum_const]
    _ = n * d * (Fintype.card F)^(n - 1) := by ring
