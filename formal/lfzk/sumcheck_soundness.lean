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

### Completeness

`sumcheck_multi_completeness` is the other direction, and the hiding side needs it: an honest
prover starting from the true claim is *accepted*, and the claim the verifier ends on is the
last true polynomial at its own challenge.  It needs no degree bound and no field-size
condition — only that the transmitted triples agree with the true polynomials where the
verifier looks.  `RoundPoly.eval_lagrange_eq_of_agree` is the companion fact that agreement at
`0`, `1`, `pt2` forces agreement everywhere.

### Mathematical Soundness Guarantee:
If the input claim $C_{k-1}$ is false (i.e. $C_{k-1} \neq \sum_{x \in \{0,1\}} P_k(x)$), then:
- Either the prover fails Check 1 ($p_k(0) + p_k(1) \neq C_{k-1}$), leading to immediate rejection.
- OR $p_k \neq P_k$ as univariate polynomials. By the Schwartz-Zippel Lemma,
  $p_k(r_k) = P_k(r_k)$ holds for at most $d$ choices of $r_k \in \mathbb{F}$.
- Thus, the probability that a false claim is converted into a true claim at round $k$ is at most $\frac{d}{|\mathbb{F}|}$.
-/

variable {F : Type} [Field F] [DecidableEq F]

/--
The interpolation points at which a sumcheck round polynomial is transmitted.

`WPoly = Poly<3, Field>` (`sumcheck/circuit.h:L75`) carries three evaluations, and
`Poly::eval_lagrange` (`algebra/poly.h`) interpolates through
`Field::poly_evaluation_point(0), (1), (2)`.  The first two are `0` and `1` — the sum
check `F.addf(tp[0], tp[1]) != *claim` is taken over them, so they are pinned.  The third
is field-specific: `2` for prime fields, but for `GF(2)[X]/(Q(X))` it is the generator `X`,
since `2 = 0` there.  `zk_common.h:L203-L205` calls it "a generic name for the third
evaluation point of the sumcheck round polynomial (could be X for binary fields)".

We therefore leave it abstract, requiring only that it is distinct from `0` and `1` so
that the three points are pairwise distinct and the interpolant is unique.
-/
class SumcheckInterp (F : Type) [Field F] where
  /-- The third evaluation point, `Field::poly_evaluation_point(2)`. -/
  pt2 : F
  pt2_ne_zero : pt2 ≠ 0
  pt2_ne_one : pt2 ≠ 1

export SumcheckInterp (pt2)

variable [SumcheckInterp F]

/--
`RoundPoly` represents a degree-≤2 univariate polynomial sent by the prover in a sumcheck
round, transmitted as its evaluations at `0`, `1`, and `pt2`.
- **Code Reference**: `proofs::LayerProof::hp` (`WPoly = Poly<3, Field>`) in
  `privacy/proofs/zk/lib/sumcheck/circuit.h`
-/
structure RoundPoly (F : Type) where
  eval0 : F
  eval1 : F
  eval2 : F

/--
The unique polynomial of degree `≤ 2` through `(0, eval0)`, `(1, eval1)`, `(pt2, eval2)`,
in Lagrange form.  This is the polynomial the prover is committing to when it sends a
`WPoly`; `Poly::newton_of_lagrange` followed by `Poly::eval_newton` computes exactly its
evaluations.
-/
noncomputable def RoundPoly.toPoly (poly : RoundPoly F) : Polynomial F :=
  Polynomial.C (poly.eval0 * (pt2 : F)⁻¹) * ((X - Polynomial.C 1) * (X - Polynomial.C (pt2 : F))) +
  Polynomial.C (poly.eval1 * (1 - (pt2 : F))⁻¹) * ((X - Polynomial.C 0) * (X - Polynomial.C (pt2 : F))) +
  Polynomial.C (poly.eval2 * ((pt2 : F) * ((pt2 : F) - 1))⁻¹) * ((X - Polynomial.C 0) * (X - Polynomial.C 1))

/--
Evaluates a `RoundPoly` at challenge point `r` using Lagrange interpolation through
`0`, `1` and `pt2`.

Previously this ignored `eval2` and interpolated linearly through `eval0`/`eval1`, which
modelled a *degree-1* verifier and so did not match the implementation.
- **Code Reference**: `tp.eval_lagrange(ch->hb[hand][round], F)` at `verifier_layers.h:L127`,
  implemented by `Poly<3, Field>::eval_lagrange` in `algebra/poly.h`.
-/
def RoundPoly.eval_lagrange (poly : RoundPoly F) (r : F) : F :=
  poly.eval0 * ((r - 1) * (r - (pt2 : F))) * (pt2 : F)⁻¹ +
  poly.eval1 * (r * (r - (pt2 : F))) * (1 - (pt2 : F))⁻¹ +
  poly.eval2 * (r * (r - 1)) * ((pt2 : F) * ((pt2 : F) - 1))⁻¹

omit [DecidableEq F] in
lemma RoundPoly.eval_toPoly (poly : RoundPoly F) (r : F) :
    poly.toPoly.eval r = poly.eval_lagrange r := by
  simp [RoundPoly.toPoly, RoundPoly.eval_lagrange]
  ring

omit [DecidableEq F] in
@[simp] lemma RoundPoly.eval_lagrange_zero (poly : RoundPoly F) :
    poly.eval_lagrange 0 = poly.eval0 := by
  have h0 : (pt2 : F) ≠ 0 := SumcheckInterp.pt2_ne_zero
  rw [RoundPoly.eval_lagrange]
  field_simp
  ring

omit [DecidableEq F] in
@[simp] lemma RoundPoly.eval_lagrange_one (poly : RoundPoly F) :
    poly.eval_lagrange 1 = poly.eval1 := by
  have h1 : (1 : F) - (pt2 : F) ≠ 0 := sub_ne_zero.mpr (Ne.symm SumcheckInterp.pt2_ne_one)
  rw [RoundPoly.eval_lagrange]
  field_simp
  ring

omit [DecidableEq F] in
/-- `eval_lagrange` recovers the third transmitted evaluation.  Together with
`eval_lagrange_zero` and `eval_lagrange_one` this pins down `eval_lagrange` as *the*
interpolant through the three points, and in particular shows `eval2` is actually read —
it was ignored entirely by the previous degree-1 definition. -/
@[simp] lemma RoundPoly.eval_lagrange_pt2 (poly : RoundPoly F) :
    poly.eval_lagrange (pt2 : F) = poly.eval2 := by
  have h0 : (pt2 : F) ≠ 0 := SumcheckInterp.pt2_ne_zero
  have h1 : (pt2 : F) - 1 ≠ 0 := sub_ne_zero.mpr SumcheckInterp.pt2_ne_one
  rw [RoundPoly.eval_lagrange]
  field_simp
  ring

omit [DecidableEq F] in
/-- The prover's round polynomial has degree at most 2, matching `WPoly = Poly<3, Field>`. -/
lemma RoundPoly.toPoly_natDegree (poly : RoundPoly F) : poly.toPoly.natDegree ≤ 2 := by
  have hterm : ∀ (a b c : F),
      (Polynomial.C a * ((X - Polynomial.C b) * (X - Polynomial.C c))).natDegree ≤ 2 := by
    intro a b c
    refine le_trans (Polynomial.natDegree_C_mul_le _ _) ?_
    refine le_trans (Polynomial.natDegree_mul_le) ?_
    simp
  rw [RoundPoly.toPoly]
  refine le_trans (Polynomial.natDegree_add_le _ _) (max_le ?_ (hterm _ _ _))
  exact le_trans (Polynomial.natDegree_add_le _ _) (max_le (hterm _ _ _) (hterm _ _ _))

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

omit [SumcheckInterp F] in
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

theorem sumcheck_step_reduction {F : Type} [Field F] [DecidableEq F] [SumcheckInterp F]
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

def BadRoundEvent {F : Type} [Field F] [SumcheckInterp F] (P_true : Polynomial F) (poly : RoundPoly F) (r : F) : Prop :=
  (poly.eval0 ≠ P_true.eval 0 ∨ poly.eval1 ≠ P_true.eval 1) ∧ poly.eval_lagrange r = P_true.eval r

def multi_round_bad_event {F : Type} [Field F] [SumcheckInterp F] : List (Polynomial F) → List (RoundPoly F) → List F → Prop
  | (P::Ps), (p::ps), (r::rs) => BadRoundEvent P p r ∨ multi_round_bad_event Ps ps rs
  | _, _, _ => False

def verify_multi_round {F : Type} [Field F] [DecidableEq F] [SumcheckInterp F] (claim_start : F) (polys : List (RoundPoly F)) (challenges : List F) : Option F :=
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
theorem sumcheck_multi_reduction {F : Type} [Field F] [DecidableEq F] [SumcheckInterp F]
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


/-!
## The other direction: completeness

`sumcheck_multi_reduction` is the soundness half — if the verifier accepts a *false* claim then
some round was lucky.  Nothing so far says the verifier accepts an *honest* run at all, and the
hiding side needs exactly that: `HonestFinalClaim` (`zk_sim.lean`) asks what claim the rounds
close on when the prover is honest.

`HonestRounds` says the transmitted triples agree with the true polynomials where the verifier
looks: at `0`, at `1`, and at the round's own challenge.  Under it the round checks pass by
`check_round_c`'s test and the chain telescopes down to `get_last_eval`.
-/

/-- The transmitted round polynomials agree with the true ones at the three points the
verifier reads: `0`, `1`, and the challenge.  This is the negation of `BadRoundEvent`'s first
conjunct, round by round, plus agreement at the challenge. -/
def HonestRounds {F : Type} [Field F] [SumcheckInterp F] :
    List (Polynomial F) → List (RoundPoly F) → List F → Prop
  | (P :: Ps), (p :: ps), (r :: rs) =>
      (p.eval0 = P.eval 0 ∧ p.eval1 = P.eval 1 ∧ p.eval_lagrange r = P.eval r)
        ∧ HonestRounds Ps ps rs
  | [], [], [] => True
  | _, _, _ => False

/--
**Sumcheck completeness, multi-round.**

An honest prover starting from the true claim is accepted, and the claim the verifier ends on
is the last true polynomial at its own challenge — `get_last_eval`.

The two hypotheses are exactly the honest prover's own properties: `hcons` is
`consistent_generate` (each true polynomial's hypercube sum is the previous one's value at the
challenge) and `hstart` says the run starts from the true claim.  Note that no degree bound and
no field-size condition appear: completeness is unconditional.
-/
theorem sumcheck_multi_completeness {F : Type} [Field F] [DecidableEq F] [SumcheckInterp F] :
    ∀ (P_trues : List (Polynomial F)) (polys : List (RoundPoly F)) (challenges : List F)
      (claim_in : F),
      HonestRounds P_trues polys challenges →
      consistent_true_polys P_trues challenges →
      polys ≠ [] →
      claim_in = P_trues.head!.eval 0 + P_trues.head!.eval 1 →
      verify_multi_round claim_in polys challenges = get_last_eval P_trues challenges := by
  intro P_trues
  induction P_trues with
  | nil => intro polys challenges claim_in hh _ _ _; cases polys <;> cases challenges <;> simp_all [HonestRounds]
  | cons P Pt ih =>
    intro polys challenges claim_in hh hcons _ hstart
    cases polys with
    | nil => exact absurd hh (by simp [HonestRounds])
    | cons p pt =>
      cases challenges with
      | nil => exact absurd hh (by simp [HonestRounds])
      | cons r rt =>
        obtain ⟨⟨h0, h1, hr⟩, hrest⟩ := hh
        -- the round check passes: the transmitted `p(0) + p(1)` is the incoming claim
        have hcheck : check_round_c claim_in p r = some (p.eval_lagrange r) := by
          rw [check_round_c, if_pos]
          simp only [beq_iff_eq, h0, h1]
          simpa using hstart.symm
        rw [verify_multi_round, hcheck, hr]
        cases pt with
        | nil =>
          -- one round left: `Pt` and `rt` are empty too, and the chain ends here
          cases Pt with
          | nil => cases rt with
            | nil => rfl
            | cons _ _ => exact absurd hrest (by simp [HonestRounds])
          | cons _ _ => exact absurd hrest (by simp [HonestRounds])
        | cons p' pt' =>
          cases Pt with
          | nil => exact absurd hrest (by simp [HonestRounds])
          | cons P' Pt' =>
            cases rt with
            | nil => exact absurd hrest (by simp [HonestRounds])
            | cons r' rt' =>
              -- the next claim is the true one, by `consistent_true_polys`
              rw [consistent_true_polys] at hcons
              -- with two or more rounds left, `get_last_eval` just drops the head
              have hgle : get_last_eval (P :: P' :: Pt') (r :: r' :: rt')
                  = get_last_eval (P' :: Pt') (r' :: rt') := rfl
              rw [hgle]
              exact ih (p' :: pt') (r' :: rt') (P.eval r) hrest hcons.2 (by simp)
                (by simpa using hcons.1.symm)

/--
**A `WPoly` determines the round polynomial.**

The transmitted triple is the degree-`≤2` interpolant through `0`, `1`, `pt2`.  If a
polynomial of degree `≤ 2` agrees with the triple at those three points, `eval_lagrange`
reproduces it *everywhere*: the difference has degree `≤ 2` and three distinct roots, so it is
zero.

This is the converse of the soundness direction.  `univariate_roots_bound` counts how often a
*disagreeing* triple can still hit the true value at the challenge; this says an *agreeing*
triple hits it at every challenge, which is what an honest prover needs.
-/
lemma RoundPoly.eval_lagrange_eq_of_agree (poly : RoundPoly F) (P : Polynomial F)
    (hdeg : P.natDegree ≤ 2) (h0 : poly.eval0 = P.eval 0) (h1 : poly.eval1 = P.eval 1)
    (h2 : poly.eval2 = P.eval (pt2 : F)) (r : F) :
    poly.eval_lagrange r = P.eval r := by
  classical
  have key : poly.toPoly = P := by
    by_contra hne
    have hQ0 : poly.toPoly - P ≠ 0 := sub_ne_zero.mpr hne
    have hQdeg : (poly.toPoly - P).natDegree ≤ 2 :=
      le_trans (Polynomial.natDegree_sub_le _ _) (max_le poly.toPoly_natDegree hdeg)
    have hsub : ({0, 1, (pt2 : F)} : Finset F) ⊆ (poly.toPoly - P).roots.toFinset := by
      intro x hx
      simp only [Finset.mem_insert, Finset.mem_singleton] at hx
      have hroot : ∀ y : F, poly.eval_lagrange y = P.eval y →
          x = y → (poly.toPoly - P).IsRoot x := by
        rintro y hy rfl
        show Polynomial.eval x (poly.toPoly - P) = 0
        rw [Polynomial.eval_sub, RoundPoly.eval_toPoly, hy, sub_self]
      have : (poly.toPoly - P).IsRoot x := by
        rcases hx with rfl | rfl | rfl
        · exact hroot 0 (by rw [RoundPoly.eval_lagrange_zero, h0]) rfl
        · exact hroot 1 (by rw [RoundPoly.eval_lagrange_one, h1]) rfl
        · exact hroot (pt2 : F) (by rw [RoundPoly.eval_lagrange_pt2, h2]) rfl
      simpa [Multiset.mem_toFinset, Polynomial.mem_roots hQ0] using this
    have hcard : ({0, 1, (pt2 : F)} : Finset F).card = 3 := by
      have hp0 : (pt2 : F) ≠ 0 := SumcheckInterp.pt2_ne_zero
      have hp1 : (pt2 : F) ≠ 1 := SumcheckInterp.pt2_ne_one
      rw [Finset.card_insert_of_notMem (by simp [hp0.symm, (zero_ne_one : (0:F) ≠ 1)]),
          Finset.card_insert_of_notMem (by simp [hp1.symm]), Finset.card_singleton]
    have hle := Finset.card_le_card hsub
    have hr2 : (poly.toPoly - P).roots.toFinset.card ≤ 2 :=
      le_trans (poly.toPoly - P).roots.toFinset_card_le
        (le_trans (Polynomial.card_roots' _) hQdeg)
    omega
  rw [← RoundPoly.eval_toPoly, key]

omit [DecidableEq F] in
/-- A round polynomial that disagrees with `P_true_poly` at `0` or at `1` is a different
polynomial, so their difference is non-zero. -/
lemma RoundPoly.toPoly_sub_ne_zero (P_true_poly : Polynomial F) (poly : RoundPoly F)
    (h_diff : poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1) :
    poly.toPoly - P_true_poly ≠ 0 := by
  intro hQ_eq_0
  have h_eq : poly.toPoly = P_true_poly := sub_eq_zero.mp hQ_eq_0
  have h0 : poly.eval0 = P_true_poly.eval 0 := by
    rw [← h_eq, RoundPoly.eval_toPoly, RoundPoly.eval_lagrange_zero]
  have h1 : poly.eval1 = P_true_poly.eval 1 := by
    rw [← h_eq, RoundPoly.eval_toPoly, RoundPoly.eval_lagrange_one]
  rcases h_diff with h | h
  · exact h h0
  · exact h h1

omit [DecidableEq F] in
/--
**KEY LEMMA: Schwartz-Zippel Bound on Cheating Provers** (`univariate_roots_bound`)

This is the central mathematical insight powering the sumcheck soundness proof.
If a cheating prover sends a polynomial `poly` that lies about the true round evaluations
(meaning `poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1`), the prover
must hope the verifier's randomly sampled challenge `r` satisfies
`poly.eval_lagrange r = P_true_poly.eval r`.

`poly.toPoly` is the degree-≤2 interpolant through `(0, eval0)`, `(1, eval1)`, `(pt2, eval2)`
— matching `WPoly = Poly<3, Field>` in the implementation — and `eval_lagrange` is its
evaluation.  The prover wins this round exactly when `r` is a root of
`poly.toPoly - P_true_poly`.  A non-zero polynomial of degree at most `max 2 d` has at
most `max 2 d` roots, so at most that many challenges are "lucky".

The `2` in `max 2 d` is the degree of the transmitted round polynomial.  It was `1` while
`eval_lagrange` ignored `eval2` and interpolated linearly; that understated the cheating
prover's power relative to the code.
-/
lemma univariate_roots_bound (P_true_poly : Polynomial F) (poly : RoundPoly F) (d : ℕ) (hd : P_true_poly.natDegree ≤ d) :
    poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1 →
    (Polynomial.roots (poly.toPoly - P_true_poly)).card ≤ max 2 d := by
  intro h_diff
  set Q : Polynomial F := poly.toPoly - P_true_poly with hQ
  have h_Q_deg : Q.natDegree ≤ max 2 d := by
    rw [hQ]
    calc (poly.toPoly - P_true_poly).natDegree
      _ ≤ max poly.toPoly.natDegree P_true_poly.natDegree := Polynomial.natDegree_sub_le _ _
      _ ≤ max 2 d := max_le_max poly.toPoly_natDegree hd
  calc (Q.roots).card ≤ Q.natDegree := Polynomial.card_roots' Q
    _ ≤ max 2 d := h_Q_deg

open scoped Classical

abbrev Prefix (F : Type) (i : ℕ) := Fin i → F

abbrev ProverStrategy (F : Type) [Field F] (n : ℕ) := ∀ i : Fin n, Prefix F i.val → RoundPoly F
abbrev TruePolyStrategy (F : Type) [Field F] (n : ℕ) := ∀ i : Fin n, Prefix F i.val → Polynomial F

def extract_prefix {n : ℕ} {F : Type} (cs : Fin n → F) (i : Fin n) : Prefix F i.val :=
  fun j => cs ⟨j.val, by omega⟩

def bad_event_at {F : Type} [Field F] [SumcheckInterp F] (n : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n) (cs : Fin n → F) (i : Fin n) : Prop :=
  BadRoundEvent (P_func i (extract_prefix cs i)) (p_func i (extract_prefix cs i)) (cs i)

def any_bad_event {F : Type} [Field F] [SumcheckInterp F] (n : ℕ) (P_func : TruePolyStrategy F n) (p_func : ProverStrategy F n) (cs : Fin n → F) : Prop :=
  ∃ i : Fin n, bad_event_at n P_func p_func cs i

/--
At most `d` of the `|F|` challenges let a cheating prover survive a round, provided the
true round polynomial has degree at most `d` and `2 ≤ d`.

The hypothesis is `2 ≤ d`, not `1 ≤ d`: the prover's own transmitted polynomial is a
`WPoly = Poly<3, Field>`, i.e. of degree up to 2, so the difference it needs to have a
root at `r` already has degree up to 2 regardless of the true polynomial.
-/
lemma bad_round_roots {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] (P_true_poly : Polynomial F) (poly : RoundPoly F) (d : ℕ) (hd : P_true_poly.natDegree ≤ d) (h2 : 2 ≤ d) :
    (Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ).card ≤ d := by
  by_cases h_diff : poly.eval0 ≠ P_true_poly.eval 0 ∨ poly.eval1 ≠ P_true_poly.eval 1
  · have h_sz := univariate_roots_bound P_true_poly poly d hd h_diff
    have h_max : max 2 d = d := max_eq_right h2
    rw [h_max] at h_sz
    have h_Q_neq_0 : poly.toPoly - P_true_poly ≠ 0 :=
      RoundPoly.toPoly_sub_ne_zero P_true_poly poly h_diff
    have h_subset : Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ ⊆
        (Polynomial.roots (poly.toPoly - P_true_poly)).toFinset := by
      intro r hr
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hr
      rw [Multiset.mem_toFinset]
      have h_root : (poly.toPoly - P_true_poly).IsRoot r := by
        dsimp [Polynomial.IsRoot]
        rw [Polynomial.eval_sub, RoundPoly.eval_toPoly]
        dsimp [BadRoundEvent] at hr
        rw [hr.right, sub_self]
      exact (Polynomial.mem_roots h_Q_neq_0).mpr h_root
    have h_card_subset := Finset.card_le_card h_subset
    have h_card_toFinset :
        (Polynomial.roots (poly.toPoly - P_true_poly)).toFinset.card
          ≤ (Polynomial.roots (poly.toPoly - P_true_poly)).card := Multiset.toFinset_card_le _
    exact le_trans h_card_subset (le_trans h_card_toFinset h_sz)
  · have h_empty : Finset.filter (fun r => BadRoundEvent P_true_poly poly r) Finset.univ = ∅ := by
      ext r
      simp
      intro hr
      dsimp [BadRoundEvent] at hr
      exact h_diff hr.left
    rw [h_empty]
    simp


variable {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
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
    (hd : ∀ (i : Fin n) (pref : Prefix F i.val), (P_func i pref).natDegree ≤ d) (h2 : 2 ≤ d) (i : Fin n) :
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
        exact bad_round_roots (P_func i pref) (p_func i pref) d (hd i pref) h2
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
    (hd : ∀ (i : Fin n) (pref : Prefix F i.val), (P_func i pref).natDegree ≤ d) (h2 : 2 ≤ d) :
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
      exact combinatorial_fs_level n d P_func p_func hd h2 i
    _ = n * (d * (Fintype.card F)^(n - 1)) := by
      simp [Finset.sum_const]
    _ = n * d * (Fintype.card F)^(n - 1) := by ring
