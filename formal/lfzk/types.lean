import Mathlib
import sumcheck_soundness

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

noncomputable def event_card (E : Finset Ω) : ℕ := E.card



/--
`Expression` models the state in `zk_common.h` that tracks the symbolic evaluation
of a sumcheck polynomial. It maintains:
- `known`: the public scalar value
- `symbolic`: an array of coefficients for the pad variables.
-/
def Expression (M : ℕ) (F : Type) [Field F] :=
  F × (Fin M → F)


def Pad (M : ℕ) (F : Type) := Fin M → F


def AugmentedWitness (M : ℕ) (F : Type) (Witness : Type) := Witness × Pad M F


/--
**Structure: Transcript**

Models the **decrypted (plaintext) interactive sumcheck transcript** between the prover and verifier
after secret blinding pads have been removed (via `decrypt`).

### Fields:
- `polys`: The sequence of univariate round polynomials ($p_1(X), \dots, p_R(X)$) sent by the prover in each round of sumcheck (`LayerProof::cp` in `privacy/proofs/zk/lib/sumcheck/circuit.h`).
- `challenges`: The random field challenges ($r_1, \dots, r_R$) sampled by the verifier (`ch->cb[round]`).
- `claim_last`: The verifier's claim at the end of the sumcheck rounds (`*claim` after the final round in `verifier_layers.h:L160`).
- `w_r_eval`, `w_l_eval`: The evaluations of the right-hand and left-hand witness polynomials claimed by the prover at evaluation points $R$ and $L$.
- `w_r_true`, `w_l_true`: The actual, mathematically honest multilinear evaluations of the right-hand and left-hand witness MLEs (`W_mle r copy`, `W_mle l copy`) at the challenge point (`got = EQ[Q,C] QUAD[G|R,L] W[R,C] W[L,C]` in `verifier_layers.h:L160`).
-/
structure Transcript (F : Type) [Field F] where
  polys : List (RoundPoly F)
  challenges : List F
  claim_last : F
  w_r_eval : F
  w_l_eval : F
  w_r_true : F
  w_l_true : F


/--
`Transcript.checkV` models the unpadded, ideal verifier check on a decrypted transcript `t` and equality factor `eqq`.

It evaluates key verifier conditions:
1. **Sumcheck Multiplication Check** (`t.claim_last == eqq * t.w_r_eval * t.w_l_eval`):
   Verifies that the final sumcheck evaluation `claim_last` equals `EQQ * W_R * W_L`.
   - **Paper Reference**: *Longfellow ZK Paper*, Page 11: `CLAIM = EQQ * W[R,C] * W[L,C]`
   - **Code Reference**: `privacy/proofs/zk/lib/zk/zk_common.h:L340`: `CLAIM = EQQ * W[R,C] * W[L,C]`
2. **Right Witness Binding Check** (`t.w_r_eval == t.w_r_true`):
   Verifies that the transcript's public witness evaluation claim matches the extracted witness evaluation at $R$.
3. **Left Witness Binding Check** (`t.w_l_eval == t.w_l_true`):
   Verifies that the transcript's public witness evaluation claim matches the extracted witness evaluation at $L$.
-/
def Transcript.checkV {F : Type} [Field F] [DecidableEq F] (t : Transcript F) (eqq : F) : Bool :=
  (t.claim_last == eqq * t.w_r_eval * t.w_l_eval) && 
  (t.w_r_eval == t.w_r_true) && 
  (t.w_l_eval == t.w_l_true)


def evaluates_to {M : ℕ} {F : Type} [Field F] (e : Expression M F) (pad : Fin M → F) : F :=
  e.1 + ∑ i : Fin M, e.2 i * pad i

/--
The event that the single `alpha`-combined input row fails to pin down the two hands
separately: the honest and claimed evaluations differ, yet their `alpha`-combinations agree.

This is the price of the code using one random-combination constraint
(`got = wc[0] + alpha * wc[1]`, `zk_common.h:L133`) instead of two.
-/
def InputBindingBad {F : Type} [Field F] (WL WR eL eR alpha : F) : Prop :=
  (WL ≠ eL ∨ WR ≠ eR) ∧ WL + alpha * WR = eL + alpha * eR

/--
At most one `alpha` in the whole field is bad, so the input binding costs `1/|F|`.

`alpha` is a fresh Fiat–Shamir challenge (`Elt alpha = tsv.elt(F)` at `zk_common.h:L131`),
so this is the Schwartz–Zippel error term of the input binding.
-/
lemma input_binding_bad_card {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (WL WR eL eR : F) :
    (Finset.univ.filter (fun alpha => InputBindingBad WL WR eL eR alpha)).card ≤ 1 := by
  apply Finset.card_le_one.mpr
  intro a ha b hb
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
  obtain ⟨hne, hae⟩ := ha
  obtain ⟨-, hbe⟩ := hb
  have hWR : eR - WR ≠ 0 := by
    intro h0
    have hWReq : WR = eR := by linear_combination -h0
    have hWLeq : WL = eL := by
      rw [hWReq] at hae; linear_combination hae
    rcases hne with h | h
    · exact h hWLeq
    · exact h hWReq
  have ha' : (WL - eL) = a * (eR - WR) := by linear_combination hae
  have hb' : (WL - eL) = b * (eR - WR) := by linear_combination hbe
  have : (a - b) * (eR - WR) = 0 := by linear_combination hb' - ha'
  rcases mul_eq_zero.mp this with h | h
  · exact sub_eq_zero.mp h
  · exact absurd h hWR

/-- Outside the bad set, the single combined row does pin down both hands. -/
lemma alpha_separates {F : Type} [Field F] (WL WR eL eR alpha : F)
    (hgood : ¬ InputBindingBad WL WR eL eR alpha)
    (h : WL + alpha * WR = eL + alpha * eR) : WL = eL ∧ WR = eR := by
  by_contra hc
  exact hgood ⟨by tauto, h⟩


/--
**The cost of the random-combination trick, counted.**

Split the sample space as `D × F`, where `D` is everything decided *before* the challenge is
drawn and the second coordinate is the challenge itself — the same shape
`card_filter_prefix_r` uses for sumcheck round challenges.  Then out of the `|D| * |F|` runs
at most `|D|` have a bad challenge: a `1/|F|` fraction.

This is what turns `IsLigeroKnowledgeSound.alpha_good` from an assumption into an error
term.  The same statement covers `LayerAlphaBad` (`layers.lean`), which is
`InputBindingBad`-shaped by construction.
-/
theorem alpha_bad_card {D : Type} [Fintype D] {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (WL WR eL eR : D → F) :
    (Finset.filter (fun p : D × F =>
        InputBindingBad (WL p.1) (WR p.1) (eL p.1) (eR p.1) p.2) Finset.univ).card
      ≤ Fintype.card D := by
  rw [card_prod_filter (fun d a => InputBindingBad (WL d) (WR d) (eL d) (eR d) a)]
  calc ∑ d : D, (Finset.filter (fun a : F =>
        InputBindingBad (WL d) (WR d) (eL d) (eR d) a) Finset.univ).card
      ≤ ∑ _d : D, 1 := Finset.sum_le_sum (fun d _ => input_binding_bad_card _ _ _ _)
    _ = Fintype.card D := by simp


/-!
`EncTranscript` and `EncTranscript.decrypt` now live in `builder.lean`: the encrypted
transcript is a list of `ConstraintBuilder` rounds, and its `polys` / `challenges` / `e` are
*derived* from them rather than being independent fields whose relationship had to be
assumed.
-/
