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


/-!
## Bilinear forms over a finite field

`begin_layer` draws two challenges back to back, and the honest layer claim is affine in each
of them, i.e. a **bilinear form**.  These three lemmas are everything the `2/|F|` bound needs,
and they are pure finite-field counting — no circuit, no protocol.  They live here rather than
in `instantiate.lean` because both the single-layer track (`event_degenerate_card`) and the
multi-layer track (`layer_claim_zero_card`) use them.
-/

/-- An affine function with a non-zero coefficient has at most one root. -/
lemma affine_root_card {F : Type} [Field F] [Fintype F] [DecidableEq F] (u v : F) (h : ¬ (u = 0 ∧ v = 0)) :
    (Finset.filter (fun b : F => u + b * v = 0) Finset.univ).card ≤ 1 := by
  refine Finset.card_le_one.mpr (fun a ha b hb => ?_)
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
  by_cases hv : v = 0
  · exact absurd ⟨by rw [hv] at ha; linear_combination ha, hv⟩ h
  · have hz : (a - b) * v = 0 := by linear_combination ha - hb
    rcases mul_eq_zero.mp hz with h1 | h1
    · linear_combination h1
    · exact absurd h1 hv

/--
**The four corners are a certificate, not a restriction.**

`alpha` and `beta` range over the whole field — they are Fiat–Shamir challenges
(`begin_layer`, `transcript_sumcheck.h:L54`).  But the claim `S(beta, alpha)` is a *bilinear*
form, so it is determined by four coefficients, and those four coefficients vanish exactly
when `S` vanishes at `(0,0)`, `(0,1)`, `(1,0)`, `(1,1)`.  The corner form is therefore
equivalent to "identically zero on `F × F`", and is what `ArithmetizedCircuit.arith` negates:
a finite, checkable certificate for a statement about the whole field.
-/
lemma bilinear_corners_iff {F : Type} [Field F] (S : F → F → F) (c00 c10 c01 c11 : F)
    (hS : ∀ b a : F, S b a = c00 + a * c10 + b * c01 + a * b * c11) :
    (∀ b a : F, S b a = 0) ↔ (S 0 0 = 0 ∧ S 0 1 = 0 ∧ S 1 0 = 0 ∧ S 1 1 = 0) := by
  constructor
  · intro h; exact ⟨h 0 0, h 0 1, h 1 0, h 1 1⟩
  · rintro ⟨h00, h01, h10, h11⟩
    rw [hS 0 0] at h00
    rw [hS 0 1] at h01
    rw [hS 1 0] at h10
    rw [hS 1 1] at h11
    have e00 : c00 = 0 := by linear_combination h00
    have e10 : c10 = 0 := by linear_combination h01 - h00
    have e01 : c01 = 0 := by linear_combination h10 - h00
    have e11 : c11 = 0 := by linear_combination h11 - h01 - h10 + h00
    intro b a
    rw [hS b a, e00, e10, e01, e11]; ring

/--
**Two-variable Schwartz–Zippel.**  A bilinear form that is not identically zero vanishes on
at most `2·|F|` of the `|F|²` pairs.  Here `p.1` is `beta` and `p.2` is `alpha`.
-/
lemma bilinear_zero_card {F : Type} [Field F] [Fintype F] [DecidableEq F] (S : F → F → F) (c00 c10 c01 c11 : F)
    (hS : ∀ b a : F, S b a = c00 + a * c10 + b * c01 + a * b * c11)
    (hne : ¬ (c00 = 0 ∧ c10 = 0 ∧ c01 = 0 ∧ c11 = 0)) :
    (Finset.filter (fun p : F × F => S p.1 p.2 = 0) Finset.univ).card
      ≤ 2 * Fintype.card F := by
  classical
  set Bset : Finset F :=
    Finset.filter (fun b : F => c10 + b * c11 = 0 ∧ c00 + b * c01 = 0) Finset.univ with hBset
  have hBcard : Bset.card ≤ 1 := by
    by_cases hc : c10 = 0 ∧ c11 = 0
    · have h2 : ¬ (c00 = 0 ∧ c01 = 0) := fun h2 => hne ⟨h2.1, hc.1, h2.2, hc.2⟩
      refine le_trans (Finset.card_le_card ?_) (affine_root_card (F := F) c00 c01 h2)
      intro b hb
      simp only [hBset, Finset.mem_filter, Finset.mem_univ, true_and] at hb ⊢
      exact hb.2
    · refine le_trans (Finset.card_le_card ?_) (affine_root_card (F := F) c10 c11 hc)
      intro b hb
      simp only [hBset, Finset.mem_filter, Finset.mem_univ, true_and] at hb ⊢
      exact hb.1
  set B1 : Finset (F × F) :=
    Finset.filter (fun p : F × F => ¬ (c10 + p.1 * c11 = 0) ∧ S p.1 p.2 = 0) Finset.univ with hB1
  set B2 : Finset (F × F) := Bset ×ˢ (Finset.univ : Finset F) with hB2
  have hsub : Finset.filter (fun p : F × F => S p.1 p.2 = 0) Finset.univ ⊆ B1 ∪ B2 := by
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp
    by_cases hc : c10 + p.1 * c11 = 0
    · refine Finset.mem_union_right _ (Finset.mem_product.mpr ⟨?_, Finset.mem_univ _⟩)
      simp only [hBset, Finset.mem_filter, Finset.mem_univ, true_and]
      refine ⟨hc, ?_⟩
      rw [hS p.1 p.2] at hp
      linear_combination hp - p.2 * hc
    · exact Finset.mem_union_left _ (by simp [hB1, hc, hp])
  have h1 : B1.card ≤ Fintype.card F := by
    have hfib : B1.card = ∑ b : F, (B1.filter (fun p => p.1 = b)).card :=
      Finset.card_eq_sum_card_fiberwise (fun p _ => Finset.mem_univ p.1)
    rw [hfib]
    refine le_trans (Finset.sum_le_sum (fun b _ => ?_)) (by simp : ∑ _b : F, 1 ≤ Fintype.card F)
    refine Finset.card_le_one.mpr (fun p hp q hq => ?_)
    simp only [hB1, Finset.mem_filter, Finset.mem_univ, true_and] at hp hq
    obtain ⟨⟨hpv, hpz⟩, hpb⟩ := hp
    obtain ⟨⟨-, hqz⟩, hqb⟩ := hq
    have hb : q.1 = p.1 := by rw [hpb, hqb]
    rw [hS p.1 p.2] at hpz
    rw [hS q.1 q.2, hb] at hqz
    have hz : (p.2 - q.2) * (c10 + p.1 * c11) = 0 := by linear_combination hpz - hqz
    rcases mul_eq_zero.mp hz with h1 | h1
    · exact Prod.ext hb.symm (by linear_combination h1)
    · exact absurd h1 hpv
  calc (Finset.filter (fun p : F × F => S p.1 p.2 = 0) Finset.univ).card
      ≤ (B1 ∪ B2).card := Finset.card_le_card hsub
    _ ≤ B1.card + B2.card := Finset.card_union_le _ _
    _ ≤ Fintype.card F + Fintype.card F := by
        refine Nat.add_le_add h1 ?_
        rw [hB2, Finset.card_product, Finset.card_univ]
        calc Bset.card * Fintype.card F ≤ 1 * Fintype.card F := by gcongr
          _ = Fintype.card F := one_mul _
    _ = 2 * Fintype.card F := by ring


/-!
## Counting a challenge against a fixed prefix

The recurring shape of every randomness bound in this development: split the sample space
into "everything decided before the challenge" and the challenge itself.  Whatever the
challenge has to separate is then a *constant* on each fiber, so the per-fiber bad set is
small and the total is `|prefix| · (bad per fiber)`.

These are used by both the single-layer track (`event_alpha_bad_card`,
`event_degenerate_card`) and the multi-layer one (`mevent_degenerate_card`), which is why
they live here rather than in `instantiate.lean`.
-/

/-- A bound of one bad challenge per pre-challenge state gives at most `|D|` bad pairs. -/
lemma pairs_card_le {D F : Type} [Fintype D] [Fintype F] (Q : D → F → Prop)
    (hQ : ∀ d : D, (Finset.filter (fun a : F => Q d a) Finset.univ).card ≤ 1) :
    (Finset.filter (fun p : D × F => Q p.1 p.2) Finset.univ).card ≤ Fintype.card D := by
  rw [card_prod_filter Q]
  calc ∑ d : D, (Finset.filter (fun a : F => Q d a) Finset.univ).card
      ≤ ∑ _d : D, 1 := Finset.sum_le_sum (fun d _ => hQ d)
    _ = Fintype.card D := by simp

/-- `m` bad challenges per pre-challenge state gives at most `|D| · m` bad pairs. -/
lemma pairs_card_le_mul {D C : Type} [Fintype D] [Fintype C] (Q : D → C → Prop) (m : ℕ)
    (hQ : ∀ d : D, (Finset.filter (fun a : C => Q d a) Finset.univ).card ≤ m) :
    (Finset.filter (fun p : D × C => Q p.1 p.2) Finset.univ).card ≤ Fintype.card D * m := by
  rw [card_prod_filter Q]
  calc ∑ d : D, (Finset.filter (fun a : C => Q d a) Finset.univ).card
      ≤ ∑ _d : D, m := Finset.sum_le_sum (fun d _ => hQ d)
    _ = Fintype.card D * m := by simp [mul_comm]

/--
For each pre-challenge state the extractor's output is already fixed, so the quantities the
challenge has to separate are fixed too and at most one challenge is bad.  Hence at most
`|D|` of the `|D| · |F|` pairs are bad — a `1/|F|` fraction.
-/
lemma option_bad_pairs_card {D F A : Type} [Fintype D] [Fintype F]
    (E : D → Option A) (P : D → A → F → Prop)
    (hP : ∀ (d : D) (v : A), (Finset.filter (fun a : F => P d v a) Finset.univ).card ≤ 1) :
    (Finset.filter (fun p : D × F => ∃ v, E p.1 = some v ∧ P p.1 v p.2) Finset.univ).card
      ≤ Fintype.card D := by
  have h := pairs_card_le (D := D) (F := F) (fun d a => ∃ v, E d = some v ∧ P d v a)
    (fun d => by
      cases hd : E d with
      | none =>
        refine le_trans (Finset.card_le_card (t := (∅ : Finset F)) ?_) (by simp)
        intro a ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha
        obtain ⟨v, hv, -⟩ := ha
        exact absurd hv (by simp)
      | some v =>
        refine le_trans (Finset.card_le_card
          (t := Finset.filter (fun a : F => P d v a) Finset.univ) ?_) (hP d v)
        intro a ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
        obtain ⟨u, hu, hPu⟩ := ha
        cases Option.some.inj hu
        exact hPu)
  convert h using 2
  congr!

/--
For each pre-challenge state the extractor's output is already fixed, so the quantities the
challenge has to separate are fixed too and at most one challenge is bad.  Hence at most
`|D| · m` of the pairs are bad.
-/
lemma option_bad_pairs_card_mul {D A C : Type} [Fintype D] [Fintype C] (E : D → Option A)
    (P : D → A → C → Prop) (m : ℕ)
    (hP : ∀ (d : D) (v : A), (Finset.filter (fun a : C => P d v a) Finset.univ).card ≤ m) :
    (Finset.filter (fun p : D × C => ∃ v, E p.1 = some v ∧ P p.1 v p.2) Finset.univ).card
      ≤ Fintype.card D * m := by
  have h := pairs_card_le_mul (D := D) (C := C) (fun d a => ∃ v, E d = some v ∧ P d v a) m
    (fun d => by
      cases hd : E d with
      | none =>
        refine le_trans (Finset.card_le_card (t := (∅ : Finset C)) ?_) (by simp)
        intro a ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha
        obtain ⟨v, hv, -⟩ := ha
        exact absurd hv (by simp)
      | some v =>
        refine le_trans (Finset.card_le_card
          (t := Finset.filter (fun a : C => P d v a) Finset.univ) ?_) (hP d v)
        intro a ha
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha ⊢
        obtain ⟨u, hu, hPu⟩ := ha
        cases Option.some.inj hu
        exact hPu)
  convert h using 2
  congr!

/--
An event that never looks at the last coordinate costs that coordinate's whole size.  This is
how `Event_Degenerate`, which is decided by the layer pair, is counted inside a sample space
that also carries `alpha_in`.
-/
lemma card_filter_fst_le {X Y : Type} [Fintype X] [Fintype Y] (Q : X → Prop)
    [DecidablePred Q] [DecidablePred (fun ω : X × Y => Q ω.1)] (m : ℕ)
    (h : (Finset.filter Q Finset.univ).card ≤ m) :
    (Finset.filter (fun ω : X × Y => Q ω.1) Finset.univ).card ≤ m * Fintype.card Y := by
  have hprod : (Finset.filter (fun ω : X × Y => Q ω.1) Finset.univ)
      = (Finset.filter Q Finset.univ) ×ˢ (Finset.univ : Finset Y) := by
    ext ω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_product, and_true]
  rw [hprod, Finset.card_product, Finset.card_univ]
  exact Nat.mul_le_mul_right _ h

/--
Counting through a `K`-to-one splitting of the sample space into "everything decided before
the challenge" × "the challenge".  This is the same argument as
`challenge_pullback_bound`, for a single challenge instead of a sequence.
-/
lemma card_le_of_split {Ω A B : Type} [Fintype Ω] [Fintype A] [Fintype B]
    [DecidableEq A] [DecidableEq B]
    (data : Ω → A) (alpha : Ω → B) (K : ℕ)
    (huni : ∀ (d : A) (a : B),
      (Finset.filter (fun ω => data ω = d ∧ alpha ω = a) Finset.univ).card ≤ K)
    (Q : A × B → Prop) :
    (Finset.filter (fun ω => Q (data ω, alpha ω)) Finset.univ).card
      ≤ K * (Finset.filter Q Finset.univ).card := by
  rw [card_filter_comp (fun ω => (data ω, alpha ω)) Q]
  calc ∑ y ∈ Finset.filter Q Finset.univ,
        (Finset.filter (fun ω => (data ω, alpha ω) = y) Finset.univ).card
      ≤ ∑ _y ∈ Finset.filter Q Finset.univ, K := by
        refine Finset.sum_le_sum (fun y _ => ?_)
        have h : (Finset.filter (fun ω => (data ω, alpha ω) = y) Finset.univ)
            = Finset.filter (fun ω => data ω = y.1 ∧ alpha ω = y.2) Finset.univ := by
          ext ω; simp [Prod.ext_iff]
        rw [h]; exact huni y.1 y.2
    _ = (Finset.filter Q Finset.univ).card * K := by simp [Finset.sum_const, mul_comm]
    _ = K * (Finset.filter Q Finset.univ).card := by ring

/-!
## Counting through a splitting of the sample space

`card_le_of_split` transports a count from a product to `Ω` at the cost of a fibre factor `K`.
When the two maps *are* a splitting — `(data, coord)` injective — that factor is `1`, and the
count over `Ω` is bounded by the count over the product outright.

This is what lets the per-layer error terms be counted: the protocol's causality is exactly
that for each challenge, the sample space splits as "everything decided before it" times "it",
and each such splitting is supplied as a pair of maps rather than by committing the whole
development to one product encoding.
-/

/-- Bound an event on `Ω` by a count over a product it factors through. -/
lemma event_card_le_split {D B : Type} [Fintype D] [Fintype B]
    [DecidableEq D] [DecidableEq B]
    (dataOf : Ω → D) (coordOf : Ω → B)
    (hinj : Function.Injective (fun ω => (dataOf ω, coordOf ω)))
    (P : Ω → Prop) (Q : D × B → Prop) (hPQ : ∀ ω, P ω → Q (dataOf ω, coordOf ω)) (m : ℕ)
    (hQ : (Finset.filter Q Finset.univ).card ≤ m) :
    event_card (Finset.filter P Finset.univ) ≤ m := by
  classical
  have hsub : Finset.filter P Finset.univ
      ⊆ Finset.filter (fun ω => Q (dataOf ω, coordOf ω)) Finset.univ := by
    intro ω hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
    exact hPQ ω hω
  have hK : ∀ (d : D) (a : B),
      (Finset.filter (fun ω => dataOf ω = d ∧ coordOf ω = a) Finset.univ).card ≤ 1 := by
    intro d a
    refine Finset.card_le_one.mpr (fun x hx y hy => ?_)
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hx hy
    refine hinj ?_
    show (dataOf x, coordOf x) = (dataOf y, coordOf y)
    rw [hx.1, hx.2, hy.1, hy.2]
  refine le_trans (Finset.card_le_card hsub) ?_
  refine le_trans (card_le_of_split dataOf coordOf 1 hK Q) ?_
  rw [one_mul]
  exact hQ

/-!
### Injectivity bounds the count; only a bijection gives the fraction

`event_card_le_split` needs only injectivity, and that is the right hypothesis for what it
concludes — a *count*.  It is **not** enough to read the count as a probability.  Injectivity
embeds `Ω` into `D × B`, so it gives `|Ω| ≤ |D| · |B|` and nothing more; the prefix `D` may be
as large as `Ω` itself, in which case a bound of `|D|` is the trivial bound.

`split_injective_not_pinning` is the counterexample.  `card_of_split_bij` is the fix: a
splitting that is a *bijection* pins `|D| = |Ω| / |B|`, which is what turns `≤ |D|` into
`≤ 1/|B|` of the sample space.
-/

/-- **Injectivity does not pin the prefix size.**  Over a one-point sample space every map is
injective, so the "splitting" carries no information and `|D| = |Ω|`. -/
theorem split_injective_not_pinning :
    Function.Injective (fun _ : Unit => ((), true))
      ∧ Fintype.card Unit ≠ Fintype.card Unit * Fintype.card Bool := by
  refine ⟨fun a b _ => Subsingleton.elim a b, ?_⟩
  decide

omit [Fintype Ω] in
/-- **A bijective splitting pins the prefix size.**  This is the hypothesis the probability
reading needs, and the one injectivity alone does not supply. -/
lemma card_of_split_bij {D B : Type} [Fintype Ω] [Fintype D] [Fintype B]
    (dataOf : Ω → D) (coordOf : Ω → B)
    (hbij : Function.Bijective (fun ω => (dataOf ω, coordOf ω))) :
    Fintype.card Ω = Fintype.card D * Fintype.card B := by
  rw [← Fintype.card_prod]
  exact Fintype.card_of_bijective hbij

/--
**The counts, read as probabilities.**

Purely arithmetic: given the four cardinality equalities that bijective splittings supply, the
multi-layer count divides down to

```
eps_FSK/|Ω|  +  3/|F|  +  nl·(1 + n·d)/|F|
```

Each term is where it should be — `1/|F|` for the input binding, `2/|F|` for the layer pair,
`1/|F|` per layer for the claim combination and `n·d/|F|` per layer for the sumcheck rounds.

The `K` of the round term is `1` here, not a supplied number: a bijective splitting at the
round challenges makes `pair_fiber_le_one` apply.
-/
theorem multi_layer_prob_of_cards {nl n dd eps_FSK t cα cb cd cs cF cΩ : ℕ}
    (hΩα : cΩ = cα * cF) (hΩb : cΩ = cb * cF) (hΩd : cΩ = cd * (cF * cF))
    (hΩs : cΩ = cs * cF ^ n) (hn : 0 < n) (hF : 0 < cF) (hΩpos : 0 < cΩ)
    (hcount : t ≤ eps_FSK + nl * cα + nl * (1 * (cs * (n * dd * cF ^ (n - 1))))
      + cb + cd * (2 * cF)) :
    (t : ℚ) / cΩ
      ≤ (eps_FSK : ℚ) / cΩ + 3 / cF + (nl : ℚ) * (1 + n * dd) / cF := by
  have hFq : (0 : ℚ) < cF := by exact_mod_cast hF
  have hΩq : (0 : ℚ) < cΩ := by exact_mod_cast hΩpos
  have hαpos : 0 < cα := by
    rcases Nat.eq_zero_or_pos cα with h | h
    · rw [h, zero_mul] at hΩα; omega
    · exact h
  have hbpos : 0 < cb := by
    rcases Nat.eq_zero_or_pos cb with h | h
    · rw [h, zero_mul] at hΩb; omega
    · exact h
  have hdpos : 0 < cd := by
    rcases Nat.eq_zero_or_pos cd with h | h
    · rw [h, zero_mul] at hΩd; omega
    · exact h
  have hspos : 0 < cs := by
    rcases Nat.eq_zero_or_pos cs with h | h
    · rw [h, zero_mul] at hΩs; omega
    · exact h
  have hαq : (0 : ℚ) < cα := by exact_mod_cast hαpos
  have hbq : (0 : ℚ) < cb := by exact_mod_cast hbpos
  have hdq : (0 : ℚ) < cd := by exact_mod_cast hdpos
  have hsq : (0 : ℚ) < cs := by exact_mod_cast hspos
  -- the sumcheck power splits off one factor of `|F|`
  have hpow : (cF : ℚ) ^ n = (cF : ℚ) ^ (n - 1) * cF := by
    conv_lhs => rw [show n = (n - 1) + 1 from by omega]
    rw [pow_succ]
  -- term by term
  have e1 : ((nl * cα : ℕ) : ℚ) / cΩ = (nl : ℚ) / cF := by
    rw [hΩα]; push_cast; field_simp; try ring
  have e2 : ((cb : ℕ) : ℚ) / cΩ = 1 / cF := by
    rw [hΩb]; push_cast; field_simp
  have e3 : ((cd * (2 * cF) : ℕ) : ℚ) / cΩ = 2 / cF := by
    rw [hΩd]; push_cast; field_simp; try ring
  have e4 : ((nl * (1 * (cs * (n * dd * cF ^ (n - 1)))) : ℕ) : ℚ) / cΩ
      = (nl : ℚ) * (n * dd) / cF := by
    rw [hΩs]; push_cast [hpow]; field_simp; try ring
  have hstep : (t : ℚ) / cΩ
      ≤ ((eps_FSK + nl * cα + nl * (1 * (cs * (n * dd * cF ^ (n - 1))))
            + cb + cd * (2 * cF) : ℕ) : ℚ) / cΩ := by
    gcongr
  refine le_trans hstep (le_of_eq ?_)
  have hsplit : ((eps_FSK + nl * cα + nl * (1 * (cs * (n * dd * cF ^ (n - 1))))
        + cb + cd * (2 * cF) : ℕ) : ℚ) / cΩ
      = ((eps_FSK : ℕ) : ℚ) / cΩ + ((nl * cα : ℕ) : ℚ) / cΩ
        + ((nl * (1 * (cs * (n * dd * cF ^ (n - 1)))) : ℕ) : ℚ) / cΩ
        + ((cb : ℕ) : ℚ) / cΩ + ((cd * (2 * cF) : ℕ) : ℚ) / cΩ := by
    push_cast; ring
  rw [hsplit, e1, e2, e3, e4]
  field_simp
  try ring
