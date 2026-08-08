import Mathlib
import sumcheck_soundness
import types
import fiat_shamir
import builder
import circuit
import ligero
import lfzk

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Instantiating the error terms, and reading the bound as a probability

`core_soundness_theorem` concludes `eps_FSK + eps_bind + eps_deg + eps_sumcheck` with all four
terms as parameters.  This file discharges the two *randomness* terms against a concrete
sample space and turns the resulting count into a fraction.

## The sample space

Fiat–Shamir challenges are modelled the way `challenge_pullback_bound` models them: the sample space splits into `data ω` — everything decided before the challenge is
drawn — and `alpha ω`, the challenge itself, with no pair `(d, a)` hit more than `K` times.
Taking `Ω = D × F` with `data = Prod.fst`, `alpha = Prod.snd` and `K = 1` is the ideal case:
the challenge is uniform and independent of the proof.

The payoff (`core_soundness_probability`) is that `eps_bind` and `eps_deg` each become
`1/|F|` of the sample space, rather than parameters the caller has to supply.
-/

variable {Ω D F : Type} [Fintype Ω] [Fintype D] [DecidableEq D] [Field F] [Fintype F] [DecidableEq F]

/-! ## Counting through a challenge split -/

omit [Field F] in
/--
Counting through a `K`-to-one splitting of the sample space into "everything decided before
the challenge" × "the challenge".  This is the same argument as
`challenge_pullback_bound`, for a single challenge instead of a sequence.
-/
lemma card_le_of_split (data : Ω → D) (alpha : Ω → F) (K : ℕ)
    (huni : ∀ (d : D) (a : F),
      (Finset.filter (fun ω => data ω = d ∧ alpha ω = a) Finset.univ).card ≤ K)
    (Q : D × F → Prop) :
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

omit [DecidableEq D] [Field F] [DecidableEq F] in
/-- A bound of one bad challenge per pre-challenge state gives at most `|D|` bad pairs. -/
lemma pairs_card_le (Q : D → F → Prop)
    (hQ : ∀ d : D, (Finset.filter (fun a : F => Q d a) Finset.univ).card ≤ 1) :
    (Finset.filter (fun p : D × F => Q p.1 p.2) Finset.univ).card ≤ Fintype.card D := by
  rw [card_prod_filter Q]
  calc ∑ d : D, (Finset.filter (fun a : F => Q d a) Finset.univ).card
      ≤ ∑ _d : D, 1 := Finset.sum_le_sum (fun d _ => hQ d)
    _ = Fintype.card D := by simp

omit [DecidableEq D] [Field F] [DecidableEq F] in
/-- `m` bad challenges per pre-challenge state gives at most `|D| · m` bad pairs. -/
lemma pairs_card_le_mul {C : Type} [Fintype C] [DecidableEq C] (Q : D → C → Prop) (m : ℕ)
    (hQ : ∀ d : D, (Finset.filter (fun a : C => Q d a) Finset.univ).card ≤ m) :
    (Finset.filter (fun p : D × C => Q p.1 p.2) Finset.univ).card ≤ Fintype.card D * m := by
  rw [card_prod_filter Q]
  calc ∑ d : D, (Finset.filter (fun a : C => Q d a) Finset.univ).card
      ≤ ∑ _d : D, m := Finset.sum_le_sum (fun d _ => hQ d)
    _ = Fintype.card D * m := by simp [mul_comm]

omit [DecidableEq D] [Field F] [DecidableEq F] in
/--
For each pre-challenge state the extractor's output is already fixed, so the quantities the
challenge has to separate are fixed too and at most one challenge is bad.  Hence at most
`|D|` of the `|D| · |F|` pairs are bad — a `1/|F|` fraction.
-/
lemma option_bad_pairs_card {A : Type} (E : D → Option A) (P : D → A → F → Prop)
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

omit [DecidableEq D] [Field F] [DecidableEq F] in
/--
For each pre-challenge state the extractor's output is already fixed, so the quantities the
challenge has to separate are fixed too and at most one challenge is bad.  Hence at most
`|D| · m` of the pairs are bad.
-/
lemma option_bad_pairs_card_mul {A C : Type} [Fintype C] [DecidableEq C] (E : D → Option A)
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

/-! ## Counting the two layer challenges

`begin_layer` draws *two* challenges per layer (`transcript_sumcheck.h:L54`): `alpha`, which
combines the two inherited claims, and `beta`, which replaces the coefficient of every
assert-zero gate (`prep_v`, `quad.h:L213`).  The sample space is therefore split as
`D × (F × F)` — everything decided before the layer, then `(beta, alpha)`.

The honest claim `S(beta, alpha)` is affine in each (`layer_claim_affine` and
`layer_claim_affine_quad`), i.e. a bilinear form, so `bilinear_zero_card` bounds its zero set
by `2·|F|` out of `|F|²`.
-/

omit [DecidableEq D] in
/-- An affine function with a non-zero coefficient has at most one root. -/
lemma affine_root_card (u v : F) (h : ¬ (u = 0 ∧ v = 0)) :
    (Finset.filter (fun b : F => u + b * v = 0) Finset.univ).card ≤ 1 := by
  refine Finset.card_le_one.mpr (fun a ha b hb => ?_)
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
  by_cases hv : v = 0
  · exact absurd ⟨by rw [hv] at ha; linear_combination ha, hv⟩ h
  · have hz : (a - b) * v = 0 := by linear_combination ha - hb
    rcases mul_eq_zero.mp hz with h1 | h1
    · linear_combination h1
    · exact absurd h1 hv

omit [Fintype F] [DecidableEq F] in
/--
**The four corners are a certificate, not a restriction.**

`alpha` and `beta` range over the whole field — they are Fiat–Shamir challenges
(`begin_layer`, `transcript_sumcheck.h:L54`).  But the claim `S(beta, alpha)` is a *bilinear*
form, so it is determined by four coefficients, and those four coefficients vanish exactly
when `S` vanishes at `(0,0)`, `(0,1)`, `(1,0)`, `(1,1)`.  The corner form is therefore
equivalent to "identically zero on `F × F`", and is what `ArithmetizedCircuit.arith` negates:
a finite, checkable certificate for a statement about the whole field.
-/
lemma bilinear_corners_iff (S : F → F → F) (c00 c10 c01 c11 : F)
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

omit [DecidableEq D] in
/--
**Two-variable Schwartz–Zippel.**  A bilinear form that is not identically zero vanishes on
at most `2·|F|` of the `|F|²` pairs.  Here `p.1` is `beta` and `p.2` is `alpha`.
-/
lemma bilinear_zero_card (S : F → F → F) (c00 c10 c01 c11 : F)
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

section Events

variable {nc nv nw ninp npub logv logw logc M : ℕ} [SumcheckInterp F]
variable {Circuit Input Witness : Type}

omit [DecidableEq D] in
/-- `eps_bind ≤ |D|·|F|`: the input-binding collision costs a `1/|F|` fraction of
`|D|·|F|²`. -/
theorem event_alpha_bad_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (accepts : D × (F × F) → Prop) (inp : Input) (var_dwR var_dwL : Fin M)
    (T_pre : D → EncTranscript M F)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    event_card (Event_AlphaBad AC accepts inp (fun p => p.2.2) var_dwR var_dwL
        (fun p => T_pre p.1) (fun p => E_pre p.1))
      ≤ Fintype.card D * Fintype.card F := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × (F × F) => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      InputBindingBad (true_evals AC inp v.1 (T_pre p.1).challenges).1
        (true_evals AC inp v.1 (T_pre p.1).challenges).2
        ((T_pre p.1).wc0 + v.2 var_dwL) ((T_pre p.1).wc1 + v.2 var_dwR) p.2.2)
    Finset.univ) ?_) ?_
  · intro p hp
    simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
    obtain ⟨-, w, pad, hE, hbad⟩ := hp
    exact ⟨(w, pad), hE, hbad⟩
  · refine option_bad_pairs_card_mul (D := D) (C := F × F) E_pre
      (fun d v p => InputBindingBad (true_evals AC inp v.1 (T_pre d).challenges).1
        (true_evals AC inp v.1 (T_pre d).challenges).2
        ((T_pre d).wc0 + v.2 var_dwL) ((T_pre d).wc1 + v.2 var_dwR) p.2)
      (Fintype.card F) (fun d v => ?_)
    refine le_trans (Finset.card_le_card (t := (Finset.univ : Finset F) ×ˢ
      Finset.filter (fun a : F =>
        InputBindingBad (true_evals AC inp v.1 (T_pre d).challenges).1
          (true_evals AC inp v.1 (T_pre d).challenges).2
          ((T_pre d).wc0 + v.2 var_dwL) ((T_pre d).wc1 + v.2 var_dwR) a) Finset.univ) ?_) ?_
    · intro q hq
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hq
      exact Finset.mem_product.mpr ⟨Finset.mem_univ _, by simpa using hq⟩
    · rw [Finset.card_product, Finset.card_univ]
      calc Fintype.card F * _ ≤ Fintype.card F * 1 := by
            gcongr; exact input_binding_bad_card _ _ _ _
        _ = Fintype.card F := mul_one _

omit [DecidableEq D] in
/-- `eps_deg ≤ 2·|D|·|F|`: degenerate layer randomness costs a `2/|F|` fraction, one `1/|F|`
for each of the two challenges `begin_layer` draws. -/
theorem event_degenerate_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (accepts : D × (F × F) → Prop) (c : Circuit) (inp : Input)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (hev : ∀ v : AugmentedWitness M F Witness, AC.eval c inp v.1 = false) :
    event_card (Event_Degenerate AC accepts c inp (fun p => p.2.2) (fun p => p.2.1)
        q_challenge g0 g1 (fun p => E_pre p.1))
      ≤ Fintype.card D * (2 * Fintype.card F) := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × (F × F) => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      AC.Degenerate c inp v.1 p.2.2 p.2.1 q_challenge g0 g1) Finset.univ) ?_) ?_
  · intro p hp
    simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
    obtain ⟨-, w, pad, hE, hdeg⟩ := hp
    exact ⟨(w, pad), hE, hdeg⟩
  refine option_bad_pairs_card_mul (D := D) (C := F × F) E_pre
    (fun _d v p => AC.Degenerate c inp v.1 p.2 p.1 q_challenge g0 g1)
    (2 * Fintype.card F) (fun d v => ?_)
  have hb : (Finset.filter (fun p : F × F =>
      layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c p.1) (AC.W_mle inp v.1) p.2 q_challenge g0 g1 = 0)
      Finset.univ).card ≤ 2 * Fintype.card F := by
    refine bilinear_zero_card (F := F)
      (fun b a => layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c b) (AC.W_mle inp v.1) a q_challenge g0 g1)
      (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 0 q_challenge g0 g1)
      (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 1 q_challenge g0 g1
        - layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 0 q_challenge g0 g1)
      (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 1) (AC.W_mle inp v.1) 0 q_challenge g0 g1
        - layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 0 q_challenge g0 g1)
      ((layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 1) (AC.W_mle inp v.1) 1 q_challenge g0 g1
        - layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 1) (AC.W_mle inp v.1) 0 q_challenge g0 g1)
        - (layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 1 q_challenge g0 g1
          - layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 0 q_challenge g0 g1)) ?_ ?_
    · intro b a
      have h1 := layer_claim_affine (nc := nc) (nv := nv) (AC.Quad_mle c b) (AC.W_mle inp v.1) a q_challenge g0 g1
      have h2 := layer_claim_affine_quad (nc := nc) (nv := nv) (AC.Quad_mle c b) (AC.Quad_mle c 0) (AC.Quad_mle c 1) b
        (fun g l r => AC.Quad_mle_affine_beta c b g l r) (AC.W_mle inp v.1) 0 q_challenge g0 g1
      have h3 := layer_claim_affine_quad (nc := nc) (nv := nv) (AC.Quad_mle c b) (AC.Quad_mle c 0) (AC.Quad_mle c 1) b
        (fun g l r => AC.Quad_mle_affine_beta c b g l r) (AC.W_mle inp v.1) 1 q_challenge g0 g1
      linear_combination h1 + (1 - a) * h2 + a * h3
    · intro hz
      refine AC.arith c inp v.1 q_challenge g0 g1 (hev v) ⟨?_, ?_, ?_, ?_⟩
      · show layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 0 q_challenge g0 g1 = 0
        exact hz.1
      · show layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 0) (AC.W_mle inp v.1) 1 q_challenge g0 g1 = 0
        linear_combination hz.1 + hz.2.1
      · show layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 1) (AC.W_mle inp v.1) 0 q_challenge g0 g1 = 0
        linear_combination hz.1 + hz.2.2.1
      · show layer_claim (nc := nc) (nv := nv) (AC.Quad_mle c 1) (AC.W_mle inp v.1) 1 q_challenge g0 g1 = 0
        linear_combination hz.1 + hz.2.1 + hz.2.2.1 + hz.2.2.2
  refine le_trans (Finset.card_le_card ?_) hb
  intro x hx
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hx ⊢
  exact hx

end Events

/-! ## Reading the bound as a probability -/

/--
Turn the count into a fraction of the sample space.  With `|Ω| = |D| · |F|` and the two
randomness terms bounded by `|D|`, each contributes exactly `1/|F|`.
-/
lemma count_to_prob {nD nF a b c e t : ℕ} (hD : 0 < nD) (hF : 0 < nF)
    (ht : t ≤ a + b + c + e) (hb : b ≤ nD * nF) (hc : c ≤ 2 * (nD * nF)) :
    (t : ℚ) / (nD * nF * nF) ≤ (a : ℚ) / (nD * nF * nF) + 3 / nF
      + (e : ℚ) / (nD * nF * nF) := by
  have hDq : (0 : ℚ) < nD := by exact_mod_cast hD
  have hFq : (0 : ℚ) < nF := by exact_mod_cast hF
  have hpos : (0 : ℚ) < (nD : ℚ) * nF * nF := by positivity
  have htq : (t : ℚ) ≤ (a : ℚ) + b + c + e := by exact_mod_cast ht
  have hbq : (b : ℚ) ≤ (nD : ℚ) * nF := by exact_mod_cast hb
  have hcq : (c : ℚ) ≤ 2 * ((nD : ℚ) * nF) := by exact_mod_cast hc
  have h3 : (3 : ℚ) / nF = (3 * ((nD : ℚ) * nF)) / ((nD : ℚ) * nF * nF) := by
    field_simp
  rw [h3, ← add_div, ← add_div, div_le_div_iff_of_pos_right hpos]
  linarith

omit [DecidableEq D] in
/--
**Soundness as a probability, with the randomness terms instantiated.**

Over the sample space `D × F` — everything decided before the layer's combination
coefficient, times the coefficient — the fraction of accepting runs on which the extractor
fails is at most

```
eps_FSK / (|D|·|F|)  +  2/|F|  +  eps_sumcheck / (|D|·|F|)
```

The `2/|F|` is the two random-combination collisions (`Event_AlphaBad` and
`Event_Degenerate`), each discharged by `option_bad_pairs_card` rather than assumed.  The
remaining two terms are Ligero knowledge soundness and the sumcheck bound;
`core_soundness_derived_eps` gives `eps_sumcheck = K · n · d · |F|^(n-1)`, which over
`|D|·|F|` runs is the familiar `n · d / |F|` once `K` and `|D|` are matched up.
-/
theorem core_soundness_probability
    {nc nv nw ninp npub logv logw logc M : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK eps_sumcheck : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (accepts : D × (F × F) → Prop) (C : Circuit) (x : Input)
    (w_ref : Witness) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : D → EncTranscript M F) (E_pre : D → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw) (hD : 0 < Fintype.card D) (hF : 0 < Fintype.card F)
    (hev : ∀ v : AugmentedWitness M F Witness, AC.eval C x v.1 = false)
    (lig : IsLigeroKnowledgeSound AC accepts (fun p => T_pre p.1) C x w_ref
             (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun p => E_pre p.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun p => T_pre p.1))
    (ci : IsSumcheckCorrelationIntractable AC accepts (fun p => T_pre p.1) var_dwR var_dwL C x
            (fun p => E_pre p.1) (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1 eps_sumcheck) :
    (event_card (Event_Fail AC accepts C x (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1
        var_dwR var_dwL (fun p => T_pre p.1) (fun p => E_pre p.1)) : ℚ)
        / (Fintype.card D * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ) / (Fintype.card D * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + (eps_sumcheck : ℚ) / (Fintype.card D * Fintype.card F * Fintype.card F) := by
  refine count_to_prob (b := Fintype.card D * Fintype.card F)
    (c := Fintype.card D * (2 * Fintype.card F)) hD hF ?_ le_rfl (by ring_nf; omega)
  exact core_soundness_theorem (eps_FSK := eps_FSK) (eps_sumcheck := eps_sumcheck)
      AC accepts C x w_ref (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1
      var_dwR var_dwL var_dwL_dwR (fun p => T_pre p.1) (fun p => E_pre p.1) hpos lig
      (Fintype.card D * Fintype.card F) (Fintype.card D * (2 * Fintype.card F))
      (event_alpha_bad_card AC accepts x var_dwR var_dwL T_pre E_pre)
      (event_degenerate_card AC accepts C x q_challenge g0 g1 E_pre hev) wf ci

/-!
## Removing `K`

`K` bounds the fibers of `challenge_map : Ω → (Fin n → F)`: how many runs share a challenge
sequence.  It appears because `event_card` counts over `Ω` while `combinatorial_fiat_shamir`
counts over challenge sequences, so pulling the bound back multiplies by the fiber size.

Left as a parameter it is meaningless — a reader cannot tell whether `K = 1` or
`K = |Ω|`.  Three facts pin it down:

* `card_le_K_mul` — **`K ≥ |Ω| / |F|^n` always**, by pigeonhole.  So `K` is a *load* factor,
  not something a better hash drives to `1`; it cannot be smaller than the average fiber.
* `regular_fiber_card` — for a **regular** map (all fibers equal, the defining property of an
  ideal hash) that lower bound is attained: `K = |Ω| / |F|^n` exactly.
* `split_fiber_card` — when the challenge sequence is literally a coordinate of the sample
  space, `h_unif` is a *theorem* with `K = |A|`, and the map is regular.

Since the bound is `K · n · d · |F|^(n-1)` out of `|Ω|`, the `K = |Ω|/|F|^n` case gives
exactly `n·d/|F|` — the textbook sumcheck error.  `K` cancels.  `sumcheck_prob_of_split` and
`core_soundness_probability_ideal_fs` are that statement.

What this does *not* do is remove the idealisation.  In the real protocol
`r_i = H(transcript_i)` is *determined* by `ω`, not an independent coordinate of it; making
it a coordinate is the random-oracle / ideal-Fiat–Shamir model.  The gain is that the
idealisation is now visible in the shape of the sample space and provably optimal, instead
of hiding inside an unexplained constant.
-/


/-- **`K` can never be smaller than the average load.** -/
lemma card_le_K_mul {F : Type} [Fintype F] [DecidableEq F] {n : ℕ}
    (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ cs : Fin n → F,
      (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card ≤ K) :
    Fintype.card Ω ≤ K * (Fintype.card F) ^ n := by
  classical
  have hfib : (Finset.univ : Finset Ω).card
      = ∑ cs ∈ (Finset.univ : Finset (Fin n → F)),
          (Finset.univ.filter (fun ω => challenge_map ω = cs)).card :=
    Finset.card_eq_sum_card_fiberwise (fun ω _ => Finset.mem_univ (challenge_map ω))
  calc Fintype.card Ω = _ := by rw [Fintype.card, hfib]
    _ ≤ ∑ _cs ∈ (Finset.univ : Finset (Fin n → F)), K :=
        Finset.sum_le_sum (fun cs _ => h_unif cs)
    _ = (Fintype.card F) ^ n * K := by
        rw [Finset.sum_const, Finset.card_univ, smul_eq_mul, Fintype.card_fun, Fintype.card_fin]
    _ = K * (Fintype.card F) ^ n := by ring

/-- A challenge map is **regular** when every challenge sequence has the same number of
preimages.  This is the defining property of an ideal Fiat–Shamir hash. -/
def IsRegularChallengeMap {F : Type} [Fintype F] [DecidableEq F] {n : ℕ}
    (challenge_map : Ω → (Fin n → F)) : Prop :=
  ∀ cs cs' : Fin n → F,
    (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card
      = (Finset.filter (fun ω => challenge_map ω = cs') Finset.univ).card

/-- For a regular map the pigeonhole bound is an equality: every fiber has exactly the
average load, so the smallest admissible `K` is `|Ω| / |F|^n`. -/
lemma regular_fiber_card {F : Type} [Fintype F] [DecidableEq F] {n : ℕ}
    (challenge_map : Ω → (Fin n → F)) (hreg : IsRegularChallengeMap challenge_map)
    (cs : Fin n → F) :
    (Fintype.card F) ^ n * (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card
      = Fintype.card Ω := by
  have hfib : Fintype.card Ω
      = ∑ cs' ∈ (Finset.univ : Finset (Fin n → F)),
          (Finset.univ.filter (fun ω => challenge_map ω = cs')).card :=
    Finset.card_eq_sum_card_fiberwise (fun ω _ => Finset.mem_univ (challenge_map ω))
  have hconst : ∑ cs' ∈ (Finset.univ : Finset (Fin n → F)),
        (Finset.univ.filter (fun ω => challenge_map ω = cs')).card
      = ∑ _cs' ∈ (Finset.univ : Finset (Fin n → F)),
        (Finset.univ.filter (fun ω => challenge_map ω = cs)).card :=
    Finset.sum_congr rfl (fun cs' _ => hreg cs' cs)
  rw [hfib, hconst, Finset.sum_const, Finset.card_univ, smul_eq_mul, Fintype.card_fun,
      Fintype.card_fin]

/-- **The split sample space: `h_unif` is a theorem.**  When the challenge sequence is a
coordinate of the sample space, the fiber over `cs` is exactly the rest of the space. -/
lemma split_fiber_card {A F : Type} [Fintype A] [Fintype F] [DecidableEq F] {n : ℕ}
    (cs : Fin n → F) :
    (Finset.filter (fun ω : A × (Fin n → F) => ω.2 = cs) Finset.univ).card
      = Fintype.card A := by
  classical
  have h : (Finset.filter (fun ω : A × (Fin n → F) => ω.2 = cs) Finset.univ)
      = Finset.image (fun a : A => (a, cs)) Finset.univ := by
    ext ω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_image]
    constructor
    · intro h
      exact ⟨ω.1, by cases ω; simp_all⟩
    · rintro ⟨a, rfl⟩
      rfl
  rw [h, Finset.card_image_of_injective _ (fun a b hab => (Prod.ext_iff.mp hab).1),
      Finset.card_univ]

/-- The split sample space is regular. -/
lemma split_regular {A F : Type} [Fintype A] [Fintype F] [DecidableEq F] {n : ℕ} :
    IsRegularChallengeMap (fun ω : A × (Fin n → F) => ω.2) := by
  intro cs cs'
  simp only [split_fiber_card]

/-- The fiber of a *middle* coordinate: `Ω = (A × challenges) × B`. -/
lemma mid_fiber_card {A B F : Type} [Fintype A] [Fintype B] [Fintype F] [DecidableEq F] {n : ℕ}
    (cs : Fin n → F) :
    (Finset.filter (fun ω : (A × (Fin n → F)) × B => ω.1.2 = cs) Finset.univ).card
      = Fintype.card A * Fintype.card B := by
  have h : (Finset.filter (fun ω : (A × (Fin n → F)) × B => ω.1.2 = cs) Finset.univ)
      = Finset.image (fun p : A × B => ((p.1, cs), p.2)) Finset.univ := by
    ext ω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_image]
    constructor
    · intro h
      exact ⟨(ω.1.1, ω.2), by obtain ⟨⟨a, c⟩, b⟩ := ω; simp_all⟩
    · rintro ⟨p, rfl⟩
      rfl
  rw [h, Finset.card_image_of_injective _ ?inj, Finset.card_univ, Fintype.card_prod]
  case inj =>
    intro p p' hpp
    have h1 : p.1 = p'.1 := congrArg (fun x => x.1.1) hpp
    have h2 : p.2 = p'.2 := congrArg (fun x => x.2) hpp
    exact Prod.ext h1 h2

/-- The arithmetic behind "`K` cancels": `K · n · d · |F|^(n-1)` over `|Ω| = K · |F|^n`. -/
lemma prob_of_split_arith (t cA cF nn dd : ℕ) (hA : 0 < cA) (hF : 0 < cF) (hn : 0 < nn)
    (ht : t ≤ cA * (nn * dd * cF ^ (nn - 1))) :
    (t : ℚ) / (cA * cF ^ nn) ≤ (nn : ℚ) * dd / cF := by
  have hAq : (0 : ℚ) < cA := by exact_mod_cast hA
  have hFq : (0 : ℚ) < cF := by exact_mod_cast hF
  have hPq : (0 : ℚ) < (cF : ℚ) ^ (nn - 1) := pow_pos hFq _
  have htq : (t : ℚ) ≤ cA * (nn * dd * (cF : ℚ) ^ (nn - 1)) := by exact_mod_cast ht
  have hpow : ((cF : ℚ)) ^ nn = (cF : ℚ) ^ (nn - 1) * cF := by
    conv_lhs => rw [show nn = (nn - 1) + 1 by omega]
    rw [pow_succ]
  rw [hpow, div_le_div_iff₀ (by positivity) hFq]
  calc (t : ℚ) * cF ≤ (cA * (nn * dd * (cF : ℚ) ^ (nn - 1))) * cF :=
        mul_le_mul_of_nonneg_right htq (le_of_lt hFq)
    _ = (nn : ℚ) * dd * ((cA : ℚ) * ((cF : ℚ) ^ (nn - 1) * cF)) := by ring

/--
**`eps_sumcheck` as a probability, with `K` gone.**

Over the sample space `A × (Fin n → F)` — everything decided before the challenges, times
the challenge sequence itself — `h_unif` is a *theorem* with `K = |A|`, and `|A|` cancels
against `|Ω| = |A| · |F|^n`.  What is left is the textbook sumcheck error `n·d/|F|`, with no
free parameter at all.
-/
theorem sumcheck_prob_of_split {A F : Type} [Fintype A] [Field F] [Fintype F] [DecidableEq F]
    [SumcheckInterp F] {n d : ℕ} (fs : IsFiatShamirTranscript F n d)
    (hA : 0 < Fintype.card A) (hn : 0 < n) :
    ((Finset.filter (fun ω : A × (Fin n → F) =>
        any_bad_event n fs.P_func fs.p_func ω.2) Finset.univ).card : ℚ)
      / Fintype.card (A × (Fin n → F))
      ≤ (n : ℚ) * d / Fintype.card F := by
  have hci := challenge_pullback_bound (Ω := A × (Fin n → F)) fs
    (fun ω => ω.2) (Fintype.card A) (fun cs => le_of_eq (split_fiber_card cs))
  have hcard : Fintype.card (A × (Fin n → F)) = Fintype.card A * Fintype.card F ^ n := by
    rw [Fintype.card_prod, Fintype.card_fun, Fintype.card_fin]
  rw [hcard]
  push_cast
  exact prob_of_split_arith _ _ _ _ _ hA Fintype.card_pos hn hci

/--
**Soundness as a probability, with `K` eliminated.**

Same as `core_soundness_probability`, but the sample space is
`(D₀ × challenges) × F` — everything decided before the challenges, the challenge sequence,
and the layer coefficient — so `h_unif` holds by `mid_fiber_card` with
`K = |D₀|·|F|`, and that `K` cancels against `|Ω|`.  The bound

```
eps_FSK / |Ω|  +  2/|F|  +  n·d/|F|
```

has no `K` and no `eps_sumcheck` in it.  With `d = 2` the last term is `2n/|F|`.
-/
theorem core_soundness_probability_ideal_fs
    {D₀ F : Type} [Fintype D₀] [DecidableEq D₀] [Field F] [Fintype F] [DecidableEq F]
    {nc nv nw ninp npub logv logw logc M n d : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (fs : IsFiatShamirTranscript F n d)
    (accepts : (D₀ × (Fin n → F)) × (F × F) → Prop) (C : Circuit) (x : Input)
    (w_ref : Witness) (q_challenge : Vector F logc)
    (g0 g1 : Vector F logv) (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : D₀ × (Fin n → F) → EncTranscript M F)
    (E_pre : D₀ × (Fin n → F) → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw) (hD : 0 < Fintype.card D₀) (hF : 0 < Fintype.card F)
    (hn : 0 < n)
    (hev : ∀ v : AugmentedWitness M F Witness, AC.eval C x v.1 = false)
    (lig : IsLigeroKnowledgeSound AC accepts (fun p => T_pre p.1) C x w_ref
             (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun p => E_pre p.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun p => T_pre p.1))
    (na : IsNonAdaptiveRun AC fs accepts (fun p => T_pre p.1) var_dwR var_dwL C x
            (fun p => E_pre p.1) (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1
            (fun ω => ω.1.2)) :
    (event_card (Event_Fail AC accepts C x (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1
        var_dwR var_dwL (fun p => T_pre p.1) (fun p => E_pre p.1)) : ℚ)
        / (Fintype.card (D₀ × (Fin n → F)) * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ) / (Fintype.card (D₀ × (Fin n → F)) * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + (n : ℚ) * d / Fintype.card F := by
  have hcardD : Fintype.card (D₀ × (Fin n → F)) = Fintype.card D₀ * Fintype.card F ^ n := by
    rw [Fintype.card_prod, Fintype.card_fun, Fintype.card_fin]
  have hDpos : 0 < Fintype.card (D₀ × (Fin n → F)) := by
    rw [hcardD]; exact Nat.mul_pos hD (Nat.pow_pos hF)
  have ci := sumcheck_ci_of_nonadaptive AC fs accepts (fun p => T_pre p.1) var_dwR var_dwL C x
      (fun p => E_pre p.1) (fun p => p.2.2) (fun p => p.2.1) q_challenge g0 g1 (fun ω => ω.1.2)
      (Fintype.card D₀ * Fintype.card (F × F)) (fun cs => le_of_eq (mid_fiber_card cs)) na
  refine le_trans (core_soundness_probability (D := D₀ × (Fin n → F)) eps_FSK _ AC accepts C x
    w_ref q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR T_pre E_pre hpos hDpos hF hev
    lig wf ci) ?_
  gcongr ?_ + ?_ + ?_
  · exact le_rfl
  · exact le_rfl
  have harith := prob_of_split_arith
      ((Fintype.card D₀ * Fintype.card (F × F)) * (n * d * Fintype.card F ^ (n - 1)))
      (Fintype.card D₀ * Fintype.card (F × F)) (Fintype.card F) n d
      (Nat.mul_pos hD (by rw [Fintype.card_prod]; exact Nat.mul_pos hF hF)) hF hn le_rfl
  have hden : ((Fintype.card (D₀ × (Fin n → F)) : ℚ)) * Fintype.card F * Fintype.card F
      = ((Fintype.card D₀ * Fintype.card (F × F) : ℕ) : ℚ) * (Fintype.card F : ℚ) ^ n := by
    rw [hcardD]; simp [Fintype.card_prod]; ring
  rw [hden]
  exact harith
