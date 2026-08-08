import Mathlib
import sumcheck_soundness
import types
import fiat_shamir
import builder
import circuit
import ligero
import fs_derive
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

Fiat–Shamir challenges are modelled the way `uniform_hash_is_correlation_intractable` models
them: the sample space splits into `data ω` — everything decided before the challenge is
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
`uniform_hash_is_correlation_intractable`, for a single challenge instead of a sequence.
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

/-! ## The two randomness terms, discharged

Both events are `InputBindingBad`-shaped in the challenge, with the other four arguments
determined by the pre-challenge data, so `option_bad_pairs_card` applies to each.
-/

section Events

variable {nc nv ninp logv logw logc M : ℕ} [Fintype (Vector F logv)] [SumcheckInterp F]
variable {Circuit Input Witness : Type}

omit [DecidableEq D] in
/-- `eps_bind ≤ |D|`: the input-binding collision costs a `1/|F|` fraction. -/
theorem event_alpha_bad_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : D × F → Prop) (var_dwR var_dwL : Fin M)
    (T_pre : D → EncTranscript M F)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    event_card (Event_AlphaBad AC accepts Prod.snd var_dwR var_dwL
        (fun p => T_pre p.1) (fun p => E_pre p.1))
      ≤ Fintype.card D := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × F => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      InputBindingBad (true_evals AC v.1 (T_pre p.1).challenges).1
        (true_evals AC v.1 (T_pre p.1).challenges).2
        ((T_pre p.1).wc0 + v.2 var_dwL) ((T_pre p.1).wc1 + v.2 var_dwR) p.2)
    Finset.univ) ?_)
    (option_bad_pairs_card (D := D) (F := F) E_pre
      (fun d v => InputBindingBad (true_evals AC v.1 (T_pre d).challenges).1
        (true_evals AC v.1 (T_pre d).challenges).2
        ((T_pre d).wc0 + v.2 var_dwL) ((T_pre d).wc1 + v.2 var_dwR))
      (fun d v => input_binding_bad_card _ _ _ _))
  intro p hp
  simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
  obtain ⟨-, w, pad, hE, hbad⟩ := hp
  exact ⟨(w, pad), hE, hbad⟩

omit [DecidableEq D] in
/-- `eps_deg ≤ |D|`: the degenerate layer coefficient costs a `1/|F|` fraction. -/
theorem event_degenerate_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : D × F → Prop) (c : Circuit)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    event_card (Event_Degenerate AC accepts c Prod.snd q_challenge g0 g1 (fun p => E_pre p.1))
      ≤ Fintype.card D := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × F => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      AC.Degenerate c v.1 p.2 q_challenge g0 g1) Finset.univ) ?_)
    (option_bad_pairs_card (D := D) (F := F) E_pre
      (fun d v a => AC.Degenerate c v.1 a q_challenge g0 g1)
      (fun d v => input_binding_bad_card _ _ _ _))
  intro p hp
  simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
  obtain ⟨-, w, pad, hE, hdeg⟩ := hp
  exact ⟨(w, pad), hE, hdeg⟩

end Events

/-! ## Reading the bound as a probability -/

/--
Turn the count into a fraction of the sample space.  With `|Ω| = |D| · |F|` and the two
randomness terms bounded by `|D|`, each contributes exactly `1/|F|`.
-/
lemma count_to_prob {nD nF a b c e t : ℕ} (hD : 0 < nD) (hF : 0 < nF)
    (ht : t ≤ a + b + c + e) (hb : b ≤ nD) (hc : c ≤ nD) :
    (t : ℚ) / (nD * nF) ≤ (a : ℚ) / (nD * nF) + 2 / nF + (e : ℚ) / (nD * nF) := by
  have hDq : (0 : ℚ) < nD := by exact_mod_cast hD
  have hFq : (0 : ℚ) < nF := by exact_mod_cast hF
  have hpos : (0 : ℚ) < (nD : ℚ) * nF := mul_pos hDq hFq
  have htq : (t : ℚ) ≤ (a : ℚ) + b + c + e := by exact_mod_cast ht
  have hbq : (b : ℚ) ≤ nD := by exact_mod_cast hb
  have hcq : (c : ℚ) ≤ nD := by exact_mod_cast hc
  have h2 : (2 : ℚ) / nF = (2 * (nD : ℚ)) / ((nD : ℚ) * nF) := by field_simp
  rw [h2, ← add_div, ← add_div, div_le_div_iff_of_pos_right hpos]
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
    {nc nv ninp logv logw logc M : ℕ} [Fintype (Vector F logv)] [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK eps_sumcheck : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : D × F → Prop) (C : Circuit) (x : Input) (npub : ℕ)
    (pub_binding : D × F → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : D → EncTranscript M F) (E_pre : D → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw) (hD : 0 < Fintype.card D) (hF : 0 < Fintype.card F)
    (lig : IsLigeroKnowledgeSound AC accepts (fun p => T_pre p.1) C npub pub_binding
             Prod.snd q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR (fun p => E_pre p.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun p => T_pre p.1))
    (ci : IsSumcheckCorrelationIntractable AC accepts (fun p => T_pre p.1) var_dwR var_dwL C
            (fun p => E_pre p.1) Prod.snd q_challenge g0 g1 eps_sumcheck) :
    (event_card (Event_Fail AC accepts C x Prod.snd q_challenge g0 g1 var_dwR var_dwL
        (fun p => T_pre p.1) (fun p => E_pre p.1)) : ℚ)
        / (Fintype.card D * Fintype.card F)
      ≤ (eps_FSK : ℚ) / (Fintype.card D * Fintype.card F)
        + 2 / Fintype.card F
        + (eps_sumcheck : ℚ) / (Fintype.card D * Fintype.card F) := by
  refine count_to_prob (b := Fintype.card D) (c := Fintype.card D) hD hF ?_ le_rfl le_rfl
  exact core_soundness_theorem (eps_FSK := eps_FSK) (eps_sumcheck := eps_sumcheck)
      AC accepts C x npub pub_binding Prod.snd q_challenge g0 g1
      var_dwR var_dwL var_dwL_dwR (fun p => T_pre p.1) (fun p => E_pre p.1) hpos lig
      (Fintype.card D) (Fintype.card D)
      (event_alpha_bad_card AC accepts var_dwR var_dwL T_pre E_pre)
      (event_degenerate_card AC accepts C q_challenge g0 g1 E_pre) wf ci
