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

## The sample space, in protocol order

A one-layer run samples three field elements, and it samples them at three different moments:

    ZkProver::commit       begin_layer        rounds        elt_field
    witness + pad,   -->   (beta, alpha) -->  challenges -->  alpha_in
    prover coins (D)          F × F                             F

The sample space is therefore `Ω = (D × (F × F)) × F`, and the protocol's causality is
expressed by *which coordinates each object is allowed to read*:

* `E_pre : D → Option (…)` — the extractor's output depends on the commitment alone.
  `ZkProver::commit` (`rust/runtime/zk/src/prover.rs:L44`) fixes the witness and the pad
  before the transcript exists, so this is a fact about the protocol, not a restriction on
  the adversary.
* `T_pre : D × (F × F) → EncTranscript` — the prover's messages *may* depend on the layer
  challenges, because `begin_layer` (`rust/runtime/sumcheck/src/transcript.rs:L106`) precedes
  every message of the layer.
* `alpha_in = ω.2` — read by nothing else.  It is the fresh challenge drawn after all layers
  have closed (`symbolic_sumcheck_verifier.rs:L247`).

Both refinements matter.  If `T_pre` were a function of `D` alone the transcript could not
react to `(alpha, beta)` even though the prover sees them first; and a single `alpha` serving
as both the layer coefficient and the input-binding coefficient would let the two fail
together on one draw.

Fiat–Shamir challenges themselves are modelled the way `challenge_pullback_bound` models them:
the space splits into "everything decided before the challenge" and the challenge, with no
pair hit more than `K` times.  Making the challenge a coordinate is the ideal case, `K = 1`
per prefix.

The payoff (`core_soundness_probability`) is that `eps_bind` and `eps_deg` stop being
parameters: they become `1/|F|` and `2/|F|` of the sample space.
-/

variable {Ω D F : Type} [Fintype Ω] [Fintype D] [DecidableEq D] [Field F] [Fintype F] [DecidableEq F]

/-! ## Counting through a challenge split -/

/-! ## Counting the two layer challenges

`begin_layer` draws *two* challenges per layer (`transcript.rs:L106`, `transcript_sumcheck.h:L54`):
`alpha`, which combines the two inherited claims, and `beta`, which replaces the coefficient of
every assert-zero gate (`prep_v`, `quad.h:L213`).  They are drawn back to back, before any of
the layer's messages, so the pair is a single coordinate `F × F` of the sample space — written
`(beta, alpha)` here, the reverse of the draw order, which has no bearing on the count.

The honest claim `S(beta, alpha)` is affine in each (`layer_claim_affine` and
`layer_claim_affine_quad`), i.e. a bilinear form, so `bilinear_zero_card` bounds its zero set
by `2·|F|` out of `|F|²`.
-/

section Events

variable {nc nv ninp npub logv logw logc M : ℕ} [SumcheckInterp F]
variable {Circuit Input Witness : Type}

omit [DecidableEq D] in
/--
`eps_bind ≤ |D|·|F|²`: the input-binding collision costs a `1/|F|` fraction of `|D|·|F|³`.

The counting works because `alpha_in` is the **last** coordinate.  Fix a point of
`D × (F × F)` — the commitment and the layer pair — and both the extracted witness/pad
(through `E_pre`, which does not even read the layer pair) and the transcript's `wc0`/`wc1`
(through `T_pre`, which does) are determined.  So the two quantities the input row must
separate are constants, and `input_binding_bad_card` leaves at most one bad `alpha_in`.
-/
theorem event_alpha_bad_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : (D × (F × F)) × F → Prop) (inp : Input) (var_dwR var_dwL : Fin M)
    (T_pre : D × (F × F) → EncTranscript M F)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    event_card (Event_AlphaBad AC accepts inp (fun ω => ω.2) var_dwR var_dwL
        (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1))
      ≤ Fintype.card D * Fintype.card F * Fintype.card F := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun ω : (D × (F × F)) × F => ∃ v : AugmentedWitness M F Witness, E_pre ω.1.1 = some v ∧
      InputBindingBad (true_evals AC inp v.1 (T_pre ω.1).challenges).1
        (true_evals AC inp v.1 (T_pre ω.1).challenges).2
        ((T_pre ω.1).wc0 + v.2 var_dwL) ((T_pre ω.1).wc1 + v.2 var_dwR) ω.2)
    Finset.univ) ?_) ?_
  · intro ω hω
    simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
    obtain ⟨-, w, pad, hE, hbad⟩ := hω
    exact ⟨(w, pad), hE, hbad⟩
  · refine le_trans (option_bad_pairs_card (D := D × (F × F)) (F := F) (fun q => E_pre q.1)
      (fun q v a => InputBindingBad (true_evals AC inp v.1 (T_pre q).challenges).1
        (true_evals AC inp v.1 (T_pre q).challenges).2
        ((T_pre q).wc0 + v.2 var_dwL) ((T_pre q).wc1 + v.2 var_dwR) a)
      (fun q v => input_binding_bad_card _ _ _ _)) (le_of_eq ?_)
    simp [Fintype.card_prod, mul_assoc]

omit [DecidableEq D] [SumcheckInterp F] in
/--
**Two-variable Schwartz–Zippel on the layer pair.**  On the prefix `D × (F × F)` — the
commitment and the two challenges `begin_layer` draws — at most `|D|·2|F|` points are
degenerate.  This is the heart of `event_degenerate_card`; the outer theorem just carries it
across the `alpha_in` coordinate.
-/
theorem degenerate_pairs_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    (Finset.filter (fun p : D × (F × F) => ∃ v : AugmentedWitness M F Witness,
        E_pre p.1 = some v ∧ (AC.Degenerate c inp v.1 p.2.2 p.2.1 q_challenge g0 g1
          ∧ AC.eval c inp v.1 = false)) Finset.univ).card
      ≤ Fintype.card D * (2 * Fintype.card F) := by
  have hfib : ∀ (_d : D) (v : AugmentedWitness M F Witness),
      (Finset.filter (fun p : F × F =>
        AC.Degenerate c inp v.1 p.2 p.1 q_challenge g0 g1 ∧ AC.eval c inp v.1 = false)
        Finset.univ).card ≤ 2 * Fintype.card F := by
    intro _d v
    by_cases hev : AC.eval c inp v.1 = false
    case neg =>
      refine le_trans (Finset.card_le_card (t := (∅ : Finset (F × F))) ?_) (by simp)
      intro p hp
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp
      exact absurd hp.2 hev
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
        have h1 := layer_claim_affine (nc := nc) (nv := nv) (AC.Quad_mle c b) (AC.W_mle inp v.1)
          a q_challenge g0 g1
        have h2 := layer_claim_affine_quad (nc := nc) (nv := nv) (AC.Quad_mle c b)
          (AC.Quad_mle c 0) (AC.Quad_mle c 1) b
          (fun g l r => AC.Quad_mle_affine_beta c b g l r) (AC.W_mle inp v.1) 0 q_challenge g0 g1
        have h3 := layer_claim_affine_quad (nc := nc) (nv := nv) (AC.Quad_mle c b)
          (AC.Quad_mle c 0) (AC.Quad_mle c 1) b
          (fun g l r => AC.Quad_mle_affine_beta c b g l r) (AC.W_mle inp v.1) 1 q_challenge g0 g1
        linear_combination h1 + (1 - a) * h2 + a * h3
      · intro hz
        refine AC.arith c inp v.1 q_challenge g0 g1 hev ⟨?_, ?_, ?_, ?_⟩
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
    exact hx.1
  have hmain := option_bad_pairs_card_mul (D := D) (C := F × F) E_pre
    (fun _d v p => AC.Degenerate c inp v.1 p.2 p.1 q_challenge g0 g1
      ∧ AC.eval c inp v.1 = false) (2 * Fintype.card F)
    (fun d v => le_trans (Finset.card_le_card (fun x hx => by
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hx ⊢; exact hx)) (hfib d v))
  refine le_trans (le_of_eq ?_) hmain
  congr 1
  ext p
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]

omit [DecidableEq D] in
/--
`eps_deg ≤ 2·|D|·|F|²`: degenerate layer randomness costs a `2/|F|` fraction, one `1/|F|` for
each of the two challenges `begin_layer` draws.

The event is decided by the prefix `D × (F × F)` alone — it never reads `alpha_in` — so the
bound is `degenerate_pairs_card` on that prefix, carried across the whole `alpha_in`
coordinate by `card_filter_fst_le`.
-/
theorem event_degenerate_card
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : (D × (F × F)) × F → Prop) (c : Circuit) (inp : Input)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_pre : D → Option (AugmentedWitness M F Witness)) :
    event_card (Event_Degenerate AC accepts c inp (fun ω => ω.1.2.2) (fun ω => ω.1.2.1)
        q_challenge g0 g1 (fun ω => E_pre ω.1.1))
      ≤ Fintype.card D * (2 * Fintype.card F) * Fintype.card F := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun ω : (D × (F × F)) × F => ∃ v : AugmentedWitness M F Witness, E_pre ω.1.1 = some v ∧
      (AC.Degenerate c inp v.1 ω.1.2.2 ω.1.2.1 q_challenge g0 g1
        ∧ AC.eval c inp v.1 = false)) Finset.univ) ?_) ?_
  · intro ω hω
    simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
    obtain ⟨-, w, pad, hE, hdeg⟩ := hω
    exact ⟨(w, pad), hE, hdeg⟩
  refine card_filter_fst_le (X := D × (F × F)) (Y := F)
    (fun p => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      (AC.Degenerate c inp v.1 p.2.2 p.2.1 q_challenge g0 g1 ∧ AC.eval c inp v.1 = false))
    (Fintype.card D * (2 * Fintype.card F)) ?_
  exact le_trans (Finset.card_le_card (fun p hp => by
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢; exact hp))
    (degenerate_pairs_card AC c inp q_challenge g0 g1 E_pre)

/-!
### The same two counts, over an abstract sample space

`event_alpha_bad_card` and `event_degenerate_card` are stated at a literal product, which fixes
one ordering of the coordinates.  The protocol's causality is really a family of *splittings* —
for each challenge, "everything decided before it" and "it" — and stating it that way lets the
coordinates sit in the order the protocol draws them rather than the order the proof found
convenient.  `event_card_le_split` transports each count at no cost.
-/

/-- `eps_bind`, over any sample space that splits at `alpha_in`. -/
theorem event_alpha_bad_card_split {P : Type} [Fintype P] [DecidableEq P]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (inp : Input) (var_dwR var_dwL : Fin M)
    (dataOf : Ω → P) (ainOf : Ω → F)
    (hinj : Function.Injective (fun ω => (dataOf ω, ainOf ω)))
    (T_pre : P → EncTranscript M F) (E_pre : P → Option (AugmentedWitness M F Witness)) :
    event_card (Event_AlphaBad AC accepts inp ainOf var_dwR var_dwL
        (fun ω => T_pre (dataOf ω)) (fun ω => E_pre (dataOf ω)))
      ≤ Fintype.card P := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : P × F → Prop, Q = fun p =>
      ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
        InputBindingBad (true_evals AC inp v.1 (T_pre p.1).challenges).1
          (true_evals AC inp v.1 (T_pre p.1).challenges).2
          ((T_pre p.1).wc0 + v.2 var_dwL) ((T_pre p.1).wc1 + v.2 var_dwR) p.2 := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card ≤ Fintype.card P := by
    refine le_trans (Finset.card_le_card ?_)
      (option_bad_pairs_card E_pre
        (fun d v a => InputBindingBad (true_evals AC inp v.1 (T_pre d).challenges).1
          (true_evals AC inp v.1 (T_pre d).challenges).2
          ((T_pre d).wc0 + v.2 var_dwL) ((T_pre d).wc1 + v.2 var_dwR) a)
        (fun d v => input_binding_bad_card _ _ _ _))
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf ainOf hinj
    (fun ω => accepts ω ∧ ∃ w pad, E_pre (dataOf ω) = some (w, pad) ∧
      InputBindingBad (true_evals AC inp w (T_pre (dataOf ω)).challenges).1
        (true_evals AC inp w (T_pre (dataOf ω)).challenges).2
        ((T_pre (dataOf ω)).wc0 + pad var_dwL) ((T_pre (dataOf ω)).wc1 + pad var_dwR) (ainOf ω))
    Q (fun ω hω => by
      obtain ⟨-, w, pad, hE, hbad⟩ := hω
      rw [hQdef]
      exact ⟨(w, pad), hE, hbad⟩)
    (Fintype.card P) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

/-- `eps_deg`, over any sample space that splits at the layer's `(beta, alpha)` pair. -/
theorem event_degenerate_card_split {P : Type} [Fintype P] [DecidableEq P]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (dataOf : Ω → P) (pairOf : Ω → F × F)
    (hinj : Function.Injective (fun ω => (dataOf ω, pairOf ω)))
    (E_pre : P → Option (AugmentedWitness M F Witness)) :
    event_card (Event_Degenerate AC accepts c inp (fun ω => (pairOf ω).2)
        (fun ω => (pairOf ω).1) q_challenge g0 g1 (fun ω => E_pre (dataOf ω)))
      ≤ Fintype.card P * (2 * Fintype.card F) := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : P × (F × F) → Prop, Q = fun p =>
      ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
        (AC.Degenerate c inp v.1 p.2.2 p.2.1 q_challenge g0 g1 ∧
          AC.eval c inp v.1 = false) := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card ≤ Fintype.card P * (2 * Fintype.card F) := by
    refine le_trans (Finset.card_le_card ?_)
      (degenerate_pairs_card (D := P) AC c inp q_challenge g0 g1 E_pre)
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf pairOf hinj
    (fun ω => accepts ω ∧ ∃ w pad, E_pre (dataOf ω) = some (w, pad) ∧
      (AC.Degenerate c inp w ((pairOf ω).2) ((pairOf ω).1) q_challenge g0 g1 ∧
        AC.eval c inp w = false))
    Q (fun ω hω => by
      obtain ⟨-, w, pad, hE, hdeg⟩ := hω
      rw [hQdef]
      exact ⟨(w, pad), hE, hdeg⟩)
    (Fintype.card P * (2 * Fintype.card F)) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

end Events

/-! ## Reading the bound as a probability -/

/--
Turn the count into a fraction of the sample space.  The space is `|Ω| = |D|·|F|³` — the
commitment, the layer pair, and `alpha_in` — and the two randomness terms are bounded by
`|D|·|F|²` and `2·|D|·|F|²`, so they contribute `1/|F|` and `2/|F|`.
-/
lemma count_to_prob {nD nF a b c e t : ℕ} (hD : 0 < nD) (hF : 0 < nF)
    (ht : t ≤ a + b + c + e) (hb : b ≤ nD * nF * nF) (hc : c ≤ 2 * (nD * nF * nF)) :
    (t : ℚ) / (nD * nF * nF * nF) ≤ (a : ℚ) / (nD * nF * nF * nF) + 3 / nF
      + (e : ℚ) / (nD * nF * nF * nF) := by
  have hDq : (0 : ℚ) < nD := by exact_mod_cast hD
  have hFq : (0 : ℚ) < nF := by exact_mod_cast hF
  have hpos : (0 : ℚ) < (nD : ℚ) * nF * nF * nF := by positivity
  have htq : (t : ℚ) ≤ (a : ℚ) + b + c + e := by exact_mod_cast ht
  have hbq : (b : ℚ) ≤ (nD : ℚ) * nF * nF := by exact_mod_cast hb
  have hcq : (c : ℚ) ≤ 2 * ((nD : ℚ) * nF * nF) := by exact_mod_cast hc
  have h3 : (3 : ℚ) / nF = (3 * ((nD : ℚ) * nF * nF)) / ((nD : ℚ) * nF * nF * nF) := by
    field_simp
  rw [h3, ← add_div, ← add_div, div_le_div_iff_of_pos_right hpos]
  linarith

omit [DecidableEq D] in
/--
**Soundness as a probability, with the randomness terms instantiated.**

Over the sample space `(D × (F × F)) × F` — the commitment, the layer pair `begin_layer`
draws, and the fresh input-binding `alpha_in` — the fraction of accepting runs on which the
extractor fails is at most

```
eps_FSK / (|D|·|F|³)  +  3/|F|  +  eps_sumcheck / (|D|·|F|³)
```

The `3/|F|` is `1/|F|` for the `alpha_in` collision (`Event_AlphaBad`) plus `2/|F|` for the
layer pair collapsing the claim (`Event_Degenerate`), each *counted* rather than assumed.  The
remaining two terms are Ligero knowledge soundness and the sumcheck bound;
`core_soundness_derived_eps` gives `eps_sumcheck = K · n · d · |F|^(n-1)`, which is the
familiar `n · d / |F|` once `K` and the sample space are matched up.

The transcript is `T_pre : D × (F × F) → EncTranscript`, so the prover's messages may depend
on `(alpha, beta)` — which they do, since `begin_layer` runs first.  The extractor is
`E_pre : D → …`, fixed at commitment time.
-/
theorem core_soundness_probability
    {nc nv ninp npub logv logw logc M : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK eps_sumcheck : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : (D × (F × F)) × F → Prop) (C : Circuit) (x : Input)
    (w_ref : Witness) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : D × (F × F) → EncTranscript M F)
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw) (hD : 0 < Fintype.card D) (hF : 0 < Fintype.card F)
    (lig : IsLigeroKnowledgeSound AC accepts (fun ω => T_pre ω.1) C x w_ref
             (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
             q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun ω => E_pre ω.1.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun ω => T_pre ω.1))
    (ci : IsSumcheckCorrelationIntractable AC accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
            (fun ω => E_pre ω.1.1) (fun ω => ω.1.2.2) (fun ω => ω.1.2.1)
            q_challenge g0 g1 eps_sumcheck) :
    (event_card (Event_Fail AC accepts C x (fun ω => ω.1.2.2) (fun ω => ω.1.2.1)
        q_challenge g0 g1 var_dwR var_dwL (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1)) : ℚ)
        / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ) / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + (eps_sumcheck : ℚ)
            / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F) := by
  refine count_to_prob (b := Fintype.card D * Fintype.card F * Fintype.card F)
    (c := Fintype.card D * (2 * Fintype.card F) * Fintype.card F) hD hF ?_ le_rfl
    (le_of_eq (by ring))
  exact core_soundness_theorem (eps_FSK := eps_FSK) (eps_sumcheck := eps_sumcheck)
      AC accepts C x w_ref (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
      q_challenge g0 g1
      var_dwR var_dwL var_dwL_dwR (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) hpos lig
      (Fintype.card D * Fintype.card F * Fintype.card F)
      (Fintype.card D * (2 * Fintype.card F) * Fintype.card F)
      (event_alpha_bad_card AC accepts x var_dwR var_dwL T_pre E_pre)
      (event_degenerate_card AC accepts C x q_challenge g0 g1 E_pre) wf ci

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

/--
**The fiber of a challenge coordinate, wherever it sits.**

If the sample space factors as "everything else" × "the challenge sequence" — for *any*
placement of the coordinate, expressed by a bijection rather than a literal product shape —
then every fiber has exactly `|A|` elements, so `h_unif` holds with `K = |A|` and the map is
regular.  The placements used below (last, second-of-two, and buried at `ω.1.1.2`) are all
instances.
-/
lemma fiber_card_of_coord {A F : Type} [Fintype A] [Fintype F] [DecidableEq F] {n : ℕ}
    {Ω : Type} [Fintype Ω] (chal : Ω → (Fin n → F)) (rest : Ω → A)
    (hbij : Function.Bijective (fun ω => (rest ω, chal ω)))
    (cs : Fin n → F) :
    (Finset.filter (fun ω => chal ω = cs) Finset.univ).card = Fintype.card A := by
  classical
  rw [← Finset.card_univ (α := A)]
  refine Finset.card_bij (fun ω _ => rest ω) (fun _ _ => Finset.mem_univ _) ?_ ?_
  · intro ω hω ω' hω' h
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω hω'
    refine hbij.1 ?_
    show (rest ω, chal ω) = (rest ω', chal ω')
    rw [h, hω, hω']
  · intro a _
    obtain ⟨ω, hω⟩ := hbij.2 (a, cs)
    have h1 : rest ω = a := congrArg Prod.fst hω
    have h2 : chal ω = cs := congrArg Prod.snd hω
    exact ⟨ω, by simp [h2], h1⟩

/-- **The split sample space: `h_unif` is a theorem.**  When the challenge sequence is a
coordinate of the sample space, the fiber over `cs` is exactly the rest of the space. -/
lemma split_fiber_card {A F : Type} [Fintype A] [Fintype F] [DecidableEq F] {n : ℕ}
    (cs : Fin n → F) :
    (Finset.filter (fun ω : A × (Fin n → F) => ω.2 = cs) Finset.univ).card
      = Fintype.card A :=
  fiber_card_of_coord (fun ω => ω.2) (fun ω => ω.1)
    ⟨fun _ _ h => by simpa [Prod.ext_iff] using h, fun p => ⟨p, rfl⟩⟩ cs

/-- The split sample space is regular. -/
lemma split_regular {A F : Type} [Fintype A] [Fintype F] [DecidableEq F] {n : ℕ} :
    IsRegularChallengeMap (fun ω : A × (Fin n → F) => ω.2) := by
  intro cs cs'
  simp only [split_fiber_card]

/--
**When the pre-state and the challenges together *are* the sample point, `K = 1`.**

`sumcheck_ci_of_nonadaptive` bounds the fibers of the *pair* `(state, challenge_map)` — how
many runs share both a pre-challenge state and a challenge sequence.  If that pair is
injective, as it is when the two are complementary coordinates of the sample space, there is
at most one such run, so the idealisation costs nothing beyond making the challenges a
coordinate at all.
-/
lemma pair_fiber_le_one {S B Ω : Type} [Fintype Ω] [DecidableEq S] [DecidableEq B]
    (state : Ω → S) (chal : Ω → B)
    (hinj : Function.Injective (fun ω => (state ω, chal ω))) (s : S) (cs : B) :
    (Finset.filter (fun ω => state ω = s ∧ chal ω = cs) Finset.univ).card ≤ 1 := by
  refine Finset.card_le_one.mpr (fun a ha b hb => ?_)
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at ha hb
  refine hinj ?_
  show (state a, chal a) = (state b, chal b)
  rw [ha.1, ha.2, hb.1, hb.2]

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

Same as `core_soundness_probability`, but every source of randomness is now a coordinate, in
protocol order:

```
Ω = ((D₀ × challenges) × (beta, alpha)) × alpha_in
```

The Fiat–Shamir strategy is indexed by the **pre-challenge state**
`S = (D₀ × (beta, alpha)) × alpha_in` — everything the run decides other than the challenges.
Together, `state` and `challenge_map` recover the sample point, so `pair_fiber_le_one` gives
`K = 1`, and the `|S|` factor in `sumcheck_ci_of_nonadaptive`'s bound cancels against
`|Ω| = |S|·|F|^n`.  The bound

```
eps_FSK / |Ω|  +  3/|F|  +  n·d/|F|
```

has no `K`, no `|S|` and no `eps_sumcheck` in it.  With `d = 2` the last term is `2n/|F|`.

Indexing by the pre-state is what makes this inhabitable at all.  With a single global
strategy, round 0's empty prefix would force every accepted run to transmit the same first
polynomial, and the *honest* side would be outright false as soon as `alpha` varies — see
`honest_polys_need_state` (`example.lean`).

The one liberty taken is that the sumcheck challenges sit *before* the layer pair in the
product while the protocol draws them after.  Nothing in the argument reads the order: what
matters is that `T_pre` may depend on both, `E_pre` on neither, and `alpha_in` on nothing —
and putting the challenges earlier only widens what `T_pre` and `E_pre` are allowed to see.
-/
theorem core_soundness_probability_ideal_fs
    {D₀ F : Type} [Fintype D₀] [DecidableEq D₀] [Field F] [Fintype F] [DecidableEq F]
    {nc nv ninp npub logv logw logc M n d : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (fam : IsFiatShamirFamily ((D₀ × (F × F)) × F) F n d)
    (accepts : ((D₀ × (Fin n → F)) × (F × F)) × F → Prop) (C : Circuit) (x : Input)
    (w_ref : Witness) (q_challenge : Vector F logc)
    (g0 g1 : Vector F logv) (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : (D₀ × (Fin n → F)) × (F × F) → EncTranscript M F)
    (E_pre : D₀ × (Fin n → F) → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw) (hD : 0 < Fintype.card D₀) (hF : 0 < Fintype.card F)
    (hn : 0 < n)
    (lig : IsLigeroKnowledgeSound AC accepts (fun ω => T_pre ω.1) C x w_ref
             (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
             q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun ω => E_pre ω.1.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun ω => T_pre ω.1))
    (na : IsNonAdaptiveRun AC fam accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
            (fun ω => E_pre ω.1.1) (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) q_challenge g0 g1
            (fun ω => ((ω.1.1.1, ω.1.2), ω.2)) (fun ω => ω.1.1.2)) :
    (event_card (Event_Fail AC accepts C x (fun ω => ω.1.2.2) (fun ω => ω.1.2.1)
        q_challenge g0 g1 var_dwR var_dwL (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1)) : ℚ)
        / (Fintype.card (D₀ × (Fin n → F)) * Fintype.card F * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ)
          / (Fintype.card (D₀ × (Fin n → F)) * Fintype.card F * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + (n : ℚ) * d / Fintype.card F := by
  have hcardD : Fintype.card (D₀ × (Fin n → F)) = Fintype.card D₀ * Fintype.card F ^ n := by
    rw [Fintype.card_prod, Fintype.card_fun, Fintype.card_fin]
  have hDpos : 0 < Fintype.card (D₀ × (Fin n → F)) := by
    rw [hcardD]; exact Nat.mul_pos hD (Nat.pow_pos hF)
  -- the pre-state and the challenge sequence together *are* the sample point
  have hinj : Function.Injective
      (fun ω : ((D₀ × (Fin n → F)) × (F × F)) × F => (((ω.1.1.1, ω.1.2), ω.2), ω.1.1.2)) := by
    rintro ⟨⟨⟨d, ch⟩, ab⟩, ain⟩ ⟨⟨⟨d', ch'⟩, ab'⟩, ain'⟩ h
    simp only [Prod.mk.injEq] at h
    obtain ⟨⟨⟨hd, hab⟩, hain⟩, hch⟩ := h
    simp_all
  have ci := sumcheck_ci_of_nonadaptive AC fam accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
      (fun ω => E_pre ω.1.1) (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) q_challenge g0 g1
      (fun ω => ((ω.1.1.1, ω.1.2), ω.2)) (fun ω => ω.1.1.2) 1
      (fun s cs => pair_fiber_le_one _ _ hinj s cs) na
  rw [one_mul] at ci
  refine le_trans (core_soundness_probability (D := D₀ × (Fin n → F)) eps_FSK _ AC accepts C x
    w_ref q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR T_pre E_pre hpos hDpos hF
    lig wf ci) ?_
  gcongr ?_ + ?_ + ?_
  · exact le_rfl
  · exact le_rfl
  have hSpos : 0 < Fintype.card ((D₀ × (F × F)) × F) := by
    simp only [Fintype.card_prod]
    exact Nat.mul_pos (Nat.mul_pos hD (Nat.mul_pos hF hF)) hF
  have harith := prob_of_split_arith
      (Fintype.card ((D₀ × (F × F)) × F) * (n * d * Fintype.card F ^ (n - 1)))
      (Fintype.card ((D₀ × (F × F)) × F)) (Fintype.card F) n d hSpos hF hn le_rfl
  have hden : ((Fintype.card (D₀ × (Fin n → F)) : ℚ))
        * Fintype.card F * Fintype.card F * Fintype.card F
      = ((Fintype.card ((D₀ × (F × F)) × F) : ℕ) : ℚ) * (Fintype.card F : ℚ) ^ n := by
    rw [hcardD]; push_cast [Fintype.card_prod]; ring
  rw [hden]
  exact harith

/--
**The ZK path, with nothing left to supply but `eps_FSK`.**

`core_soundness_probability_ideal_fs` is generic in the round count `n`, the degree bound `d`
and the Fiat–Shamir family, so a caller could instantiate it at any of them — and the README's
claim that `d = 2` is *derived* is only true if the family is the one the arithmetization
determines.  This corollary removes the choice:

* `logc = 0` — the ZK path, where the copy point is a `Vector F 0`;
* `n = 0 + 2·logw` — the round count `ArithmetizedCircuit` fixes, not a parameter;
* `d = 2` — from `famOfArithmetized`, whose `hd` field is
  `round_poly_natDegree_le_two`, i.e. the fact that `WPoly` is `Poly<3>`;
* the family is `famOfArithmetized` itself, so the degree bound applies to the *honest* round
  polynomials (`circuit_true_polys_eq_famOfArithmetized`), not to some unrelated family.

The resulting bound is

```
Pr[accepts ∧ extraction fails]  ≤  eps_FSK/|Ω|  +  3/|F|  +  4·logw/|F|
```

and `eps_FSK` really is the only free parameter left.
-/
theorem zk_soundness_probability
    {D₀ F : Type} [Fintype D₀] [DecidableEq D₀] [Field F] [Fintype F] [DecidableEq F]
    {nc nv ninp npub logv logw M : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (accepts : ((D₀ × (Fin (0 + 2 * logw) → F)) × (F × F)) × F → Prop)
    (C : Circuit) (x : Input) (w_ref : Witness) (q_challenge : Vector F 0)
    (g0 g1 : Vector F logv) (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : (D₀ × (Fin (0 + 2 * logw) → F)) × (F × F) → EncTranscript M F)
    (E_pre : D₀ × (Fin (0 + 2 * logw) → F) → Option (AugmentedWitness M F Witness))
    (wOf : ((D₀ × (F × F)) × F) → Witness) (alphaOf betaOf : ((D₀ × (F × F)) × F) → F)
    (p_func : ((D₀ × (F × F)) × F) → ProverStrategy F (0 + 2 * logw))
    (hpos : 0 < 0 + 2 * logw) (hD : 0 < Fintype.card D₀) (hF : 0 < Fintype.card F)
    (lig : IsLigeroKnowledgeSound AC accepts (fun ω => T_pre ω.1) C x w_ref
             (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
             q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun ω => E_pre ω.1.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := 0) accepts (fun ω => T_pre ω.1))
    (na : IsNonAdaptiveRun AC
            (famOfArithmetized AC C x q_challenge g0 g1 wOf alphaOf betaOf p_func)
            accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
            (fun ω => E_pre ω.1.1) (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) q_challenge g0 g1
            (fun ω => ((ω.1.1.1, ω.1.2), ω.2)) (fun ω => ω.1.1.2)) :
    (event_card (Event_Fail AC accepts C x (fun ω => ω.1.2.2) (fun ω => ω.1.2.1)
        q_challenge g0 g1 var_dwR var_dwL (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1)) : ℚ)
        / (Fintype.card (D₀ × (Fin (0 + 2 * logw) → F))
            * Fintype.card F * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ)
          / (Fintype.card (D₀ × (Fin (0 + 2 * logw) → F))
              * Fintype.card F * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + ((0 + 2 * logw : ℕ) : ℚ) * 2 / Fintype.card F :=
  core_soundness_probability_ideal_fs (D₀ := D₀) (n := 0 + 2 * logw) (d := 2) eps_FSK AC
    (famOfArithmetized AC C x q_challenge g0 g1 wOf alphaOf betaOf p_func)
    accepts C x w_ref q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR T_pre E_pre
    hpos hD hF hpos lig wf na

/-!
## The sample space in protocol order

`core_soundness_probability_ideal_fs` puts the challenge sequence *inside* the extractor's
prefix — `D := D₀ × (Fin n → F)` — so the extractor formally may read it, and the sequence sits
before the layer pair although the protocol draws it after.  Neither breaks the counting, since
widening what the extractor and transcript may see only weakens the hypotheses.  But it is a
safe over-approximation, not the causal order.

This is the causal order:

```
Ω  =  ((D₀ × (beta, alpha)) × round challenges) × alpha_in
```

* `E_pre : D₀ → …` — the extractor reads the **commitment only**, matching `ZkProver::commit`
  fixing the witness and pad before the transcript exists;
* `T_pre : (D₀ × (F × F)) × (Fin n → F) → …` — the prover's messages may depend on the layer
  pair and on the challenges, since both precede them.  That round `i`'s message depends only
  on the prefix through `i−1` is `IsNonAdaptiveRun.prover_eq`, not the product shape;
* `alpha_in` last, read by nothing else.

The counts are unchanged: `|Ω| = |D₀|·|F|^(n+3)`, `eps_bind = |Ω|/|F|`,
`eps_deg = 2·|Ω|/|F|`, and the sumcheck term is `n·d/|F|` after `K = 1` and `|S|` cancel.
-/

/-- The pre-challenge state of a run in protocol order: commitment, layer pair, `alpha_in`. -/
abbrev ProtoState (D₀ F : Type) : Type := (D₀ × (F × F)) × F

/-- The sample space in protocol order. -/
abbrev ProtoΩ (D₀ F : Type) (n : ℕ) : Type := ((D₀ × (F × F)) × (Fin n → F)) × F

/--
**Core soundness over a sample space in protocol order.**

Same bound as `core_soundness_theorem`, with `eps_bind` and `eps_deg` derived rather than
supplied, and with the extractor typed so that it cannot read any challenge.
-/
theorem core_soundness_protocol_order
    {D₀ : Type} [Fintype D₀] [DecidableEq D₀]
    {nc nv ninp npub logv logw logc M n d : ℕ} [SumcheckInterp F]
    [DecidableEq (Fin M)] {Circuit Input Witness : Type} (eps_FSK : ℕ)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (fam : IsFiatShamirFamily (ProtoState D₀ F) F n d)
    (accepts : ProtoΩ D₀ F n → Prop) (C : Circuit) (x : Input) (w_ref : Witness)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_pre : (D₀ × (F × F)) × (Fin n → F) → EncTranscript M F)
    (E_pre : D₀ → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw)
    (lig : IsLigeroKnowledgeSound AC accepts (fun ω => T_pre ω.1) C x w_ref
             (fun ω => ω.1.1.2.2) (fun ω => ω.1.1.2.1) (fun ω => ω.2)
             q_challenge g0 g1 var_dwR var_dwL var_dwL_dwR
             (fun ω => E_pre ω.1.1.1) eps_FSK)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts (fun ω => T_pre ω.1))
    (na : IsNonAdaptiveRun AC fam accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
            (fun ω => E_pre ω.1.1.1) (fun ω => ω.1.1.2.2) (fun ω => ω.1.1.2.1)
            q_challenge g0 g1 (fun ω => ((ω.1.1.1, ω.1.1.2), ω.2)) (fun ω => ω.1.2)) :
    event_card (Event_Fail AC accepts C x (fun ω => ω.1.1.2.2) (fun ω => ω.1.1.2.1)
        q_challenge g0 g1 var_dwR var_dwL (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1.1))
      ≤ eps_FSK
        + Fintype.card ((D₀ × (F × F)) × (Fin n → F))
        + Fintype.card (D₀ × ((Fin n → F) × F)) * (2 * Fintype.card F)
        + 1 * (Fintype.card (ProtoState D₀ F) * (n * d * (Fintype.card F) ^ (n - 1))) := by
  classical
  -- `alpha_in` is the last coordinate: the input binding costs one draw
  have hbind := event_alpha_bad_card_split (Ω := ProtoΩ D₀ F n)
    (P := (D₀ × (F × F)) × (Fin n → F)) AC accepts x var_dwR var_dwL
    (fun ω => ω.1) (fun ω => ω.2)
    (fun a b h => by
      obtain ⟨⟨p, cs⟩, ain⟩ := a; obtain ⟨⟨p', cs'⟩, ain'⟩ := b
      simp only [Prod.mk.injEq] at h ⊢
      exact ⟨h.1, h.2⟩)
    T_pre (fun p => E_pre p.1.1)
  -- the layer pair is a coordinate: the degeneracy costs `2|F|`
  have hdeg := event_degenerate_card_split (Ω := ProtoΩ D₀ F n)
    (P := D₀ × ((Fin n → F) × F)) AC accepts C x q_challenge g0 g1
    (fun ω => (ω.1.1.1, ω.1.2, ω.2)) (fun ω => ω.1.1.2)
    (fun a b h => by
      obtain ⟨⟨⟨d, pr⟩, cs⟩, ain⟩ := a; obtain ⟨⟨⟨d', pr'⟩, cs'⟩, ain'⟩ := b
      simp only [Prod.mk.injEq] at h ⊢
      exact ⟨⟨⟨h.1.1, h.2⟩, h.1.2.1⟩, h.1.2.2⟩)
    (fun p => E_pre p.1)
  -- the challenge sequence is a coordinate, so `K = 1`
  have hinj : Function.Injective
      (fun ω : ProtoΩ D₀ F n => (((ω.1.1.1, ω.1.1.2), ω.2), ω.1.2)) := by
    rintro ⟨⟨⟨d, pr⟩, cs⟩, ain⟩ ⟨⟨⟨d', pr'⟩, cs'⟩, ain'⟩ h
    simp only [Prod.mk.injEq] at h ⊢
    exact ⟨⟨⟨h.1.1.1, h.1.1.2⟩, h.2⟩, h.1.2⟩
  have ci := sumcheck_ci_of_nonadaptive AC fam accepts (fun ω => T_pre ω.1) var_dwR var_dwL C x
    (fun ω => E_pre ω.1.1.1) (fun ω => ω.1.1.2.2) (fun ω => ω.1.1.2.1) q_challenge g0 g1
    (fun ω => ((ω.1.1.1, ω.1.1.2), ω.2)) (fun ω => ω.1.2) 1
    (fun s cs => pair_fiber_le_one _ _ hinj s cs) na
  exact core_soundness_theorem (eps_FSK := eps_FSK)
    (eps_sumcheck := 1 * (Fintype.card (ProtoState D₀ F)
      * (n * d * (Fintype.card F) ^ (n - 1))))
    (AC := AC) (accepts := accepts) (C := C) (x := x) (w_ref := w_ref)
    (alpha := fun ω => ω.1.1.2.2) (beta := fun ω => ω.1.1.2.1) (alpha_in := fun ω => ω.2)
    (q_challenge := q_challenge) (g0 := g0) (g1 := g1)
    (var_dwR := var_dwR) (var_dwL := var_dwL) (var_dwL_dwR := var_dwL_dwR)
    (T_prime := fun ω => T_pre ω.1) (E_Ligero := fun ω => E_pre ω.1.1.1)
    (hpos := hpos) (lig := lig)
    (eps_bind := Fintype.card ((D₀ × (F × F)) × (Fin n → F)))
    (eps_deg := Fintype.card (D₀ × ((Fin n → F) × F)) * (2 * Fintype.card F))
    (h_bind := hbind) (h_deg := hdeg) (wf := wf) (ci := ci)
