import Mathlib
import sumcheck_soundness
import types
import builder
import circuit
import ligero
import layers
import zk_layers
import fiat_shamir

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Multi-layer knowledge soundness

`core_soundness_theorem` (`lfzk.lean`) decomposes the failure event for a *single* layer;
`zk_multi_layer_soundness` (`zk_layers.lean`) runs the reduction across *all* layers but only
tracks the sumcheck error.  This file carries the other bad events through the layers too, so
there is one statement covering the whole proof.

## The decomposition

For a run on which the verifier accepts and the extractor returns `(w, pad)`, exactly one of
the following must go wrong if `w` does not satisfy the circuit:

| Event | Meaning | Bound |
|---|---|---|
| `Event_A` | the extractor returned nothing | `eps_FSK` (Ligero, assumed) |
| `MEvent_Rows` | some layer's Ligero rows fail | `0` — the extractor's guarantee |
| `MEvent_Rand` | some layer's coefficient `alpha` was unlucky | `nl * eps_alpha` |
| `MEvent_Round` | some layer's sumcheck round was lucky | `nl * eps_round` |
| `MEvent_Input` | the input-layer claims are not the committed witness | `eps_bind` |
| `MEvent_Degenerate` | layer 0's `(alpha, beta)` collapsed the output claim | `eps_deg` |

The two `nl *` factors are `union_bound_layers`: each is a disjunction over layers, and
`alpha_bad_card` bounds a single layer's coefficient collision by a `1/|F|` fraction.

## Where `beta` enters

`begin_layer` draws two challenges per layer, and both now appear: `LayerData` and `ZkLayer`
carry `alpha` and `beta`, and `LayeredCircuit.Quad` takes `beta` exactly as
`ArithmetizedCircuit.Quad_mle` does — the two tracks describe the same `QUAD`.

They enter at different places, and it is worth being precise about why:

* `alpha` is counted **per layer** (`MEvent_Rand`).  The layer-to-layer reduction can be
  defeated by a lucky `alpha` at any layer, so the cost scales with depth.
* `beta` is counted **once** (`MEvent_Degenerate`), at layer 0.  Inside `layer_step` a `beta`
  that makes `EQQ` vanish costs nothing — the contradiction there never divides by `EQQ`.
  What `beta` protects is the *start* of the run: both verifiers initialise the output claims
  to zero, so a witness that violates an assert-zero gate is caught only because `prep_v`
  puts `beta` on that gate's coefficient and makes the output claim non-zero.

This is what turned the old hypothesis `harith` — "an unsatisfying witness does not have the
claimed output values" — into `zero_claims_wrong` plus a counted event.  `harith` was doing
the work of the assert-zero mechanism by fiat.

## Uniform layer width

Every layer is assumed to have the same `logw`.  This is a **restriction on the circuits
covered, not a soundness gap**, and it is a genuine WLOG:

* The widths are *public circuit parameters* (`clr->logw`, read from `Circuit<Field>`), not
  values the prover supplies.  A cheating prover has no freedom in them, so restricting them
  removes no adversarial power — the theorem quantifies over fewer circuits, and a weaker
  true statement cannot hide an attack.
* `logw ≤ kMaxBindings = 40` is enforced by the implementation itself
  (`sumcheck/circuit.h:L78`, checked at `verifier_layers.h:L118` and `L166`), and
  `logw > 0` at `zk_common.h:L83`.  So a finite common width `W = max_ly logw_ly ≤ 40`
  always exists, and every layer can be padded up to it with wires that `QUAD` never
  references — which contributes `0` to the layer relation and so preserves it.

What is *not* formalized is that padding transformation; the theorem below is stated for
already-uniform circuits.  Handling varying widths directly would need `LayerState` and
`LayerData` indexed by a width function, with a fold whose type changes at each step — a
dependent-family redesign of `layers.lean` that this WLOG avoids.
-/

variable {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
variable {Witness Circuit Input : Type}
variable {Ω : Type} [Fintype Ω]

section

variable {nc nv logw logc : ℕ}

/-- Some layer's Ligero rows fail even though the extractor succeeded. -/
noncomputable def MEvent_Rows (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ ZkRowsHold LC (betas ω) pad 0 st0 none (T ω)) Finset.univ

/-- The layer coefficient was unlucky at layer `i`. -/
noncomputable def MEvent_RandAt (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (i : ℕ) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    LayerAlphaBadAt LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)) i) Finset.univ

/-- The layer coefficient was unlucky somewhere. -/
noncomputable def MEvent_Rand (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ GoodRandomness LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω))) Finset.univ

/-- A sumcheck round of layer `i` was lucky. -/
noncomputable def MEvent_RoundAt (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (i : ℕ) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    LayerRoundBadAt LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)) i) Finset.univ

/-- A sumcheck round was lucky somewhere. -/
noncomputable def MEvent_Round (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    AnyLayerRoundBad LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω))) Finset.univ

/-- The claims the run ends on are not the honest input-layer values, i.e. the Ligero input
row failed to pin them to the committed witness. -/
noncomputable def MEvent_Input (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ ClaimsCorrect LC (T ω).length w (betas ω) (zkFinalState pad st0 (T ω))) Finset.univ

/--
**Layer 0's randomness collapsed the output claim.**

The run's `(alpha, beta)` — drawn by `begin_layer` before any message of layer 0 — make the
starting claim zero even though the witness fails the circuit.  On this event the verifier's
own initial claims of zero are *correct* as far as the sumcheck can see, and no reduction can
recover anything.

The multi-layer twin of `Event_Degenerate` (`lfzk.lean`), and bounded the same way: the claim
is a bilinear form in `(alpha, beta)`, so `layer_claim_zero_card` gives `2·|F|` out of `|F|²`.
`alpha0` and `beta0` are abstract here, exactly as `alpha`/`beta` are in `lfzk.lean`; making
them coordinates of the sample space is `mevent_degenerate_card`'s job.
-/
noncomputable def MEvent_Degenerate (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F) (alpha0 : Ω → F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ev c inp w = false ∧
      LC.Degenerate w (betas ω) (alpha0 ω) (betas ω 0) st0) Finset.univ

/-- The verifier accepted, yet the extracted witness does not satisfy the circuit. -/
noncomputable def MEvent_Fail (accepts : Ω → Prop)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ (E_L ω = none ∨
    ∃ w pad, E_L ω = some (w, pad) ∧ ev c inp w = false)) Finset.univ

omit [Fintype Ω] [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma union_bound_6 (A B C D E G : Finset Ω) :
    event_card (A ∪ B ∪ C ∪ D ∪ E ∪ G)
      ≤ event_card A + event_card B + event_card C + event_card D + event_card E
        + event_card G := by
  dsimp [event_card]
  linarith [Finset.card_union_le (A ∪ B ∪ C ∪ D ∪ E) G,
    Finset.card_union_le (A ∪ B ∪ C ∪ D) E, Finset.card_union_le (A ∪ B ∪ C) D,
    Finset.card_union_le (A ∪ B) C, Finset.card_union_le A B]

/--
**The multi-layer failure decomposition.**

If the verifier accepted and the extracted witness is wrong, then one of six things went
wrong: extraction failed, some layer's Ligero rows failed, some layer's coefficient was
unlucky, some layer's sumcheck round was lucky, the input-layer claims were not the committed
witness, or layer 0's randomness collapsed the output claim.

`hzero0`/`hzero1` say the run starts from claims of zero, which is how both verifiers
initialise (`claim: [Expression::zero, Expression::zero]` in
`symbolic_sumcheck_verifier.rs`, `verifier_layers.h:L70`).  Given that, `zero_claims_wrong`
*derives* the non-vanishing condition rather than assuming it, leaving only the counted event
`MEvent_Degenerate`.
-/
theorem mevent_fail_subset (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F) (alpha0 : Ω → F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (hpos : 0 < logc + 2 * logw)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω))) :
    MEvent_Fail accepts ev c inp E_L
      ⊆ Event_A accepts E_L ∪ MEvent_Rows LC accepts betas st0 T E_L
        ∪ MEvent_Rand LC accepts betas st0 T E_L ∪ MEvent_Round LC accepts betas st0 T E_L
        ∪ MEvent_Input LC accepts betas st0 T E_L
        ∪ MEvent_Degenerate LC accepts betas st0 alpha0 E_L ev c inp := by
  intro ω hω
  simp only [MEvent_Fail, Event_A, MEvent_Rows, MEvent_Rand, MEvent_Round, MEvent_Input,
    MEvent_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at hω ⊢
  obtain ⟨hacc, hfail⟩ := hω
  cases hfail with
  | inl hnone => exact Or.inl (Or.inl (Or.inl (Or.inl (Or.inl ⟨hacc, hnone⟩))))
  | inr hsome =>
    obtain ⟨w, pad, hE, hev⟩ := hsome
    by_cases hdeg : LC.Degenerate w (betas ω) (alpha0 ω) (betas ω 0) st0
    · exact Or.inr ⟨hacc, w, pad, hE, hev, hdeg⟩
    -- the starting claims are wrong, because non-degenerate randomness says so
    have hwrong : ¬ ClaimsCorrect LC 0 w (betas ω) st0 :=
      zero_claims_wrong LC w (betas ω) (alpha0 ω) st0 hzero0 hzero1 hdeg
    by_cases hrows : ZkRowsHold LC (betas ω) pad 0 st0 none (T ω)
    · by_cases hrand : GoodRandomness LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω))
      · by_cases hround : AnyLayerRoundBad LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω))
        · exact Or.inl (Or.inl (Or.inr ⟨hacc, w, pad, hE, hround⟩))
        · -- rows hold, randomness good, no lucky round: the reduction lands on the input layer
          have h := zk_multi_layer_soundness LC (betas ω) pad w hpos (T ω) st0 hrows
            (hshape ω w pad hacc hE) hrand hwrong
          cases h with
          | inl hbad => exact absurd hbad hround
          | inr hin => exact Or.inl (Or.inr ⟨hacc, w, pad, hE, hin⟩)
      · exact Or.inl (Or.inl (Or.inl (Or.inr ⟨hacc, w, pad, hE, hrand⟩)))
    · exact Or.inl (Or.inl (Or.inl (Or.inl (Or.inr ⟨hacc, w, pad, hE, hrows⟩))))

/-- The per-layer coefficient collisions add up. -/
theorem mevent_rand_card (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (nl eps : ℕ) (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hEps : ∀ i, i < nl → event_card (MEvent_RandAt LC accepts betas st0 T E_L i) ≤ eps) :
    event_card (MEvent_Rand LC accepts betas st0 T E_L) ≤ nl * eps := by
  have h := union_bound_layers nl eps
    (fun i ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      LayerAlphaBadAt LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)) i)
    (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      ¬ GoodRandomness LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)))
    (by
      rintro ω ⟨hacc, w, pad, hE, hbad⟩
      obtain ⟨i, hi, hb⟩ := notGoodRandomness_exists LC w (betas ω) (zkLayerDatas pad st0 (T ω)) 0 st0 hbad
      exact ⟨i, lt_of_lt_of_le (by simpa using hi) (hnl ω), hacc, w, pad, hE, hb⟩)
    (fun i hi => by
      refine le_trans (Finset.card_le_card ?_) (hEps i hi)
      intro ω hω
      simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
      exact hω)
  refine le_trans (Finset.card_le_card ?_) h
  intro ω hω
  simp only [MEvent_Rand, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

/-- The per-layer sumcheck luck adds up. -/
theorem mevent_round_card (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (nl eps : ℕ) (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hEps : ∀ i, i < nl → event_card (MEvent_RoundAt LC accepts betas st0 T E_L i) ≤ eps) :
    event_card (MEvent_Round LC accepts betas st0 T E_L) ≤ nl * eps := by
  have h := union_bound_layers nl eps
    (fun i ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      LayerRoundBadAt LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)) i)
    (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      AnyLayerRoundBad LC w (betas ω) 0 st0 (zkLayerDatas pad st0 (T ω)))
    (by
      rintro ω ⟨hacc, w, pad, hE, hbad⟩
      obtain ⟨i, hi, hb⟩ := anyLayerRoundBad_exists LC w (betas ω) (zkLayerDatas pad st0 (T ω)) 0 st0 hbad
      exact ⟨i, lt_of_lt_of_le (by simpa using hi) (hnl ω), hacc, w, pad, hE, hb⟩)
    (fun i hi => by
      refine le_trans (Finset.card_le_card ?_) (hEps i hi)
      intro ω hω
      simp only [MEvent_RoundAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
      exact hω)
  refine le_trans (Finset.card_le_card ?_) h
  intro ω hω
  simp only [MEvent_Round, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

/--
**Multi-layer knowledge soundness.**

The whole proof, all layers, with every error term carried through:

```
|Event_Fail|  ≤  eps_FSK  +  nl · eps_alpha  +  nl · eps_round  +  eps_bind  +  eps_deg
```

`MEvent_Rows` contributes nothing: the Ligero extractor's guarantee is exactly that the
rows hold, so that event is empty.

This is the statement `core_soundness_theorem` gives for one layer, now for `nl` of them, and
with the same two randomness terms: `eps_alpha` per layer for the claim combination, and a
single `eps_deg` for the `(alpha, beta)` pair that could collapse the output claim.  The two
`nl ·` factors are summed by `union_bound_layers`; `eps_FSK`, `eps_bind` and `eps_deg` are
per-run and do not scale with depth.

`eps_deg` replaces the old hypothesis `harith`, which asserted outright that an unsatisfying
witness gives wrong output claims.  That is now `zero_claims_wrong` — a theorem — with the
residual randomness condition counted at `2/|F|` by `layer_claim_zero_card`.
-/
theorem multi_layer_core_soundness (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F) (alpha0 : Ω → F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (nl eps_FSK eps_alpha eps_round eps_bind eps_deg : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω)))
    (h_extract : event_card (Event_A accepts E_L) ≤ eps_FSK)
    (h_rows : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      ZkRowsHold LC (betas ω) pad 0 st0 none (T ω))
    (h_alpha : ∀ i, i < nl →
      event_card (MEvent_RandAt LC accepts betas st0 T E_L i) ≤ eps_alpha)
    (h_round : ∀ i, i < nl →
      event_card (MEvent_RoundAt LC accepts betas st0 T E_L i) ≤ eps_round)
    (h_bind : event_card (MEvent_Input LC accepts betas st0 T E_L) ≤ eps_bind)
    (h_deg : event_card (MEvent_Degenerate LC accepts betas st0 alpha0 E_L ev c inp)
      ≤ eps_deg) :
    event_card (MEvent_Fail accepts ev c inp E_L)
      ≤ eps_FSK + nl * eps_alpha + nl * eps_round + eps_bind + eps_deg := by
  have h_sub := Finset.card_le_card
    (mevent_fail_subset LC accepts betas st0 alpha0 T E_L ev c inp hpos hzero0 hzero1 hshape)
  have h_ub := union_bound_6 (Event_A accepts E_L) (MEvent_Rows LC accepts betas st0 T E_L)
    (MEvent_Rand LC accepts betas st0 T E_L) (MEvent_Round LC accepts betas st0 T E_L)
    (MEvent_Input LC accepts betas st0 T E_L)
    (MEvent_Degenerate LC accepts betas st0 alpha0 E_L ev c inp)
  have h_rows0 : event_card (MEvent_Rows LC accepts betas st0 T E_L) = 0 := by
    have hempty : MEvent_Rows LC accepts betas st0 T E_L = ∅ := by
      ext ω
      simp only [MEvent_Rows, Finset.mem_filter, Finset.mem_univ, true_and]
      constructor
      · rintro ⟨hacc, w, pad, hE, hno⟩
        exact absurd (h_rows ω w pad hacc hE) hno
      · intro hc; exact absurd hc (by simp)
    simp [event_card, hempty]
  have h_r := mevent_rand_card LC accepts betas st0 T E_L nl eps_alpha hnl h_alpha
  have h_c := mevent_round_card LC accepts betas st0 T E_L nl eps_round hnl h_round
  dsimp [event_card] at *
  linarith

/-!
## The layer-0 randomness, counted

`MEvent_Degenerate` is the only new error term, and it is discharged the same way
`Event_Degenerate` is on the single-layer side: over a sample space split as
`D × (F × F)` — everything decided before `begin_layer`, then the pair it draws — the
extracted witness is already fixed, so the bilinear count applies fibrewise.
-/

omit [SumcheckInterp F] in
/--
`eps_deg ≤ |D|·2·|F|`: the layer-0 pair costs a `2/|F|` fraction.

The schedule is `Function.update tail 0 b`: layer 0's challenge is the sampled coordinate `b`,
and layers `1 …` keep the fixed tail.  That is what makes the count legitimate — by `V_local`,
`V 1` cannot read `betas 0`, so `betas_tail_eq` replaces the whole varying schedule by the
constant `tail` and the claim becomes an honest bilinear form in `(alpha, b)`.

`hne` is where the arithmetization enters, and it is the *only* place: an unsatisfying witness
must not give an identically-zero output claim.  `arith_gives_layered_nonvanishing` below
derives it from `ArithmetizedCircuit.arith`.
-/
theorem mevent_degenerate_card {D : Type} [Fintype D]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : D × (F × F) → Prop) (st0 : LayerState logw logc F)
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (tail : ℕ → F)
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0)) :
    event_card (MEvent_Degenerate LC accepts (fun p => Function.update tail 0 p.2.1) st0
        (fun p => p.2.2) (fun p => E_pre p.1) ev c inp)
      ≤ Fintype.card D * (2 * Fintype.card F) := by
  -- layer 0's slot is the sampled coordinate; every later layer keeps `tail`
  have hupd : ∀ b : F, Function.update tail 0 b 0 = b := fun b => by simp
  have htail : ∀ (b : F) (i : ℕ), 1 ≤ i → Function.update tail 0 b i = tail i := by
    intro b i hi; exact Function.update_of_ne (by omega) _ _
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × (F × F) => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      (ev c inp v.1 = false ∧ LC.Degenerate v.1 tail p.2.2 p.2.1 st0)) Finset.univ) ?_) ?_
  · intro p hp
    simp only [MEvent_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢
    obtain ⟨-, w, pad, hE, hev, hdeg⟩ := hp
    rw [hupd] at hdeg
    exact ⟨(w, pad), hE, hev,
      (betas_tail_eq LC w _ tail p.2.2 p.2.1 st0 (htail p.2.1)).mp hdeg⟩
  have hfib : ∀ (_d : D) (v : AugmentedWitness M F Witness),
      (Finset.filter (fun p : F × F =>
        ev c inp v.1 = false ∧ LC.Degenerate v.1 tail p.2 p.1 st0) Finset.univ).card
        ≤ 2 * Fintype.card F := by
    intro _d v
    by_cases hev : ev c inp v.1 = false
    case neg =>
      refine le_trans (Finset.card_le_card (t := (∅ : Finset (F × F))) ?_) (by simp)
      intro p hp
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp
      exact absurd hp.1 hev
    refine le_trans (Finset.card_le_card (t := Finset.filter
      (fun p : F × F => LC.Degenerate v.1 tail p.2 p.1 st0) Finset.univ) (fun p hp => by
        simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hp ⊢; exact hp.2)) ?_
    exact layer_claim_zero_card LC v.1 tail st0 (hne v.1 hev)
  have hmain := option_bad_pairs_card_mul (D := D) (C := F × F) E_pre
    (fun _d v p => ev c inp v.1 = false ∧ LC.Degenerate v.1 tail p.2 p.1 st0)
    (2 * Fintype.card F)
    (fun d v => le_trans (Finset.card_le_card (fun x hx => by
      simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hx ⊢; exact hx)) (hfib d v))
  refine le_trans (le_of_eq ?_) hmain
  congr 1
  ext p
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]

/-!
## The bridge to `ArithmetizedCircuit`

`layers.lean` and `circuit.lean` grew up separately, and until now nothing said the `QUAD` of
one was the `QUAD` of the other.  With `beta` in both, they are the same object, and the two
degeneracy predicates coincide on the nose.
-/

section Bridge

variable {ninp npub logv : ℕ}

omit [SumcheckInterp F] in
/--
**The two tracks' degeneracy predicates are the same predicate.**

Given a `LayeredCircuit` whose layer-0 `QUAD` is an `ArithmetizedCircuit`'s and whose
layer-1 wire values are that circuit's committed wires, `LayeredCircuit.Degenerate` *is*
`ArithmetizedCircuit.Degenerate` at the same `(alpha, beta)`.

Both hypotheses are equalities of functions, so this is not a coincidence of notation: it says
the multi-layer track's layer 0 and the single-layer track's only layer are the same layer.
-/
lemma degenerate_agrees
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logw logw logc F)
    (c : Circuit) (inp : Input) (w : Witness) (betas : ℕ → F) (alpha beta : F)
    (st : LayerState logw logc F)
    (hQ : LC.Quad 0 beta = AC.Quad_mle c beta)
    (hV : LC.V 1 w betas = AC.W_mle inp w) :
    LC.Degenerate w betas alpha beta st
      ↔ AC.Degenerate c inp w alpha beta st.q st.g0 st.g1 := by
  rw [LayeredCircuit.Degenerate, ArithmetizedCircuit.Degenerate, hQ, hV]

omit [SumcheckInterp F] in
/--
**`arith` discharges the multi-layer non-vanishing hypothesis.**

`mevent_degenerate_card` needs "an unsatisfying witness has a non-zero output claim at one of
the four corners".  That is exactly what `ArithmetizedCircuit.arith` says, so a bridged
`LayeredCircuit` gets it for free rather than assuming it again.
-/
lemma arith_gives_layered_nonvanishing
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logw logw logc F)
    (c : Circuit) (inp : Input) (betas : ℕ → F) (st : LayerState logw logc F)
    (hQ0 : LC.Quad 0 0 = AC.Quad_mle c 0) (hQ1 : LC.Quad 0 1 = AC.Quad_mle c 1)
    (hV : ∀ w : Witness, LC.V 1 w betas = AC.W_mle inp w) :
    ∀ w : Witness, AC.eval c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0
            st.q st.g0 st.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 1
            st.q st.g0 st.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 0
            st.q st.g0 st.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 1
            st.q st.g0 st.g1 = 0) := by
  intro w hev
  rw [hQ0, hQ1, hV w]
  exact AC.arith c inp w st.q st.g0 st.g1 hev

end Bridge

end

/-!
# The per-layer randomness terms

`multi_layer_core_soundness` takes `eps_alpha` and `eps_round` as numbers.  This section earns
both, at the same rates the one-layer path pays: `1/|F|` for the claim combination and
`n·d/|F|` for the sumcheck rounds.

Both bounds are *per layer*, and both need the same structural fact first.  `LayerAlphaBadAt`
and `LayerRoundBadAt` walk the run recursively; `stateAfter` names the state a run is in when
it enters layer `i`, and the two `_iff` lemmas turn "bad at layer `i`" into a statement about
that state and layer `i`'s data alone.  Everything after is the one-layer argument, applied
there.
-/

section PerLayer

/-- The state a run is in when it enters layer `i`. -/
noncomputable def stateAfter (st : LayerState logw logc F) :
    List (LayerData logw logc F) → ℕ → LayerState logw logc F
  | [], _ => st
  | _ :: _, 0 => st
  | ld :: rest, (i + 1) => stateAfter (next_state ld) rest i

omit [SumcheckInterp F] in
/-- "Unlucky `alpha` at layer `i`" is `LayerAlphaBad` at the state layer `i` is entered in. -/
lemma layerAlphaBadAt_iff (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (w : Witness) :
    ∀ (lds : List (LayerData logw logc F)) (ly i : ℕ) (st : LayerState logw logc F)
      (ld : LayerData logw logc F), lds[i]? = some ld →
      (LayerAlphaBadAt LC w betas ly st lds i
        ↔ LayerAlphaBad LC (ly + i) w betas (stateAfter st lds i) ld) := by
  intro lds
  induction lds with
  | nil => intro ly i st ld h; simp at h
  | cons a rest ih =>
    intro ly i st ld h
    cases i with
    | zero =>
      have : a = ld := by simpa using h
      subst this
      exact Iff.rfl
    | succ j =>
      have h' : rest[j]? = some ld := by simpa using h
      have hIH := ih (ly + 1) j (next_state a) ld h'
      have hidx : (ly + 1) + j = ly + (j + 1) := by omega
      rw [hidx] at hIH
      exact hIH

/-- "Lucky round at layer `i`" is `LayerRoundBad` at the state layer `i` is entered in. -/
lemma layerRoundBadAt_iff (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (w : Witness) :
    ∀ (lds : List (LayerData logw logc F)) (ly i : ℕ) (st : LayerState logw logc F)
      (ld : LayerData logw logc F), lds[i]? = some ld →
      (LayerRoundBadAt LC w betas ly st lds i
        ↔ LayerRoundBad LC (ly + i) w betas (stateAfter st lds i) ld) := by
  intro lds
  induction lds with
  | nil => intro ly i st ld h; simp at h
  | cons a rest ih =>
    intro ly i st ld h
    cases i with
    | zero =>
      have : a = ld := by simpa using h
      subst this
      exact Iff.rfl
    | succ j =>
      have h' : rest[j]? = some ld := by simpa using h
      have hIH := ih (ly + 1) j (next_state a) ld h'
      have hidx : (ly + 1) + j = ly + (j + 1) := by omega
      rw [hidx] at hIH
      exact hIH

/-!
## `eps_alpha`: `1/|F|` per layer

Layer `i`'s `alpha` is drawn by `begin_layer` at the top of iteration `i`, after layers
`0 … i−1` have closed.  So over a sample space split as `D × F` — everything decided before
that draw, then the draw — the two claims it has to separate are already fixed, and
`layer_alpha_bad_card` says at most one draw fails.

`hstate` is exactly that causality condition: the state entering layer `i` does not read the
coordinate.  `halpha` says the coordinate really is layer `i`'s `alpha` and not some other
field element.
-/

theorem mevent_randAt_card {D : Type} [Fintype D]
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : D × F → Prop)
    (betas : D → ℕ → F) (st0 : LayerState logw logc F)
    (T : D × F → List (ZkLayer M F))
    (E_pre : D → Option (AugmentedWitness M F Witness)) (i : ℕ)
    (ST : D → Pad M F → LayerState logw logc F)
    (hstate : ∀ (p : D × F) (pad : Pad M F),
      stateAfter st0 (zkLayerDatas pad st0 (T p)) i = ST p.1 pad)
    (halpha : ∀ (p : D × F) (pad : Pad M F) (ld : LayerData logw logc F),
      (zkLayerDatas pad st0 (T p))[i]? = some ld → ld.alpha = p.2)
    (hlen : ∀ (p : D × F) (pad : Pad M F), i < (zkLayerDatas pad st0 (T p)).length) :
    event_card (MEvent_RandAt LC accepts (fun p => betas p.1) st0 T
      (fun p => E_pre p.1) i) ≤ Fintype.card D := by
  classical
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × F => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      InputBindingBad (LC.V (0 + i) v.1 (betas p.1) (ST p.1 v.2).g0 (ST p.1 v.2).q)
        (LC.V (0 + i) v.1 (betas p.1) (ST p.1 v.2).g1 (ST p.1 v.2).q)
        (ST p.1 v.2).claim0 (ST p.1 v.2).claim1 p.2) Finset.univ) ?_) ?_
  · intro p hp
    simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and] at hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    obtain ⟨-, w, pad, hE, hbad⟩ := hp
    obtain ⟨ld, hld⟩ : ∃ ld, (zkLayerDatas pad st0 (T p))[i]? = some ld :=
      ⟨_, List.getElem?_eq_getElem (hlen p pad)⟩
    rw [layerAlphaBadAt_iff LC (betas p.1) w _ 0 i st0 ld hld, hstate p pad] at hbad
    refine ⟨(w, pad), hE, ?_⟩
    rw [LayerAlphaBad] at hbad
    rwa [halpha p pad ld hld] at hbad
  · exact option_bad_pairs_card E_pre
      (fun d v a => InputBindingBad (LC.V (0 + i) v.1 (betas d) (ST d v.2).g0 (ST d v.2).q)
        (LC.V (0 + i) v.1 (betas d) (ST d v.2).g1 (ST d v.2).q)
        (ST d v.2).claim0 (ST d v.2).claim1 a)
      (fun d v => input_binding_bad_card _ _ _ _)

/-!
## `eps_round`: the sumcheck term, per layer

`challenge_pullback_bound_indexed` is already stated over an arbitrary pre-challenge state and
challenge map, with no circuit in it, so the per-layer bound is the same theorem applied at
layer `i`.  `IsLayerNonAdaptive` is what connects the two: it says layer `i`'s transmitted
round polynomials and its true ones are the family's, read at the layer's own challenge prefix.

That is the same causality `IsNonAdaptiveRun` states for a single layer, one layer in: within
a fixed pre-state, round `j` of layer `i` sees only challenges `0 … j−1` of that layer.
-/

/-- Layer `i` of a run is non-adaptive with respect to a strategy family. -/
structure IsLayerNonAdaptive {S : Type} {n d : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (fam : IsFiatShamirFamily S F n d)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) (i : ℕ)
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) : Prop where
  /-- The run reaches layer `i`. -/
  layer_present : ∀ (ω : Ω) (pad : Pad M F), accepts ω →
    i < (zkLayerDatas pad st0 (T ω)).length
  /-- Layer `i`'s challenges are the sequence. -/
  challenges_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F) (ld : LayerData logw logc F),
    accepts ω → E_L ω = some (w, pad) → (zkLayerDatas pad st0 (T ω))[i]? = some ld →
    ld.challenges = List.ofFn (challenge_map ω)
  /-- Round `j` of layer `i` is fixed before challenge `j` of that layer is drawn. -/
  prover_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F) (ld : LayerData logw logc F),
    accepts ω → E_L ω = some (w, pad) → (zkLayerDatas pad st0 (T ω))[i]? = some ld →
    ld.polys = List.ofFn (fun j : Fin n =>
      fam.p_func (state ω) j (extract_prefix (challenge_map ω) j))
  /-- And the honest round polynomials of layer `i` are the family's. -/
  true_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F) (ld : LayerData logw logc F),
    accepts ω → E_L ω = some (w, pad) → (zkLayerDatas pad st0 (T ω))[i]? = some ld →
    LC.truePolys i w (betas ω) (stateAfter st0 (zkLayerDatas pad st0 (T ω)) i) ld
      = List.ofFn (fun j : Fin n =>
          fam.P_func (state ω) j (extract_prefix (challenge_map ω) j))

/--
**`eps_round`, earned.**

At most `K · |S| · n·d·|F|^(n−1)` runs are lucky in a round of layer `i`.  Over a sample space
in which layer `i`'s challenge sequence is a coordinate, `K` and `|S|` cancel against `|Ω|` and
this is `n·d/|F|` — the same rate the one-layer path pays, per layer.
-/
theorem mevent_roundAt_card {S : Type} [Fintype S] [DecidableEq S] {n d : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (fam : IsFiatShamirFamily S F n d)
    (accepts : Ω → Prop) (betas : Ω → ℕ → F) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) (i : ℕ)
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ (s : S) (cs : Fin n → F),
      (Finset.filter (fun ω => state ω = s ∧ challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsLayerNonAdaptive LC fam accepts betas st0 T E_L i state challenge_map) :
    event_card (MEvent_RoundAt LC accepts betas st0 T E_L i)
      ≤ K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1))) := by
  classical
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun ω => any_bad_event n (fam.P_func (state ω)) (fam.p_func (state ω))
      (challenge_map ω)) Finset.univ) ?_)
    (challenge_pullback_bound_indexed fam state challenge_map K h_unif)
  intro ω hω
  simp only [MEvent_RoundAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]
  obtain ⟨hacc, w, pad, hE, hbad⟩ := hω
  obtain ⟨ld, hld⟩ : ∃ ld, (zkLayerDatas pad st0 (T ω))[i]? = some ld :=
    ⟨_, List.getElem?_eq_getElem (na.layer_present ω pad hacc)⟩
  rw [layerRoundBadAt_iff LC (betas ω) w _ 0 i st0 ld hld] at hbad
  rw [LayerRoundBad, Nat.zero_add] at hbad
  rw [na.true_eq ω w pad ld hacc hE hld, na.prover_eq ω w pad ld hacc hE hld,
    na.challenges_eq ω w pad ld hacc hE hld] at hbad
  obtain ⟨k, hP, hp, hr, hb⟩ := multi_round_bad_event_exists _ _ _ hbad
  have hk : k < n := by simpa using hP
  refine ⟨⟨k, hk⟩, ?_⟩
  dsimp [bad_event_at]
  simpa using hb

/-!
## The same bounds over an abstract sample space

`mevent_randAt_card` is stated at a literal product `D × F`.  The composition needs the bound
on whatever `Ω` a caller has, with the splitting supplied as a *pair of maps* — "everything
decided before layer `i`'s alpha" and "that alpha" — rather than by committing the development
to one product encoding.  `event_card_le_split` is what transports it, at no cost when the two
maps really are a splitting.

Layer `i`'s `beta` is drawn together with its `alpha`, so a caller puts `beta` in `dataOf`; the
statement does not care, since `dataOf` is arbitrary.
-/

/-- `eps_alpha` at layer `i`, over an abstract sample space that splits at that layer's
`alpha`. -/
theorem mevent_randAt_card_split {D : Type} [Fintype D] [DecidableEq D]
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : Ω → Prop)
    (betas : D → ℕ → F) (st0 : LayerState logw logc F)
    (dataOf : Ω → D) (alphaOf : Ω → F)
    (hinj : Function.Injective (fun ω => (dataOf ω, alphaOf ω)))
    (T : Ω → List (ZkLayer M F)) (E_pre : D → Option (AugmentedWitness M F Witness)) (i : ℕ)
    (ST : D → Pad M F → LayerState logw logc F)
    (hstate : ∀ (ω : Ω) (pad : Pad M F),
      stateAfter st0 (zkLayerDatas pad st0 (T ω)) i = ST (dataOf ω) pad)
    (halpha : ∀ (ω : Ω) (pad : Pad M F) (ld : LayerData logw logc F),
      (zkLayerDatas pad st0 (T ω))[i]? = some ld → ld.alpha = alphaOf ω)
    (hlen : ∀ (ω : Ω) (pad : Pad M F), i < (zkLayerDatas pad st0 (T ω)).length) :
    event_card (MEvent_RandAt LC accepts (fun ω => betas (dataOf ω)) st0 T
      (fun ω => E_pre (dataOf ω)) i) ≤ Fintype.card D := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : D × F → Prop, Q = fun p =>
      ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
        InputBindingBad (LC.V (0 + i) v.1 (betas p.1) (ST p.1 v.2).g0 (ST p.1 v.2).q)
          (LC.V (0 + i) v.1 (betas p.1) (ST p.1 v.2).g1 (ST p.1 v.2).q)
          (ST p.1 v.2).claim0 (ST p.1 v.2).claim1 p.2 := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card ≤ Fintype.card D := by
    refine le_trans (Finset.card_le_card ?_)
      (option_bad_pairs_card E_pre
        (fun d v a => InputBindingBad (LC.V (0 + i) v.1 (betas d) (ST d v.2).g0 (ST d v.2).q)
          (LC.V (0 + i) v.1 (betas d) (ST d v.2).g1 (ST d v.2).q)
          (ST d v.2).claim0 (ST d v.2).claim1 a)
        (fun d v => input_binding_bad_card _ _ _ _))
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf alphaOf hinj
    (fun ω => accepts ω ∧ ∃ w pad, E_pre (dataOf ω) = some (w, pad) ∧
      LayerAlphaBadAt LC w (betas (dataOf ω)) 0 st0 (zkLayerDatas pad st0 (T ω)) i)
    Q (fun ω hω => by
      obtain ⟨-, w, pad, hE, hbad⟩ := hω
      obtain ⟨ld, hld⟩ : ∃ ld, (zkLayerDatas pad st0 (T ω))[i]? = some ld :=
        ⟨_, List.getElem?_eq_getElem (hlen ω pad)⟩
      rw [layerAlphaBadAt_iff LC (betas (dataOf ω)) w _ 0 i st0 ld hld, hstate ω pad] at hbad
      rw [hQdef]
      refine ⟨(w, pad), hE, ?_⟩
      rw [LayerAlphaBad] at hbad
      rwa [halpha ω pad ld hld] at hbad)
    (Fintype.card D) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

omit [SumcheckInterp F] in
/-- `eps_deg`, over an abstract sample space that splits at layer 0's `(beta, alpha)` pair. -/
theorem mevent_degenerate_card_split {D : Type} [Fintype D] [DecidableEq D]
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : Ω → Prop)
    (st0 : LayerState logw logc F) (dataOf : Ω → D) (pairOf : Ω → F × F)
    (hinj : Function.Injective (fun ω => (dataOf ω, pairOf ω)))
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input) (tail : ℕ → F)
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0)) :
    event_card (MEvent_Degenerate LC accepts
        (fun ω => Function.update tail 0 (pairOf ω).1) st0 (fun ω => (pairOf ω).2)
        (fun ω => E_pre (dataOf ω)) ev c inp)
      ≤ Fintype.card D * (2 * Fintype.card F) := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : D × (F × F) → Prop, Q = fun p =>
      (fun _ : D × (F × F) => True) p ∧ ∃ w pad, E_pre p.1 = some (w, pad) ∧
        ev c inp w = false ∧
        LC.Degenerate w (Function.update tail 0 p.2.1) p.2.2
          (Function.update tail 0 p.2.1 0) st0 := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card ≤ Fintype.card D * (2 * Fintype.card F) := by
    refine le_trans (Finset.card_le_card ?_)
      (mevent_degenerate_card LC (fun _ : D × (F × F) => True) st0 E_pre ev c inp tail hne)
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef, MEvent_Degenerate] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf pairOf hinj
    (fun ω => accepts ω ∧ ∃ w pad, E_pre (dataOf ω) = some (w, pad) ∧
      ev c inp w = false ∧
      LC.Degenerate w (Function.update tail 0 (pairOf ω).1) ((pairOf ω).2)
        (Function.update tail 0 (pairOf ω).1 0) st0)
    Q (fun ω hω => by
      obtain ⟨-, w, pad, hE, hev, hdeg⟩ := hω
      rw [hQdef]
      exact ⟨trivial, w, pad, hE, hev, hdeg⟩)
    (Fintype.card D * (2 * Fintype.card F)) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [MEvent_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

end PerLayer
