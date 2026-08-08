import Mathlib
import sumcheck_soundness
import types
import builder
import circuit
import ligero
import layers
import zk_layers

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

The two `nl *` factors are `union_bound_layers`: each is a disjunction over layers, and
`alpha_bad_card` bounds a single layer's coefficient collision by a `1/|F|` fraction.

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
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ ZkRowsHold LC pad 0 st0 (T ω)) Finset.univ

/-- The layer coefficient was unlucky at layer `i`. -/
noncomputable def MEvent_RandAt (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (i : ℕ) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    LayerAlphaBadAt LC w 0 st0 (zkLayerDatas pad st0 (T ω)) i) Finset.univ

/-- The layer coefficient was unlucky somewhere. -/
noncomputable def MEvent_Rand (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ GoodRandomness LC w 0 st0 (zkLayerDatas pad st0 (T ω))) Finset.univ

/-- A sumcheck round of layer `i` was lucky. -/
noncomputable def MEvent_RoundAt (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (i : ℕ) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    LayerRoundBadAt LC w 0 st0 (zkLayerDatas pad st0 (T ω)) i) Finset.univ

/-- A sumcheck round was lucky somewhere. -/
noncomputable def MEvent_Round (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    AnyLayerRoundBad LC w 0 st0 (zkLayerDatas pad st0 (T ω))) Finset.univ

/-- The claims the run ends on are not the honest input-layer values, i.e. the Ligero input
row failed to pin them to the committed witness. -/
noncomputable def MEvent_Input (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ ClaimsCorrect LC (T ω).length w (zkFinalState pad st0 (T ω))) Finset.univ

/-- The verifier accepted, yet the extracted witness does not satisfy the circuit. -/
noncomputable def MEvent_Fail (accepts : Ω → Prop)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ (E_L ω = none ∨
    ∃ w pad, E_L ω = some (w, pad) ∧ ev c inp w = false)) Finset.univ

omit [Fintype Ω] [Fintype F] [DecidableEq F] [SumcheckInterp F] in
lemma union_bound_5 (A B C D E : Finset Ω) :
    event_card (A ∪ B ∪ C ∪ D ∪ E)
      ≤ event_card A + event_card B + event_card C + event_card D + event_card E := by
  dsimp [event_card]
  linarith [Finset.card_union_le (A ∪ B ∪ C ∪ D) E, Finset.card_union_le (A ∪ B ∪ C) D,
    Finset.card_union_le (A ∪ B) C, Finset.card_union_le A B]

/--
**The multi-layer failure decomposition.**

If the verifier accepted and the extracted witness is wrong, then one of five things went
wrong: extraction failed, some layer's Ligero rows failed, some layer's coefficient was
unlucky, some layer's sumcheck round was lucky, or the input-layer claims were not the
committed witness.

`harith` is the arithmetization statement at the top of the circuit: an unsatisfying witness
does not have the claimed output values.  With the verifier's initial claims both zero
(`verifier_layers.h:L70`) that reads "an unsatisfied circuit has a non-zero output MLE".
-/
theorem mevent_fail_subset (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (hpos : 0 < logc + 2 * logw)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω)))
    (harith : ∀ w : Witness, ev c inp w = false → ¬ ClaimsCorrect LC 0 w st0) :
    MEvent_Fail accepts ev c inp E_L
      ⊆ Event_A accepts E_L ∪ MEvent_Rows LC accepts st0 T E_L
        ∪ MEvent_Rand LC accepts st0 T E_L ∪ MEvent_Round LC accepts st0 T E_L
        ∪ MEvent_Input LC accepts st0 T E_L := by
  intro ω hω
  simp only [MEvent_Fail, Event_A, MEvent_Rows, MEvent_Rand, MEvent_Round, MEvent_Input,
    Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at hω ⊢
  obtain ⟨hacc, hfail⟩ := hω
  cases hfail with
  | inl hnone => exact Or.inl (Or.inl (Or.inl (Or.inl ⟨hacc, hnone⟩)))
  | inr hsome =>
    obtain ⟨w, pad, hE, hev⟩ := hsome
    by_cases hrows : ZkRowsHold LC pad 0 st0 (T ω)
    · by_cases hrand : GoodRandomness LC w 0 st0 (zkLayerDatas pad st0 (T ω))
      · by_cases hround : AnyLayerRoundBad LC w 0 st0 (zkLayerDatas pad st0 (T ω))
        · exact Or.inl (Or.inr ⟨hacc, w, pad, hE, hround⟩)
        · -- rows hold, randomness good, no lucky round: the reduction lands on the input layer
          have h := zk_multi_layer_soundness LC pad w hpos (T ω) st0 hrows
            (hshape ω w pad hacc hE) hrand (harith w hev)
          cases h with
          | inl hbad => exact absurd hbad hround
          | inr hin => exact Or.inr ⟨hacc, w, pad, hE, hin⟩
      · exact Or.inl (Or.inl (Or.inr ⟨hacc, w, pad, hE, hrand⟩))
    · exact Or.inl (Or.inl (Or.inl (Or.inr ⟨hacc, w, pad, hE, hrows⟩)))

/-- The per-layer coefficient collisions add up. -/
theorem mevent_rand_card (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (nl eps : ℕ) (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hEps : ∀ i, i < nl → event_card (MEvent_RandAt LC accepts st0 T E_L i) ≤ eps) :
    event_card (MEvent_Rand LC accepts st0 T E_L) ≤ nl * eps := by
  have h := union_bound_layers nl eps
    (fun i ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      LayerAlphaBadAt LC w 0 st0 (zkLayerDatas pad st0 (T ω)) i)
    (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      ¬ GoodRandomness LC w 0 st0 (zkLayerDatas pad st0 (T ω)))
    (by
      rintro ω ⟨hacc, w, pad, hE, hbad⟩
      obtain ⟨i, hi, hb⟩ := notGoodRandomness_exists LC w (zkLayerDatas pad st0 (T ω)) 0 st0 hbad
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
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (nl eps : ℕ) (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hEps : ∀ i, i < nl → event_card (MEvent_RoundAt LC accepts st0 T E_L i) ≤ eps) :
    event_card (MEvent_Round LC accepts st0 T E_L) ≤ nl * eps := by
  have h := union_bound_layers nl eps
    (fun i ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      LayerRoundBadAt LC w 0 st0 (zkLayerDatas pad st0 (T ω)) i)
    (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      AnyLayerRoundBad LC w 0 st0 (zkLayerDatas pad st0 (T ω)))
    (by
      rintro ω ⟨hacc, w, pad, hE, hbad⟩
      obtain ⟨i, hi, hb⟩ := anyLayerRoundBad_exists LC w (zkLayerDatas pad st0 (T ω)) 0 st0 hbad
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
|Event_Fail|  ≤  eps_FSK  +  nl · eps_alpha  +  nl · eps_round  +  eps_bind
```

`MEvent_Rows` contributes nothing: the Ligero extractor's guarantee is exactly that the
rows hold, so that event is empty.

This is the statement `core_soundness_theorem` gives for one layer, now for `nl` of them.
The two `nl ·` factors are the per-layer randomness and sumcheck errors summed by
`union_bound_layers`; `eps_FSK` and `eps_bind` are per-run and do not scale with depth.
-/
theorem multi_layer_core_soundness (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F)
    (T : Ω → List (ZkLayer M F)) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (nl eps_FSK eps_alpha eps_round eps_bind : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω)))
    (harith : ∀ w : Witness, ev c inp w = false → ¬ ClaimsCorrect LC 0 w st0)
    (h_extract : event_card (Event_A accepts E_L) ≤ eps_FSK)
    (h_rows : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      ZkRowsHold LC pad 0 st0 (T ω))
    (h_alpha : ∀ i, i < nl → event_card (MEvent_RandAt LC accepts st0 T E_L i) ≤ eps_alpha)
    (h_round : ∀ i, i < nl → event_card (MEvent_RoundAt LC accepts st0 T E_L i) ≤ eps_round)
    (h_bind : event_card (MEvent_Input LC accepts st0 T E_L) ≤ eps_bind) :
    event_card (MEvent_Fail accepts ev c inp E_L)
      ≤ eps_FSK + nl * eps_alpha + nl * eps_round + eps_bind := by
  have h_sub := Finset.card_le_card
    (mevent_fail_subset LC accepts st0 T E_L ev c inp hpos hshape harith)
  have h_ub := union_bound_5 (Event_A accepts E_L) (MEvent_Rows LC accepts st0 T E_L)
    (MEvent_Rand LC accepts st0 T E_L) (MEvent_Round LC accepts st0 T E_L)
    (MEvent_Input LC accepts st0 T E_L)
  have h_rows0 : event_card (MEvent_Rows LC accepts st0 T E_L) = 0 := by
    have hempty : MEvent_Rows LC accepts st0 T E_L = ∅ := by
      ext ω
      simp only [MEvent_Rows, Finset.mem_filter, Finset.mem_univ, true_and]
      constructor
      · rintro ⟨hacc, w, pad, hE, hno⟩
        exact absurd (h_rows ω w pad hacc hE) hno
      · intro hc; exact absurd hc (by simp)
    simp [event_card, hempty]
  have h_r := mevent_rand_card LC accepts st0 T E_L nl eps_alpha hnl h_alpha
  have h_c := mevent_round_card LC accepts st0 T E_L nl eps_round hnl h_round
  dsimp [event_card] at *
  linarith

end
