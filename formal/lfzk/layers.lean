import Mathlib
import sumcheck_soundness
import types
import circuit
import ligero

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# The layer loop

This file models `VerifierLayers::layers` (`sumcheck/verifier_layers.h:L135-L200`) — the
`for (ly = 0; ly < CIRCUIT->nl; ++ly)` loop and, more importantly, the **layer-to-layer
reduction** it performs.

Per layer the verifier:

1. combines the two inherited claims, `claim = cl->claim[0] + alpha * cl->claim[1]`
   (`L147`);
2. runs `logc` copy rounds and `logw * 2` hand rounds of sumcheck (`layer_c`, `layer_h`);
3. checks `got == claim` where `got = EQ[Q,C] * QUAD[G|R,L] * wc[0] * wc[1]` (`L176-L185`);
4. **reduces** to two fresh claims on the next layer down, `*cl = claims{.claim = {wc[0],
   wc[1]}, .q = challenge->cb, .g = {hb[0], hb[1]}}` (`L191-L197`).

Step 4 is what `sumcheck_soundness.lean` alone cannot see: it turns one wrong claim about
layer `ly` into a wrong claim about layer `ly+1`, and the induction over all layers is what
finally lands on the input wires, where the Ligero input row binds them (`ligero.lean`).

## Modelling restriction

All layers are assumed to have the **same** width `logw` and the same `logc`.  The circuit
format allows `Layer.logw` to vary per layer (`sumcheck/circuit.h:L30`), and the verifier
carries `cl->logv = clr->logw` from one layer to the next.  Handling varying widths means
indexing `Vector F (logw ly)` by the layer, which this development does not do.
-/

variable {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
variable {Witness : Type}

/--
The verifier's per-layer state: the two claims it has yet to justify, plus the points they
are claims at.  **Code Reference**: `VerifierLayers::claims` (`verifier_layers.h:L39-L45`).
-/
structure LayerState (logw logc : ℕ) (F : Type) where
  claim0 : F
  claim1 : F
  q  : Vector F logc
  g0 : Vector F logw
  g1 : Vector F logw

/--
One layer's proof and challenge data.  **Code Reference**: `LayerProof<Field>` and
`LayerChallenge<Field>` (`sumcheck/circuit.h:L69-L106`).  `polys` is `cp ++ hp` flattened,
`challenges` is `cb ++ hb`, `wc0`/`wc1` are `wc[0]`/`wc[1]`, and `alpha` is the random
coefficient of the claim combination.
-/
structure LayerData (logw logc : ℕ) (F : Type) where
  polys : List (RoundPoly F)
  challenges : List F
  wc0 : F
  wc1 : F
  alpha : F

/-- The layer polynomial the sumcheck of one layer is about, with the two `g` points
already folded together by `alpha` (matching `Quad::bind_g`). -/
noncomputable def layer_poly_of {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logw)]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) : Vector F (logc + 2 * logw) → F :=
  layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad Vnext alpha st.q st.g0 st.g1

/-- The honest round polynomials of one layer. -/
noncomputable def layer_true_polys_of {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logw)] [DecidableEq F]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) (chal : List F) : List (Polynomial F) :=
  generate_true_polys (layer_poly_of (nc := nc) (nv := nv) Quad Vnext alpha st)
    (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)

/-- There is exactly one honest round polynomial per sumcheck variable.  Unlike the other
facts about the honest polynomials this one is a theorem, not an assumption. -/
lemma layer_true_polys_length {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logw)] [DecidableEq F]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) (chal : List F) :
    (layer_true_polys_of (nc := nc) (nv := nv) Quad Vnext alpha st chal).length = logc + 2 * logw := by
  simp [layer_true_polys_of, generate_true_polys]

/--
**Structure: LayeredCircuit**

A multi-layer arithmetization: the honest wire values of every layer, the per-layer `QUAD`,
and the facts about the honest round polynomials that the sumcheck reduction consumes.

* `V ly w` is the multilinear extension of the layer-`ly` wire values under witness `w`.
  `V 0` is the output layer; `V nl` is the input layer, i.e. the committed witness columns.
* `Quad ly` is `Layer.quad` of layer `ly` (`sumcheck/circuit.h:L33`).

The last three fields are the *honest prover* facts.  For a genuine arithmetization all
three are theorems about `generate_true_polys`; proving them in general needs the
hypercube-splitting bijection `Fin (2^(m+1)) ≃ Fin 2 × Fin (2^m)` matched against
`boolean_vector` / `construct_assignment`, which this development does not yet have (see
the README plan).  They are packaged as fields so a concrete instance can discharge them.

`head_sum` is the one carrying real content: it says the round-0 polynomial's sum over
`{0,1}` is the `alpha`-combination of the two claims *the layer relation predicts*.  That
is the layer relation
`V ly [g,q] = ∑_{c,l,r} EQ[q,c] QUAD_ly[g|l,r] V (ly+1)[l,c] V (ly+1)[r,c]`.
-/
structure LayeredCircuit (Witness : Type) (nc nv logw logc : ℕ) (F : Type)
    [Field F] [Fintype F] [Fintype (Vector F logw)] [DecidableEq F] where
  V : ℕ → Witness → Vector F logw → Vector F logc → F
  Quad : ℕ → Vector F logw → Vector F logw → Vector F logw → F
  /--
  **The layer relation**, and now the only thing this structure assumes about the round
  polynomials:

      V ly [g, q] = ∑_{c,l,r ∈ {0,1}^*} EQ[q,c] · QUAD_ly[g|l,r] · V (ly+1)[l,c] · V (ly+1)[r,c]

  stated for the `alpha`-combination of the two `g` points, which is the form the verifier
  actually sumchecks (`claim[0] + alpha * claim[1]` at `verifier_layers.h:L147` against
  `Quad::bind_g`).

  `consistent`, `head_sum` and `last_eval` used to be three further fields; they are now
  theorems, derived from this one by the hypercube-splitting lemmas in `circuit.lean`.
  -/
  layer_rel : ∀ (ly : ℕ) (w : Witness) (alpha : F) (st : LayerState logw logc F),
    ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
        layer_poly_of (nc := nc) (nv := nv) (Quad ly) (V (ly + 1) w) alpha st (boolean_vector j)
      = V ly w st.g0 st.q + alpha * V ly w st.g1 st.q

namespace LayeredCircuit

variable {nc nv logw logc : ℕ} [Fintype (Vector F logw)]

omit [SumcheckInterp F] in
/-- Derived: the honest round polynomials of a layer are chained consistently. -/
lemma consistent (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (st : LayerState logw logc F) (chal : List F)
    (hchal : chal.length = logc + 2 * logw) :
    consistent_true_polys
      (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) alpha st chal) chal :=
  consistent_generate _ chal hchal

omit [SumcheckInterp F] in
/-- Derived: the round-0 polynomial's sum over `{0,1}` is the `alpha`-combination of the two
claims the layer relation predicts. -/
lemma head_sum (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (st : LayerState logw logc F) (chal : List F)
    (hpos : 0 < logc + 2 * logw) :
    (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) alpha st chal).head!.eval 0
      + (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) alpha st chal).head!.eval 1
      = LC.V ly w st.g0 st.q + alpha * LC.V ly w st.g1 st.q := by
  rw [layer_true_polys_of, head_generate _ _ hpos]
  exact LC.layer_rel ly w alpha st

omit [SumcheckInterp F] in
/-- Derived: the honest chain ends at the layer polynomial evaluated at the challenges. -/
lemma last_eval (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (st : LayerState logw logc F) (chal : List F)
    (hchal : chal.length = logc + 2 * logw) (hpos : 0 < logc + 2 * logw) :
    get_last_eval (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) alpha st chal) chal
      = some (layer_poly_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) alpha st
                (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)) :=
  get_last_eval_generate _ chal hchal hpos

/-- The honest round polynomials of layer `ly` under witness `w`. -/
noncomputable def truePolys (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (ld : LayerData logw logc F) :
    List (Polynomial F) :=
  layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) ld.alpha st ld.challenges

/--
`EQQ = EQ[Q,C] * QUAD[G|R,L]` for one layer, recomputed by the verifier at
`verifier_layers.h:L162-L178` (and `zk_common.h:L107-L111`).
-/
noncomputable def eqq (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (st : LayerState logw logc F) (ld : LayerData logw logc F) : F :=
  eq_matrix_mle nc logc st.q (challenge_split (logw := logw) (logc := logc) ld.challenges).1 *
    ∑ g ∈ (Finset.univ : Finset (Vector F logw)),
      LC.Quad ly g (challenge_split (logw := logw) (logc := logc) ld.challenges).2.1
                   (challenge_split (logw := logw) (logc := logc) ld.challenges).2.2 *
        (eq_matrix_mle nv logw st.g0 g + ld.alpha * eq_matrix_mle nv logw st.g1 g)

end LayeredCircuit

/--
The state the verifier moves to after finishing a layer.
**Code Reference**: `*cl = claims{.claim = {plr->wc[0], plr->wc[1]}, .q = challenge->cb,
.g = {challenge->hb[0], challenge->hb[1]}}` at `verifier_layers.h:L191-L197`.

This is the layer-to-layer reduction, as a function.
-/
noncomputable def next_state {logw logc : ℕ} {F : Type} [Field F]
    (ld : LayerData logw logc F) : LayerState logw logc F :=
  { claim0 := ld.wc0
    claim1 := ld.wc1
    q  := (challenge_split (logw := logw) (logc := logc) ld.challenges).1
    g0 := (challenge_split (logw := logw) (logc := logc) ld.challenges).2.1
    g1 := (challenge_split (logw := logw) (logc := logc) ld.challenges).2.2 }

/-- One iteration of the layer loop: combine the claims, run the sumcheck, check
`got == claim`, and reduce to the next state. -/
noncomputable def verify_layer {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (st : LayerState logw logc F) (ld : LayerData logw logc F) :
    Option (LayerState logw logc F) :=
  match verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges with
  | none => none
  | some final =>
      if final = LC.eqq ly st ld * ld.wc0 * ld.wc1 then some (next_state ld) else none

/-- The whole `for (ly)` loop of `VerifierLayers::layers`. -/
noncomputable def verify_layers {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Option (LayerState logw logc F)
  | _, st, [] => some st
  | ly, st, ld :: rest =>
      match verify_layer LC ly st ld with
      | some st' => verify_layers LC (ly + 1) st' rest
      | none => none

/-- The two claims the verifier carries into layer `ly` really are the honest wire values
of layer `ly` at the two points. -/
def ClaimsCorrect {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) : Prop :=
  st.claim0 = LC.V ly w st.g0 st.q ∧ st.claim1 = LC.V ly w st.g1 st.q

/-- A lucky sumcheck round inside layer `ly`. -/
def LayerRoundBad {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (ld : LayerData logw logc F) : Prop :=
  multi_round_bad_event (LC.truePolys ly w st ld) ld.polys ld.challenges

/--
The unlucky `alpha` that lets a wrong pair of claims survive the combination
`claim[0] + alpha * claim[1]` (`verifier_layers.h:L147`).

This is the same shape as the input-binding collision, so `input_binding_bad_card` applies:
for a fixed pair of honest and claimed values, at most one `alpha` in the field is bad.
-/
def LayerAlphaBad {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (ld : LayerData logw logc F) : Prop :=
  InputBindingBad (LC.V ly w st.g0 st.q) (LC.V ly w st.g1 st.q) st.claim0 st.claim1 ld.alpha

omit [SumcheckInterp F] in
/-- At most one `alpha` per layer is bad — the layer-combination analogue of
`input_binding_bad_card`. -/
lemma layer_alpha_bad_card {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (c0 c1 : F) :
    (Finset.univ.filter (fun a : F =>
      InputBindingBad (LC.V ly w st.g0 st.q) (LC.V ly w st.g1 st.q) c0 c1 a)).card ≤ 1 :=
  input_binding_bad_card _ _ _ _

omit [SumcheckInterp F] in
/--
**The per-layer randomness cost, counted.**

Splitting the sample space as `D × F` — everything decided before the layer's `alpha`, times
`alpha` — at most `|D|` of the `|D| * |F|` runs hit a bad `alpha` at this layer.  That is
`1/|F|` per layer, so `nl/|F|` over a whole run.

This is `alpha_bad_card` (`ligero.lean`) applied to `LayerAlphaBad`, which is
`InputBindingBad`-shaped by construction: the layer combination
`claim[0] + alpha * claim[1]` (`verifier_layers.h:L147`) and the input binding
`wc[0] + alpha * wc[1]` (`zk_common.h:L133`) are the same trick.
-/
theorem layer_alpha_bad_card_prod {D : Type} [Fintype D] {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (ly : ℕ) (w : Witness)
    (st : D → LayerState logw logc F) (c0 c1 : D → F) :
    (Finset.filter (fun p : D × F =>
        InputBindingBad (LC.V ly w (st p.1).g0 (st p.1).q) (LC.V ly w (st p.1).g1 (st p.1).q)
          (c0 p.1) (c1 p.1) p.2) Finset.univ).card ≤ Fintype.card D :=
  alpha_bad_card (fun d => LC.V ly w (st d).g0 (st d).q) (fun d => LC.V ly w (st d).g1 (st d).q) c0 c1

/-- Every layer of the run has the round count the verifier enforces. -/
def LayersShapeOK {logw logc : ℕ} {F : Type} (lds : List (LayerData logw logc F)) : Prop :=
  ∀ ld ∈ lds, ld.polys.length = logc + 2 * logw ∧ ld.challenges.length = logc + 2 * logw

/-- No unlucky `alpha` anywhere along the run.  The states are determined by the run, so
this recurses in step with `verify_layers`.

Note there is no `EQQ ≠ 0` condition: `layer_step` derives its contradiction without
cancelling `EQQ`, so a vanishing `EQ[Q,C] * QUAD` costs nothing here. -/
noncomputable def GoodRandomness {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Prop
  | _, _, [] => True
  | ly, st, ld :: rest =>
      ¬ LayerAlphaBad LC ly w st ld ∧ GoodRandomness LC w (ly + 1) (next_state ld) rest

/-- A lucky sumcheck round somewhere along the run. -/
noncomputable def AnyLayerRoundBad {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Prop
  | _, _, [] => False
  | ly, st, ld :: rest =>
      LayerRoundBad LC ly w st ld ∨ AnyLayerRoundBad LC w (ly + 1) (next_state ld) rest


/-!
## The per-layer reduction
-/

/-- `verify_layer` accepts exactly when the sumcheck closes on `EQQ * wc[0] * wc[1]`, and
when it does, the new state is the reduction `next_state ld`. -/
lemma verify_layer_some_iff {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (st st' : LayerState logw logc F) (ld : LayerData logw logc F) :
    verify_layer LC ly st ld = some st' ↔
      (st' = next_state ld ∧
        verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges
          = some (LC.eqq ly st ld * ld.wc0 * ld.wc1)) := by
  rw [verify_layer]
  cases h_vm : verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges with
  | none => simp
  | some final =>
    by_cases hg : final = LC.eqq ly st ld * ld.wc0 * ld.wc1
    · subst hg; simp [eq_comm]
    · simp [hg]

omit [SumcheckInterp F] in
/-- At the transcript's own challenge point the layer polynomial factors as
`EQQ * V(ly+1)[L,C] * V(ly+1)[R,C]`.  This is where the state update
`.g = {hb[0], hb[1]}, .q = cb` (`verifier_layers.h:L195-L196`) meets the sumcheck's final
evaluation point. -/
lemma layer_poly_at_challenges {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (ld : LayerData logw logc F) :
    layer_poly_of (nc := nc) (nv := nv) (LC.Quad ly) (LC.V (ly + 1) w) ld.alpha st
        (Vector.ofFn (n := logc + 2 * logw) fun i => ld.challenges.getD i.val 0)
      = LC.eqq ly st ld
        * LC.V (ly + 1) w (next_state ld).g0 (next_state ld).q
        * LC.V (ly + 1) w (next_state ld).g1 (next_state ld).q := rfl

/--
**The layer-to-layer reduction step.**

If the verifier accepted layer `ly` but the claims it carried *into* the layer were wrong,
then either it was lucky in one of the layer's sumcheck rounds, or the claims it carries
*out* of the layer — on layer `ly+1` — are wrong too.

This is the induction step of GKR soundness, and it is the piece that
`sumcheck_soundness.lean` on its own cannot supply: `sumcheck_multi_reduction` ends at
"the final claim is wrong", and it is the `got == claim` check plus the state update at
`verifier_layers.h:L182-L197` that converts that into a wrong claim one layer down.
-/
theorem layer_step {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (st st' : LayerState logw logc F) (ld : LayerData logw logc F)
    (h_polys : ld.polys.length = logc + 2 * logw)
    (h_chal : ld.challenges.length = logc + 2 * logw)
    (h_pos : 0 < logc + 2 * logw)
    (h_ver : verify_layer LC ly st ld = some st')
    (h_wrong : ¬ ClaimsCorrect LC ly w st)
    (h_alpha : ¬ LayerAlphaBad LC ly w st ld) :
    LayerRoundBad LC ly w st ld ∨ ¬ ClaimsCorrect LC (ly + 1) w st' := by
  -- unpack the verifier's acceptance of this layer
  obtain ⟨h_st', h_vm⟩ := (verify_layer_some_iff LC ly st st' ld).mp h_ver
  subst h_st'
  · -- the combined claim entering the sumcheck is false
    have h_false : st.claim0 + ld.alpha * st.claim1 ≠
        (LC.truePolys ly w st ld).head!.eval 0 + (LC.truePolys ly w st ld).head!.eval 1 := by
      rw [LayeredCircuit.truePolys, LC.head_sum _ _ _ _ _ h_pos]
      intro hEq
      refine h_alpha ⟨?_, hEq.symm⟩
      by_contra hc
      push Not at hc
      exact h_wrong ⟨(hc.1).symm, (hc.2).symm⟩
    -- the multi-round reduction
    have h_nnil : ld.polys ≠ [] := by
      intro h0
      rw [h0, List.length_nil] at h_polys
      omega
    have h_len1 : (LC.truePolys ly w st ld).length = ld.polys.length := by
      rw [LayeredCircuit.truePolys, layer_true_polys_length, h_polys]
    have h_len2 : ld.challenges.length = ld.polys.length := by rw [h_chal, h_polys]
    have h_red := sumcheck_multi_reduction (LC.truePolys ly w st ld) ld.polys ld.challenges
      (st.claim0 + ld.alpha * st.claim1) (LC.eqq ly st ld * ld.wc0 * ld.wc1)
      h_vm h_len1 h_len2 (LC.consistent ly w ld.alpha st ld.challenges h_chal) h_nnil h_false
    cases h_red with
    | inr h_bad => exact Or.inl h_bad
    | inl h_last =>
      right
      -- the honest chain ends at `EQQ * V(ly+1)[L,C] * V(ly+1)[R,C]`
      have h_ge := LC.last_eval ly w ld.alpha st ld.challenges h_chal h_pos
      rw [layer_poly_at_challenges LC ly w st ld] at h_ge
      -- so that product differs from `EQQ * wc0 * wc1`
      intro hcc
      obtain ⟨hc0, hc1⟩ := hcc
      apply h_last
      rw [LayeredCircuit.truePolys, h_ge, ← hc0, ← hc1]
      rfl


/-!
## The induction over all layers
-/

/--
**Multi-layer soundness reduction.**

If the verifier accepts every layer of a run but the claims it started with were wrong,
then either it was lucky in some round of some layer, or the claims it ends with — on the
*input* layer — are wrong.

Contrapositively: once the input claims are pinned to the committed witness (which is what
`input_row_binds_hands` does), a wrong starting claim forces a lucky round somewhere.
-/
theorem layers_reduction {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (h_pos : 0 < logc + 2 * logw) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st stF : LayerState logw logc F),
      verify_layers LC ly st lds = some stF →
      LayersShapeOK lds →
      GoodRandomness LC w ly st lds →
      ¬ ClaimsCorrect LC ly w st →
      AnyLayerRoundBad LC w ly st lds ∨ ¬ ClaimsCorrect LC (ly + lds.length) w stF := by
  intro lds
  induction lds with
  | nil =>
    intro ly st stF h_ver _ _ h_wrong
    rw [verify_layers] at h_ver
    injection h_ver with h_eq
    subst h_eq
    right
    simpa using h_wrong
  | cons ld rest ih =>
    intro ly st stF h_ver h_shape h_good h_wrong
    rw [verify_layers] at h_ver
    cases h_vl : verify_layer LC ly st ld with
    | none => rw [h_vl] at h_ver; exact absurd h_ver (by simp)
    | some st' =>
    rw [h_vl] at h_ver
    obtain ⟨h_alpha, h_good_rest⟩ := h_good
    obtain ⟨h_p, h_c⟩ := h_shape ld (List.mem_cons_self ..)
    -- `verify_layer` always returns `next_state ld`
    have h_st' : st' = next_state ld := ((verify_layer_some_iff LC ly st st' ld).mp h_vl).1
    cases layer_step LC ly w st st' ld h_p h_c h_pos h_vl h_wrong h_alpha with
    | inl h_bad => exact Or.inl (Or.inl h_bad)
    | inr h_next =>
      subst h_st'
      have h_ih := ih (ly + 1) (next_state ld) stF h_ver
        (fun d hd => h_shape d (List.mem_cons_of_mem _ hd)) h_good_rest h_next
      cases h_ih with
      | inl h_bad => exact Or.inl (Or.inr h_bad)
      | inr h_wrongF =>
        right
        have : ly + (ld :: rest).length = ly + 1 + rest.length := by simp; omega
        rwa [this]


/-!
## Error terms across layers

`AnyLayerRoundBad` is a disjunction over the layers of the run.  These lemmas turn a
per-layer bound into a bound for the whole run: `nl` layers cost `nl` times as much.
-/

/-- "The prover was lucky in layer `i` of this run", picking out the `i`-th disjunct of
`AnyLayerRoundBad`. -/
noncomputable def LayerRoundBadAt {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → ℕ → Prop
  | _, _, [], _ => False
  | ly, st, ld :: _, 0 => LayerRoundBad LC ly w st ld
  | ly, _, ld :: rest, (i + 1) => LayerRoundBadAt LC w (ly + 1) (next_state ld) rest i

/-- The multi-layer bad event is exactly "some layer was bad". -/
lemma anyLayerRoundBad_exists {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st : LayerState logw logc F),
      AnyLayerRoundBad LC w ly st lds →
      ∃ i, i < lds.length ∧ LayerRoundBadAt LC w ly st lds i := by
  intro lds
  induction lds with
  | nil => intro ly st h; exact absurd h (by simp [AnyLayerRoundBad])
  | cons ld rest ih =>
    intro ly st h
    rw [AnyLayerRoundBad] at h
    cases h with
    | inl hbad => exact ⟨0, by simp, hbad⟩
    | inr hrest =>
      obtain ⟨i, hi, hb⟩ := ih (ly + 1) (next_state ld) hrest
      exact ⟨i + 1, by simpa using hi, hb⟩

omit [SumcheckInterp F] in
/--
**The error terms add across layers.**

If the multi-layer bad event implies that *some* layer of the run was bad, and each layer's
bad event costs at most `eps`, then the run costs at most `nl * eps`.
-/
lemma union_bound_layers {Ω : Type} [Fintype Ω] (nl eps : ℕ)
    (Bad : ℕ → Ω → Prop) (Any : Ω → Prop)
    (hAny : ∀ ω, Any ω → ∃ i, i < nl ∧ Bad i ω)
    (hBad : ∀ i, i < nl → (Finset.filter (fun ω => Bad i ω) Finset.univ).card ≤ eps) :
    (Finset.filter Any Finset.univ).card ≤ nl * eps := by
  have hsub : Finset.filter Any Finset.univ
      ⊆ (Finset.range nl).biUnion (fun i => Finset.filter (fun ω => Bad i ω) Finset.univ) := by
    intro ω hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω
    simp only [Finset.mem_biUnion, Finset.mem_range, Finset.mem_filter, Finset.mem_univ, true_and]
    obtain ⟨i, hi, hb⟩ := hAny ω hω
    exact ⟨i, hi, hb⟩
  calc (Finset.filter Any Finset.univ).card
      ≤ ((Finset.range nl).biUnion
          (fun i => Finset.filter (fun ω => Bad i ω) Finset.univ)).card := Finset.card_le_card hsub
    _ ≤ ∑ i ∈ Finset.range nl, (Finset.filter (fun ω => Bad i ω) Finset.univ).card :=
        Finset.card_biUnion_le
    _ ≤ ∑ _i ∈ Finset.range nl, eps :=
        Finset.sum_le_sum (fun i hi => hBad i (Finset.mem_range.mp hi))
    _ = nl * eps := by simp

/--
The multi-layer sumcheck error, assembled: a run of `nl` layers costs `nl` times the
per-layer error.  Combined with `sumcheck_ci_of_nonadaptive` this is
`nl · K · n · d · |F|^(n-1)`.
-/
theorem any_layer_round_bad_card {Ω : Type} [Fintype Ω] {nc nv logw logc : ℕ}
    [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness)
    (lds : List (LayerData logw logc F)) (ly : ℕ) (st : Ω → LayerState logw logc F)
    (nl eps : ℕ) (hnl : lds.length ≤ nl)
    (hBad : ∀ i, i < nl →
      (Finset.filter (fun ω => LayerRoundBadAt LC w ly (st ω) lds i) Finset.univ).card ≤ eps) :
    (Finset.filter (fun ω => AnyLayerRoundBad LC w ly (st ω) lds) Finset.univ).card
      ≤ nl * eps := by
  refine union_bound_layers nl eps (fun i ω => LayerRoundBadAt LC w ly (st ω) lds i) _ ?_ hBad
  intro ω hω
  obtain ⟨i, hi, hb⟩ := anyLayerRoundBad_exists LC w lds ly (st ω) hω
  exact ⟨i, lt_of_lt_of_le hi hnl, hb⟩


/-- "The layer coefficient was unlucky at layer `i` of this run", picking out the `i`-th
conjunct of `GoodRandomness`. -/
noncomputable def LayerAlphaBadAt {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → ℕ → Prop
  | _, _, [], _ => False
  | ly, st, ld :: _, 0 => LayerAlphaBad LC ly w st ld
  | ly, _, ld :: rest, (i + 1) => LayerAlphaBadAt LC w (ly + 1) (next_state ld) rest i

omit [SumcheckInterp F] in
/-- Randomness failing somewhere along the run means it failed at some specific layer. -/
lemma notGoodRandomness_exists {nc nv logw logc : ℕ} [Fintype (Vector F logw)]
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st : LayerState logw logc F),
      ¬ GoodRandomness LC w ly st lds →
      ∃ i, i < lds.length ∧ LayerAlphaBadAt LC w ly st lds i := by
  intro lds
  induction lds with
  | nil => intro ly st h; exact absurd trivial h
  | cons ld rest ih =>
    intro ly st h
    rw [GoodRandomness] at h
    by_cases hbad : LayerAlphaBad LC ly w st ld
    · exact ⟨0, by simp, hbad⟩
    · have hrest : ¬ GoodRandomness LC w (ly + 1) (next_state ld) rest := by
        intro hg; exact h ⟨hbad, hg⟩
      obtain ⟨i, hi, hb⟩ := ih (ly + 1) (next_state ld) hrest
      exact ⟨i + 1, by simpa using hi, hb⟩
