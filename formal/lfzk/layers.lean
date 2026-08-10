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
  /-- `LayerChallenge::alpha`: the coefficient combining the two inherited claims. -/
  alpha : F

/-- The layer polynomial the sumcheck of one layer is about, with the two `g` points
already folded together by `alpha` (matching `Quad::bind_g`). -/
noncomputable def layer_poly_of {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) : Vector F (logc + 2 * logw) → F :=
  layer_sumcheck_poly_concat (nc := nc) (nv := nv) Quad Vnext alpha st.q st.g0 st.g1

/-- The honest round polynomials of one layer. -/
noncomputable def layer_true_polys_of {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) (chal : List F) : List (Polynomial F) :=
  generate_true_polys (layer_poly_of (nc := nc) (nv := nv) Quad Vnext alpha st)
    (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)

/-- There is exactly one honest round polynomial per sumcheck variable.  Unlike the other
facts about the honest polynomials this one is a theorem, not an assumption. -/
lemma layer_true_polys_length {nc nv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (Quad : Vector F logw → Vector F logw → Vector F logw → F)
    (Vnext : Vector F logw → Vector F logc → F)
    (alpha : F) (st : LayerState logw logc F) (chal : List F) :
    (layer_true_polys_of (nc := nc) (nv := nv) Quad Vnext alpha st chal).length = logc + 2 * logw := by
  simp [layer_true_polys_of, generate_true_polys]

/--
**Structure: LayeredCircuit**

A multi-layer arithmetization: the honest wire values of every layer, the per-layer `QUAD`,
and the facts about the honest round polynomials that the sumcheck reduction consumes.

* `V ly w betas` is the multilinear extension of the layer-`ly` wire values under witness `w`.
  `V 0` is the output layer; `V nl` is the input layer, i.e. the committed witness columns.
* `Quad ly beta` is `Layer.quad` of layer `ly` (`sumcheck/circuit.h:L33`) *after* `prep_v`,
  which replaces the coefficient of every assert-zero gate by the layer's `beta`
  (`quad.h:L213`; in the Rust, `vcc = if k == 0 { beta * dot } else { k * dot }` inside
  `HQuad::bind_g`).  This matches `ArithmetizedCircuit.Quad_mle`, which takes the same
  argument — the two tracks describe the same object, and `degenerate_agrees`
  (`zk_soundness.lean`) is the proof.

## Why the wire values answer to the challenges

`betas : ℕ → F` is the run's **beta schedule**: `betas ly` is what `begin_layer` draws at
layer `ly` (`rust/runtime/zk/src/symbolic_sumcheck_verifier.rs:L73`).  `V` takes it because
the wire values genuinely depend on it.

For a witness that *satisfies* the circuit this is invisible: every assert-zero gate's operand
product is zero, so `prep_v`'s substitution multiplies zero and `V` is the same for every
schedule.  For a witness that **violates** an assert-zero gate it is the whole point — the
layer's values pick up `beta ·` (the violation), which is how a violated constraint becomes a
non-zero output claim and gets caught.

Indexing `V` by the schedule is a deliberate choice.  The alternative — `V` schedule-free
with `layer_rel` quantified over `beta` — is consistent, but it states the satisfying-witness
case as if it were general: with a `beta`-free right-hand side `Degenerate` cannot depend on
`beta` at all, and the two-variable Schwartz–Zippel count would be bounding a one-variable
form.

`consistent`, `head_sum` and `last_eval` are theorems rather than fields, derived from
`layer_rel` by the hypercube-splitting lemmas in `circuit.lean`.
-/
structure LayeredCircuit (Witness : Type) (nc nv logw logc : ℕ) (F : Type)
    [Field F] [Fintype F] [DecidableEq F] where
  V : ℕ → Witness → (ℕ → F) → Vector F logw → Vector F logc → F
  Quad : ℕ → F → Vector F logw → Vector F logw → Vector F logw → F
  /--
  **`QUAD` is affine in `beta`**, because `prep_v` is: it either keeps a gate's stored
  coefficient or substitutes `beta`, and both are affine.  This is the multi-layer twin of
  the theorem `ArithmetizedCircuit.Quad_mle_affine_beta`; here it is a field because `Quad`
  is abstract rather than built from a gate list.

  It is what makes the layer claim a *bilinear* form in `(alpha, beta)`, hence
  `layer_claim_zero_card`'s `2·|F|` bound.
  -/
  Quad_affine_beta : ∀ (ly : ℕ) (b : F) (g l r : Vector F logw),
    Quad ly b g l r = Quad ly 0 g l r + b * (Quad ly 1 g l r - Quad ly 0 g l r)
  /--
  **Layer `ly`'s values read only layers `ly` and below.**

  `V ly` is built from `V (ly+1)` through `Quad ly`, so it can depend on `betas ly`,
  `betas (ly+1)`, … but not on the challenges of layers *above* it, which it never touches.

  This is what keeps the layer-0 count honest: when `betas 0` is the coordinate being sampled,
  `V 1 w betas` has to be a constant on the fiber, or the claim would not be a bilinear form
  in `(alpha, betas 0)`.  `layer_claim_zero_card` uses it through `betas_tail_eq`.
  -/
  V_local : ∀ (ly : ℕ) (w : Witness) (betas betas' : ℕ → F),
    (∀ i, ly ≤ i → betas i = betas' i) → V ly w betas = V ly w betas'
  /--
  **The layer relation**, and the only thing this structure assumes about the round
  polynomials:

      V ly [g, q] = ∑_{c,l,r ∈ {0,1}^*} EQ[q,c] · QUAD_ly[g|l,r] · V (ly+1)[l,c] · V (ly+1)[r,c]

  stated for the `alpha`-combination of the two `g` points, which is the form the verifier
  actually sumchecks (`claim[0] + alpha * claim[1]` at `verifier_layers.h:L147` against
  `Quad::bind_g`), and at the layer's **own** challenge `betas ly` on both sides.
  -/
  layer_rel : ∀ (ly : ℕ) (w : Witness) (alpha : F) (betas : ℕ → F)
      (st : LayerState logw logc F),
    ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
        layer_poly_of (nc := nc) (nv := nv) (Quad ly (betas ly)) (V (ly + 1) w betas) alpha st
          (boolean_vector j)
      = V ly w betas st.g0 st.q + alpha * V ly w betas st.g1 st.q

namespace LayeredCircuit

variable {nc nv logw logc : ℕ}

omit [SumcheckInterp F] in
/-- Derived: the honest round polynomials of a layer are chained consistently. -/
lemma consistent (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (betas : ℕ → F) (st : LayerState logw logc F)
    (chal : List F) (hchal : chal.length = logc + 2 * logw) :
    consistent_true_polys
      (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly))
        (LC.V (ly + 1) w betas) alpha st chal) chal :=
  consistent_generate _ chal hchal

omit [SumcheckInterp F] in
/-- Derived: the round-0 polynomial's sum over `{0,1}` is the `alpha`-combination of the two
claims the layer relation predicts. -/
lemma head_sum (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (betas : ℕ → F) (st : LayerState logw logc F)
    (chal : List F) (hpos : 0 < logc + 2 * logw) :
    (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly))
        (LC.V (ly + 1) w betas) alpha st chal).head!.eval 0
      + (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly))
        (LC.V (ly + 1) w betas) alpha st chal).head!.eval 1
      = LC.V ly w betas st.g0 st.q + alpha * LC.V ly w betas st.g1 st.q := by
  rw [layer_true_polys_of, head_generate _ _ hpos]
  exact LC.layer_rel ly w alpha betas st

omit [SumcheckInterp F] in
/-- Derived: the honest chain ends at the layer polynomial evaluated at the challenges. -/
lemma last_eval (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (alpha : F) (betas : ℕ → F) (st : LayerState logw logc F)
    (chal : List F) (hchal : chal.length = logc + 2 * logw) (hpos : 0 < logc + 2 * logw) :
    get_last_eval (layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly))
        (LC.V (ly + 1) w betas) alpha st chal) chal
      = some (layer_poly_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly))
                (LC.V (ly + 1) w betas) alpha st
                (Vector.ofFn (n := logc + 2 * logw) fun i => chal.getD i.val 0)) :=
  get_last_eval_generate _ chal hchal hpos

/-- The honest round polynomials of layer `ly` under witness `w`. -/
noncomputable def truePolys (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F)
    (ld : LayerData logw logc F) : List (Polynomial F) :=
  layer_true_polys_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly)) (LC.V (ly + 1) w betas)
    ld.alpha st ld.challenges

/--
`EQQ = EQ[Q,C] * QUAD[G|R,L]` for one layer, recomputed by the verifier at
`verifier_layers.h:L162-L178` (and `zk_common.h:L107-L111`).  `QUAD` is the layer's, bound at
its own `beta` — `HQuad::bind_g` takes `(alpha, beta)` from `begin_layer` of *this* layer.
-/
noncomputable def eqq (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (ly : ℕ) (st : LayerState logw logc F) (ld : LayerData logw logc F) : F :=
  eq_matrix_mle nc logc st.q (challenge_split (logw := logw) (logc := logc) ld.challenges).1 *
    ∑ i ∈ Finset.range nv,
      LC.Quad ly (betas ly) (boolean_vector i)
                   (challenge_split (logw := logw) (logc := logc) ld.challenges).2.1
                   (challenge_split (logw := logw) (logc := logc) ld.challenges).2.2 *
        (eq_mle_basis i st.g0 + ld.alpha * eq_mle_basis i st.g1)

/-!
### The output claim, and where `beta` bites

The per-layer reduction below never needs `beta`: `layer_step` derives its contradiction from
the round polynomials and the `got == claim` check, and a `beta` that makes `EQQ` vanish costs
nothing.  `beta` matters at the *top*, where the run starts.

Both verifiers initialise the output claims to zero — `claim: [Expression::zero, zero]` in
`symbolic_sumcheck_verifier.rs`, `verifier_layers.h:L70` in the C++.  So
`ClaimsCorrect LC 0 w st0` reads "the honest output MLE really is zero at both points", i.e.
"this witness satisfies the circuit as far as the sumcheck can see".  `Degenerate` is the
event that the layer randomness makes that *look* true when it is not, and it is a bilinear
form in `(alpha, beta)` — the same object as `ArithmetizedCircuit.Degenerate`.
-/

/--
**Degenerate layer-0 randomness**, the multi-layer twin of `ArithmetizedCircuit.Degenerate`.

The claim the run starts its sumcheck from is zero.  By `layer_rel` that claim *is* the
`alpha`-combination of the two honest output values, so on this event a wrong pair of starting
claims is indistinguishable from a right one.
-/
noncomputable def Degenerate (LC : LayeredCircuit Witness nc nv logw logc F)
    (w : Witness) (betas : ℕ → F) (alpha beta : F) (st : LayerState logw logc F) : Prop :=
  layer_claim (nc := nc) (nv := nv) (LC.Quad 0 beta) (LC.V 1 w betas) alpha st.q st.g0 st.g1 = 0

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
noncomputable def verify_layer {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (ly : ℕ) (st : LayerState logw logc F) (ld : LayerData logw logc F) :
    Option (LayerState logw logc F) :=
  match verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges with
  | none => none
  | some final =>
      if final = LC.eqq betas ly st ld * ld.wc0 * ld.wc1 then some (next_state ld) else none

/-- The whole `for (ly)` loop of `VerifierLayers::layers`. -/
noncomputable def verify_layers {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Option (LayerState logw logc F)
  | _, st, [] => some st
  | ly, st, ld :: rest =>
      match verify_layer LC betas ly st ld with
      | some st' => verify_layers LC betas (ly + 1) st' rest
      | none => none

/-- The two claims the verifier carries into layer `ly` really are the honest wire values
of layer `ly` at the two points. -/
def ClaimsCorrect {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F) : Prop :=
  st.claim0 = LC.V ly w betas st.g0 st.q ∧ st.claim1 = LC.V ly w betas st.g1 st.q

/-- A lucky sumcheck round inside layer `ly`. -/
def LayerRoundBad {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F)
    (ld : LayerData logw logc F) : Prop :=
  multi_round_bad_event (LC.truePolys ly w betas st ld) ld.polys ld.challenges

/--
The unlucky `alpha` that lets a wrong pair of claims survive the combination
`claim[0] + alpha * claim[1]` (`verifier_layers.h:L147`).

This is the same shape as the input-binding collision, so `input_binding_bad_card` applies:
for a fixed pair of honest and claimed values, at most one `alpha` in the field is bad.
-/
def LayerAlphaBad {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F)
    (ld : LayerData logw logc F) : Prop :=
  InputBindingBad (LC.V ly w betas st.g0 st.q) (LC.V ly w betas st.g1 st.q)
    st.claim0 st.claim1 ld.alpha

omit [SumcheckInterp F] in
/-- At most one `alpha` per layer is bad — the layer-combination analogue of
`input_binding_bad_card`. -/
lemma layer_alpha_bad_card {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (ly : ℕ) (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F) (c0 c1 : F) :
    (Finset.univ.filter (fun a : F =>
      InputBindingBad (LC.V ly w betas st.g0 st.q) (LC.V ly w betas st.g1 st.q)
        c0 c1 a)).card ≤ 1 :=
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
theorem layer_alpha_bad_card_prod {D : Type} [Fintype D] {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (ly : ℕ) (w : Witness) (betas : ℕ → F)
    (st : D → LayerState logw logc F) (c0 c1 : D → F) :
    (Finset.filter (fun p : D × F =>
        InputBindingBad (LC.V ly w betas (st p.1).g0 (st p.1).q)
          (LC.V ly w betas (st p.1).g1 (st p.1).q)
          (c0 p.1) (c1 p.1) p.2) Finset.univ).card ≤ Fintype.card D :=
  alpha_bad_card (fun d => LC.V ly w betas (st d).g0 (st d).q)
    (fun d => LC.V ly w betas (st d).g1 (st d).q) c0 c1

omit [SumcheckInterp F] in
/--
**Non-degenerate layer-0 randomness makes the verifier's zero claims wrong.**

The verifier starts from `claim = [0, 0]`.  If those claims were *correct* — if the honest
output MLE really were zero at both points — then by `layer_rel` the layer-0 claim would be
`0 + alpha·0 = 0`, i.e. degenerate.  So a non-degenerate claim forces `¬ ClaimsCorrect`.

This is what `multi_layer_core_soundness` used to assume outright as `harith`.  It is now a
theorem, and the residual randomness condition is a *counted* event
(`layer_claim_zero_card`), exactly as `Event_Degenerate` is on the single-layer side.

The degeneracy is taken at the run's **own** layer-0 challenge `betas 0`, which is where
`layer_rel` fires.  At any other `beta` the claim is a different quantity — that is exactly
what makes the count below a two-variable one.
-/
lemma zero_claims_wrong {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (w : Witness) (betas : ℕ → F) (alpha : F) (st : LayerState logw logc F)
    (h0 : st.claim0 = 0) (h1 : st.claim1 = 0)
    (hnd : ¬ LC.Degenerate w betas alpha (betas 0) st) :
    ¬ ClaimsCorrect LC 0 w betas st := by
  rintro ⟨hc0, hc1⟩
  refine hnd ?_
  show layer_claim (nc := nc) (nv := nv) (LC.Quad 0 (betas 0)) (LC.V 1 w betas) alpha
      st.q st.g0 st.g1 = 0
  have hrel := LC.layer_rel 0 w alpha betas st
  rw [show ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
        layer_poly_of (nc := nc) (nv := nv) (LC.Quad 0 (betas 0)) (LC.V 1 w betas) alpha st
          (boolean_vector j)
      = layer_claim (nc := nc) (nv := nv) (LC.Quad 0 (betas 0)) (LC.V 1 w betas) alpha
          st.q st.g0 st.g1
      from rfl] at hrel
  rw [hrel, ← hc0, ← hc1, h0, h1]
  ring

omit [SumcheckInterp F] in
/--
**`Degenerate` reads the schedule only from layer 1 up.**

`V 1` is built from `V 2` through `Quad 1`, so it never touches `betas 0`.  Replacing the
schedule by one that agrees from layer 1 onwards therefore leaves `Degenerate` alone.

This is what lets the layer-0 count treat `betas 0` as a *free coordinate*: on a fiber where
only `betas 0` varies, `V 1 w betas` is a constant, and the claim really is a bilinear form in
`(alpha, betas 0)`.  Without it the "everything decided before the challenge" half of the
sample space would not be fixed, and the `2·|F|` bound would not follow.
-/
lemma betas_tail_eq {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (w : Witness) (betas betas' : ℕ → F) (alpha beta : F) (st : LayerState logw logc F)
    (h : ∀ i, 1 ≤ i → betas i = betas' i) :
    LC.Degenerate w betas alpha beta st ↔ LC.Degenerate w betas' alpha beta st := by
  simp only [LayeredCircuit.Degenerate, LC.V_local 1 w betas betas' h]

omit [SumcheckInterp F] in
/--
**At the run's own challenge, `Degenerate` is "the output claim vanishes".**

`layer_rel` fires exactly at `betas 0`, turning the layer-0 hypercube sum into the
`alpha`-combination of the honest output values.  Away from `betas 0` the two sides are
different quantities.  This is why `beta` is not inert: a `beta`-free right-hand side would
force the sum to a fixed value and make `Degenerate` independent of `beta`.
-/
lemma degenerate_at_schedule {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (w : Witness) (betas : ℕ → F) (alpha : F) (st : LayerState logw logc F) :
    LC.Degenerate w betas alpha (betas 0) st
      ↔ LC.V 0 w betas st.g0 st.q + alpha * LC.V 0 w betas st.g1 st.q = 0 := by
  have hrel := LC.layer_rel 0 w alpha betas st
  rw [show ∑ j ∈ Finset.range (2 ^ (logc + 2 * logw)),
        layer_poly_of (nc := nc) (nv := nv) (LC.Quad 0 (betas 0)) (LC.V 1 w betas) alpha st
          (boolean_vector j)
      = layer_claim (nc := nc) (nv := nv) (LC.Quad 0 (betas 0)) (LC.V 1 w betas) alpha
          st.q st.g0 st.g1
      from rfl] at hrel
  simp only [LayeredCircuit.Degenerate, hrel]

omit [SumcheckInterp F] in
/--
**The layer-0 randomness costs `2/|F|`.**

`Degenerate` is a bilinear form in `(alpha, beta)` — affine in `alpha` because the verifier
combines the two claims linearly, affine in `beta` because `prep_v` is (`Quad_affine_beta`) —
so unless it vanishes identically it vanishes on at most `2·|F|` of the `|F|²` pairs.

`hne` is the multi-layer counterpart of `ArithmetizedCircuit.arith`: an unsatisfied witness
does not give an identically-zero output claim.  `degenerate_agrees` below lets an
`ArithmetizedCircuit` supply it.
-/
theorem layer_claim_zero_card {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (w : Witness) (betas : ℕ → F) (st : LayerState logw logc F)
    (hne : ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0 st.q st.g0 st.g1 = 0 ∧
              layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 1 st.q st.g0 st.g1 = 0 ∧
              layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 0 st.q st.g0 st.g1 = 0 ∧
              layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 1 st.q st.g0 st.g1 = 0)) :
    (Finset.filter (fun p : F × F => LC.Degenerate w betas p.2 p.1 st) Finset.univ).card
      ≤ 2 * Fintype.card F := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : F × F =>
      layer_claim (nc := nc) (nv := nv) (LC.Quad 0 p.1) (LC.V 1 w betas) p.2 st.q st.g0 st.g1 = 0)
    Finset.univ) (fun p hp => by simpa [LayeredCircuit.Degenerate] using hp)) ?_
  refine bilinear_zero_card (F := F)
    (fun b a => layer_claim (nc := nc) (nv := nv) (LC.Quad 0 b) (LC.V 1 w betas) a st.q st.g0 st.g1)
    (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0 st.q st.g0 st.g1)
    (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 1 st.q st.g0 st.g1
      - layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0 st.q st.g0 st.g1)
    (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 0 st.q st.g0 st.g1
      - layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0 st.q st.g0 st.g1)
    ((layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 1 st.q st.g0 st.g1
      - layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w betas) 0 st.q st.g0 st.g1)
      - (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 1 st.q st.g0 st.g1
        - layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w betas) 0 st.q st.g0 st.g1)) ?_ ?_
  · intro b a
    have h1 := layer_claim_affine (nc := nc) (nv := nv) (LC.Quad 0 b) (LC.V 1 w betas)
      a st.q st.g0 st.g1
    have h2 := layer_claim_affine_quad (nc := nc) (nv := nv) (LC.Quad 0 b)
      (LC.Quad 0 0) (LC.Quad 0 1) b (fun g l r => LC.Quad_affine_beta 0 b g l r)
      (LC.V 1 w betas) 0 st.q st.g0 st.g1
    have h3 := layer_claim_affine_quad (nc := nc) (nv := nv) (LC.Quad 0 b)
      (LC.Quad 0 0) (LC.Quad 0 1) b (fun g l r => LC.Quad_affine_beta 0 b g l r)
      (LC.V 1 w betas) 1 st.q st.g0 st.g1
    linear_combination h1 + (1 - a) * h2 + a * h3
  · intro hz
    refine hne ⟨hz.1, ?_, ?_, ?_⟩
    · linear_combination hz.1 + hz.2.1
    · linear_combination hz.1 + hz.2.2.1
    · linear_combination hz.1 + hz.2.1 + hz.2.2.1 + hz.2.2.2

/-- Every layer of the run has the round count the verifier enforces. -/
def LayersShapeOK {logw logc : ℕ} {F : Type} (lds : List (LayerData logw logc F)) : Prop :=
  ∀ ld ∈ lds, ld.polys.length = logc + 2 * logw ∧ ld.challenges.length = logc + 2 * logw

/-- No unlucky `alpha` anywhere along the run.  The states are determined by the run, so
this recurses in step with `verify_layers`.

Note there is no `EQQ ≠ 0` condition: `layer_step` derives its contradiction without
cancelling `EQQ`, so a vanishing `EQ[Q,C] * QUAD` costs nothing here. -/
noncomputable def GoodRandomness {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Prop
  | _, _, [] => True
  | ly, st, ld :: rest =>
      ¬ LayerAlphaBad LC ly w betas st ld ∧ GoodRandomness LC w betas (ly + 1) (next_state ld) rest

/-- A lucky sumcheck round somewhere along the run. -/
noncomputable def AnyLayerRoundBad {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → Prop
  | _, _, [] => False
  | ly, st, ld :: rest =>
      LayerRoundBad LC ly w betas st ld ∨ AnyLayerRoundBad LC w betas (ly + 1) (next_state ld) rest


/-!
## The per-layer reduction
-/

/-- `verify_layer` accepts exactly when the sumcheck closes on `EQQ * wc[0] * wc[1]`, and
when it does, the new state is the reduction `next_state ld`. -/
lemma verify_layer_some_iff {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (ly : ℕ) (st st' : LayerState logw logc F) (ld : LayerData logw logc F) :
    verify_layer LC betas ly st ld = some st' ↔
      (st' = next_state ld ∧
        verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges
          = some (LC.eqq betas ly st ld * ld.wc0 * ld.wc1)) := by
  rw [verify_layer]
  cases h_vm : verify_multi_round (st.claim0 + ld.alpha * st.claim1) ld.polys ld.challenges with
  | none => simp
  | some final =>
    by_cases hg : final = LC.eqq betas ly st ld * ld.wc0 * ld.wc1
    · subst hg; simp [eq_comm]
    · simp [hg]

omit [SumcheckInterp F] in
/-- At the transcript's own challenge point the layer polynomial factors as
`EQQ * V(ly+1)[L,C] * V(ly+1)[R,C]`.  This is where the state update
`.g = {hb[0], hb[1]}, .q = cb` (`verifier_layers.h:L195-L196`) meets the sumcheck's final
evaluation point. -/
lemma layer_poly_at_challenges {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (ly : ℕ) (w : Witness) (st : LayerState logw logc F) (ld : LayerData logw logc F) :
    layer_poly_of (nc := nc) (nv := nv) (LC.Quad ly (betas ly)) (LC.V (ly + 1) w betas)
        ld.alpha st
        (Vector.ofFn (n := logc + 2 * logw) fun i => ld.challenges.getD i.val 0)
      = LC.eqq betas ly st ld
        * LC.V (ly + 1) w betas (next_state ld).g0 (next_state ld).q
        * LC.V (ly + 1) w betas (next_state ld).g1 (next_state ld).q := rfl

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
theorem layer_step {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F)
    (ly : ℕ) (w : Witness) (st st' : LayerState logw logc F) (ld : LayerData logw logc F)
    (h_polys : ld.polys.length = logc + 2 * logw)
    (h_chal : ld.challenges.length = logc + 2 * logw)
    (h_pos : 0 < logc + 2 * logw)
    (h_ver : verify_layer LC betas ly st ld = some st')
    (h_wrong : ¬ ClaimsCorrect LC ly w betas st)
    (h_alpha : ¬ LayerAlphaBad LC ly w betas st ld) :
    LayerRoundBad LC ly w betas st ld ∨ ¬ ClaimsCorrect LC (ly + 1) w betas st' := by
  -- unpack the verifier's acceptance of this layer
  obtain ⟨h_st', h_vm⟩ := (verify_layer_some_iff LC betas ly st st' ld).mp h_ver
  subst h_st'
  · -- the combined claim entering the sumcheck is false
    have h_false : st.claim0 + ld.alpha * st.claim1 ≠
        (LC.truePolys ly w betas st ld).head!.eval 0
          + (LC.truePolys ly w betas st ld).head!.eval 1 := by
      rw [LayeredCircuit.truePolys, LC.head_sum _ _ _ _ _ _ h_pos]
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
    have h_len1 : (LC.truePolys ly w betas st ld).length = ld.polys.length := by
      rw [LayeredCircuit.truePolys, layer_true_polys_length, h_polys]
    have h_len2 : ld.challenges.length = ld.polys.length := by rw [h_chal, h_polys]
    have h_red := sumcheck_multi_reduction (LC.truePolys ly w betas st ld) ld.polys ld.challenges
      (st.claim0 + ld.alpha * st.claim1) (LC.eqq betas ly st ld * ld.wc0 * ld.wc1)
      h_vm h_len1 h_len2 (LC.consistent ly w ld.alpha betas st ld.challenges h_chal) h_nnil
      h_false
    cases h_red with
    | inr h_bad => exact Or.inl h_bad
    | inl h_last =>
      right
      -- the honest chain ends at `EQQ * V(ly+1)[L,C] * V(ly+1)[R,C]`
      have h_ge := LC.last_eval ly w ld.alpha betas st ld.challenges h_chal h_pos
      rw [layer_poly_at_challenges LC betas ly w st ld] at h_ge
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
theorem layers_reduction {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F)
    (h_pos : 0 < logc + 2 * logw) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st stF : LayerState logw logc F),
      verify_layers LC betas ly st lds = some stF →
      LayersShapeOK lds →
      GoodRandomness LC w betas ly st lds →
      ¬ ClaimsCorrect LC ly w betas st →
      AnyLayerRoundBad LC w betas ly st lds
        ∨ ¬ ClaimsCorrect LC (ly + lds.length) w betas stF := by
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
    cases h_vl : verify_layer LC betas ly st ld with
    | none => rw [h_vl] at h_ver; exact absurd h_ver (by simp)
    | some st' =>
    rw [h_vl] at h_ver
    obtain ⟨h_alpha, h_good_rest⟩ := h_good
    obtain ⟨h_p, h_c⟩ := h_shape ld (List.mem_cons_self ..)
    -- `verify_layer` always returns `next_state ld`
    have h_st' : st' = next_state ld := ((verify_layer_some_iff LC betas ly st st' ld).mp h_vl).1
    cases layer_step LC betas ly w st st' ld h_p h_c h_pos h_vl h_wrong h_alpha with
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
noncomputable def LayerRoundBadAt {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → ℕ → Prop
  | _, _, [], _ => False
  | ly, st, ld :: _, 0 => LayerRoundBad LC ly w betas st ld
  | ly, _, ld :: rest, (i + 1) => LayerRoundBadAt LC w betas (ly + 1) (next_state ld) rest i

/-- The multi-layer bad event is exactly "some layer was bad". -/
lemma anyLayerRoundBad_exists {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st : LayerState logw logc F),
      AnyLayerRoundBad LC w betas ly st lds →
      ∃ i, i < lds.length ∧ LayerRoundBadAt LC w betas ly st lds i := by
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
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F)
    (lds : List (LayerData logw logc F)) (ly : ℕ) (st : Ω → LayerState logw logc F)
    (nl eps : ℕ) (hnl : lds.length ≤ nl)
    (hBad : ∀ i, i < nl →
      (Finset.filter (fun ω => LayerRoundBadAt LC w betas ly (st ω) lds i)
        Finset.univ).card ≤ eps) :
    (Finset.filter (fun ω => AnyLayerRoundBad LC w betas ly (st ω) lds) Finset.univ).card
      ≤ nl * eps := by
  refine union_bound_layers nl eps
    (fun i ω => LayerRoundBadAt LC w betas ly (st ω) lds i) _ ?_ hBad
  intro ω hω
  obtain ⟨i, hi, hb⟩ := anyLayerRoundBad_exists LC w betas lds ly (st ω) hω
  exact ⟨i, lt_of_lt_of_le hi hnl, hb⟩


/-- "The layer coefficient was unlucky at layer `i` of this run", picking out the `i`-th
conjunct of `GoodRandomness`. -/
noncomputable def LayerAlphaBadAt {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ℕ → LayerState logw logc F → List (LayerData logw logc F) → ℕ → Prop
  | _, _, [], _ => False
  | ly, st, ld :: _, 0 => LayerAlphaBad LC ly w betas st ld
  | ly, _, ld :: rest, (i + 1) => LayerAlphaBadAt LC w betas (ly + 1) (next_state ld) rest i

omit [SumcheckInterp F] in
/-- The converse of `notGoodRandomness_exists`: good randomness means no layer is unlucky. -/
lemma goodRandomness_not_badAt {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st : LayerState logw logc F),
      GoodRandomness LC w betas ly st lds → ∀ i, ¬ LayerAlphaBadAt LC w betas ly st lds i := by
  intro lds
  induction lds with
  | nil => intro ly st _ i; simp [LayerAlphaBadAt]
  | cons ld rest ih =>
      intro ly st hgood i
      rw [GoodRandomness] at hgood
      cases i with
      | zero => rw [LayerAlphaBadAt]; exact hgood.1
      | succ k => rw [LayerAlphaBadAt]; exact ih (ly + 1) (next_state ld) hgood.2 k

omit [SumcheckInterp F] in
/-- Randomness failing somewhere along the run means it failed at some specific layer. -/
lemma notGoodRandomness_exists {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (w : Witness) (betas : ℕ → F) :
    ∀ (lds : List (LayerData logw logc F)) (ly : ℕ) (st : LayerState logw logc F),
      ¬ GoodRandomness LC w betas ly st lds →
      ∃ i, i < lds.length ∧ LayerAlphaBadAt LC w betas ly st lds i := by
  intro lds
  induction lds with
  | nil => intro ly st h; exact absurd trivial h
  | cons ld rest ih =>
    intro ly st h
    rw [GoodRandomness] at h
    by_cases hbad : LayerAlphaBad LC ly w betas st ld
    · exact ⟨0, by simp, hbad⟩
    · have hrest : ¬ GoodRandomness LC w betas (ly + 1) (next_state ld) rest := by
        intro hg; exact h ⟨hbad, hg⟩
      obtain ⟨i, hi, hb⟩ := ih (ly + 1) (next_state ld) hrest
      exact ⟨i + 1, by simpa using hi, hb⟩
