import Mathlib
import sumcheck_soundness
import types
import builder
import circuit
import ligero
import layers

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Joining the layer loop to the ZK/Ligero side

`layers.lean` proves the layer-to-layer reduction for the *sumcheck* verifier; `builder.lean`
and `ligero.lean` handle the ZK side for a *single* layer.  This file runs them together.

## What has to line up

A ZK proof carries, per layer, the `ConstraintBuilder` rounds and the two masked witness
evaluations `wc[0]`, `wc[1]`.  For the sumcheck verifier of `layers.lean` to accept, three
things must match up at every layer:

1. the sumcheck rounds must close on the builder's expression — `builder_run_verifies`;
2. the final claim must equal `EQQ · W[L,C] · W[R,C]` — the `builder_finalize` row, via
   `layer_checks_imply_sumcheck`;
3. the claim the layer *starts* from must be the one the previous layer handed on.

Point 3 is the pad overlap.  `ConstraintBuilder::first` reads `CLAIM_PAD[layer − 1]`
(`zk_common.h:L328-L329`), which is the *previous* layer's `CLAIM_PAD[layer]` — the two
layers' pad layouts overlap by three entries (`PadLayout`, `zk_common.h:L207-L213`).
`ZkLayer.first_matches_next_state` below is exactly that overlap, and it is a theorem: the
value of `builder_first` on the previous layer's `wc`s and claim pads *is* the state
`next_state` produced.
-/

variable {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
variable {Witness : Type}

/--
One layer of a ZK proof.

* `rounds` — the `ConstraintBuilder` rounds (`LayerProof::hp` plus the pad indices of the
  blinders).
* `wc0`, `wc1` — the masked witness evaluations `W_hat[L,C]`, `W_hat[R,C]` (`LayerProof::wc`).
* `alpha` — the first of the pair `begin_layer` draws before any of the layer's messages
  (`let (alpha, beta) = transcript.begin_layer(f)`,
  `rust/runtime/zk/src/symbolic_sumcheck_verifier.rs:L73`); it combines the two inherited
  claims.  The second, `beta`, is *not* stored here: it is `betas ly` of the run's beta
  schedule, since it is a challenge indexed by layer rather than data the prover supplies.
  It reaches the verifier's arithmetic through `bind_quad`'s call to `HQuad::bind_g`.
* `dwL`, `dwR`, `dwLR` — this layer's claim pads `CLAIM_PAD[layer]`, i.e.
  `ovp_claim_pad(0)`, `(1)`, `(2)` (`zk_common.h:L246`).  The next layer's `first` reads
  `dwL` and `dwR`; `dwLR` carries the quadratic relation `dW[L]·dW[R]`.
-/
structure ZkLayer (M : ℕ) (F : Type) where
  rounds : List (RoundData M F)
  wc0 : F
  wc1 : F
  alpha : F
  dwL : Fin M
  dwR : Fin M
  dwLR : Fin M

/-- The unpadded left witness evaluation `W[L,C] = W_hat[L,C] + dW[L,C]`. -/
def ZkLayer.claimL (zl : ZkLayer M F) (pad : Pad M F) : F := zl.wc0 + pad zl.dwL

/-- The unpadded right witness evaluation `W[R,C] = W_hat[R,C] + dW[R,C]`. -/
def ZkLayer.claimR (zl : ZkLayer M F) (pad : Pad M F) : F := zl.wc1 + pad zl.dwR

/-- The sumcheck-side data of one ZK layer, given the pad and the claim it starts from.
The round polynomials are the *unpadded* ones, which is why the pad appears. -/
noncomputable def ZkLayer.toLayerData {logw logc : ℕ} (zl : ZkLayer M F) (pad : Pad M F)
    (claim_in : F) : LayerData logw logc F :=
  { polys := run_polys pad claim_in zl.rounds
    challenges := run_challenges zl.rounds
    wc0 := zl.claimL pad
    wc1 := zl.claimR pad
    alpha := zl.alpha }

omit [Fintype F] [DecidableEq F] in
/--
**The pad overlap, as a theorem.**

`ConstraintBuilder::first` for a layer reads the *previous* layer's claim pads
(`CLAIM_PAD[layer − 1]`, `zk_common.h:L328-L329`).  Its value is exactly the claim the
sumcheck verifier carries forward — `next_state` of the previous layer's data, combined by
this layer's `alpha`.

This is what makes the two sides composable: the ZK expression and the sumcheck state agree
at every layer boundary.
-/
lemma ZkLayer.first_matches_next_state {logw logc : ℕ}
    (prev zl : ZkLayer M F) (pad : Pad M F) (claim_prev : F) :
    evaluates_to (builder_first zl.alpha prev.wc0 prev.wc1 prev.dwL prev.dwR) pad
      = (next_state (prev.toLayerData (logw := logw) (logc := logc) pad claim_prev)).claim0
        + zl.alpha
          * (next_state (prev.toLayerData (logw := logw) (logc := logc) pad claim_prev)).claim1 := by
  rw [builder_first_eval]
  rfl

/--
The Ligero rows of one layer, at **the expression the verifier actually builds**.

`e` is a parameter rather than an existential.  That matters: an existential would admit rows
no verifier could construct.  `ZkRowsHold` below supplies the real one — `Expression.zero` at
layer 0, matching `claims_state.claim = [zero, zero]`
(`symbolic_sumcheck_verifier.rs`), and `builder_first` on the previous layer's `wc`s and claim
pads at an interior layer, matching `claim.axpy(claim[0], 1); claim.axpy(claim[1], alpha)`.
-/
def ZkLayerRow {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F)
    (ly : ℕ) (st : LayerState logw logc F) (zl : ZkLayer M F) (e : Expression M F) : Prop :=
  evaluates_to e pad = st.claim0 + zl.alpha * st.claim1 ∧
  ligero_layer_checks (builder_run e zl.rounds) pad
    (LC.eqq betas ly st (zl.toLayerData (logw := logw) (logc := logc) pad
      (st.claim0 + zl.alpha * st.claim1)))
    zl.wc0 zl.wc1 zl.dwL zl.dwR zl.dwLR

/-- The starting expression of a layer: `Expression.zero` for the first layer, and the
previous layer's claims combined with this layer's `alpha` otherwise. -/
noncomputable def zkExpr (prev : Option (ZkLayer M F)) (alpha : F) : Expression M F :=
  match prev with
  | none => Expression.zero M F
  | some p => builder_first alpha p.wc0 p.wc1 p.dwL p.dwR

/-- **One layer of a ZK proof drives `verify_layer` to accept.**  The round checks pass by
construction (`builder_run_verifies`) and the final identity is what `finalize` forces. -/
theorem zk_layer_verifies {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F)
    (ly : ℕ) (st : LayerState logw logc F) (zl : ZkLayer M F) (e : Expression M F)
    (h : ZkLayerRow LC betas pad ly st zl e) :
    verify_layer LC betas ly st (zl.toLayerData (logw := logw) (logc := logc) pad
        (st.claim0 + zl.alpha * st.claim1))
      = some (next_state (zl.toLayerData (logw := logw) (logc := logc) pad
        (st.claim0 + zl.alpha * st.claim1))) := by
  set ld := zl.toLayerData (logw := logw) (logc := logc) pad (st.claim0 + zl.alpha * st.claim1)
    with hld
  obtain ⟨he, hrowIn⟩ := h
  refine (verify_layer_some_iff LC betas ly st _ ld).mpr ⟨rfl, ?_⟩
  have hrun := builder_run_verifies pad zl.rounds e
  rw [he] at hrun
  have hrow := layer_checks_imply_sumcheck (builder_run e zl.rounds) pad
    (LC.eqq betas ly st ld) zl.wc0 zl.wc1 zl.dwL zl.dwR zl.dwLR hrowIn
  have hld_eq : ld.alpha = zl.alpha := rfl
  have hpolys : ld.polys = run_polys pad (st.claim0 + zl.alpha * st.claim1) zl.rounds := rfl
  have hchal : ld.challenges = run_challenges zl.rounds := rfl
  rw [hld_eq, hpolys, hchal, hrun, hrow]
  rfl

/-! ## The whole ZK proof -/

/-- The sumcheck-side data of a whole ZK proof, one `LayerData` per layer, threading the
state through. -/
noncomputable def zkLayerDatas {logw logc : ℕ} (pad : Pad M F) :
    LayerState logw logc F → List (ZkLayer M F) → List (LayerData logw logc F)
  | _, [] => []
  | st, zl :: rest =>
      zl.toLayerData pad (st.claim0 + zl.alpha * st.claim1)
        :: zkLayerDatas pad (next_state (zl.toLayerData pad (st.claim0 + zl.alpha * st.claim1))) rest

/-- The state the ZK proof ends on. -/
noncomputable def zkFinalState {logw logc : ℕ} (pad : Pad M F) :
    LayerState logw logc F → List (ZkLayer M F) → LayerState logw logc F
  | st, [] => st
  | st, zl :: rest =>
      zkFinalState pad (next_state (zl.toLayerData pad (st.claim0 + zl.alpha * st.claim1))) rest

omit [Fintype F] [DecidableEq F] in
@[simp] lemma zkLayerDatas_length {logw logc : ℕ} (pad : Pad M F) :
    ∀ (st : LayerState logw logc F) (zls : List (ZkLayer M F)),
      (zkLayerDatas pad st zls).length = zls.length := by
  intro st zls
  induction zls generalizing st with
  | nil => rfl
  | cons zl rest ih => simp [zkLayerDatas, ih]

noncomputable def ZkRowsHold {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F) :
    ℕ → LayerState logw logc F → Option (ZkLayer M F) → List (ZkLayer M F) → Prop
  | _, _, _, [] => True
  | ly, st, prev, zl :: rest =>
      ZkLayerRow LC betas pad ly st zl (zkExpr prev zl.alpha) ∧
        ZkRowsHold LC betas pad (ly + 1)
          (next_state (zl.toLayerData pad (st.claim0 + zl.alpha * st.claim1))) (some zl) rest

omit [Fintype F] [DecidableEq F] in
/--
**At an interior layer the claim conjunct is free.**

`ZkLayer.first_matches_next_state` says the value of `builder_first` on the previous layer's
data *is* the claim `next_state` handed on.  So for every layer after the first, the first
conjunct of `ZkLayerRow` is a theorem rather than an assumption — only layer 0 constrains
anything, and what it constrains is that the run starts from claims of zero.
-/
lemma zkExpr_some_eval {logw logc : ℕ} (prev zl : ZkLayer M F) (pad : Pad M F)
    (claim_prev : F) :
    evaluates_to (zkExpr (some prev) zl.alpha) pad
      = (next_state (prev.toLayerData (logw := logw) (logc := logc) pad claim_prev)).claim0
        + zl.alpha
          * (next_state (prev.toLayerData (logw := logw) (logc := logc) pad claim_prev)).claim1 :=
  ZkLayer.first_matches_next_state prev zl pad claim_prev

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- At layer 0 the expression is `Expression.zero`, so the first conjunct says exactly that
the run starts from a zero output claim — which is how both verifiers initialise. -/
lemma zkExpr_none_eval (alpha : F) (pad : Pad M F) :
    evaluates_to (zkExpr (none : Option (ZkLayer M F)) alpha) pad = 0 := by
  simp [zkExpr, Expression.evaluates_to_zero]

/--
**The ZK proof drives the whole layer loop.**

Every layer's Ligero rows together make `VerifierLayers::layers` accept the entire run.
This is the join that was missing: `layers.lean` could reduce claims from one layer to the
next, but nothing connected those layers to the ZK constraint system.
-/
theorem zk_layers_verify {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F) :
    ∀ (zls : List (ZkLayer M F)) (ly : ℕ) (st : LayerState logw logc F)
      (prev : Option (ZkLayer M F)),
      ZkRowsHold LC betas pad ly st prev zls →
      verify_layers LC betas ly st (zkLayerDatas pad st zls)
        = some (zkFinalState pad st zls) := by
  intro zls
  induction zls with
  | nil => intro ly st prev _; rfl
  | cons zl rest ih =>
    intro ly st prev hrows
    obtain ⟨hrow, hrest⟩ := hrows
    rw [zkLayerDatas, zkFinalState, verify_layers,
      zk_layer_verifies LC betas pad ly st zl (zkExpr prev zl.alpha) hrow]
    exact ih (ly + 1) _ (some zl) hrest

/--
**Multi-layer soundness of the ZK composition.**

If the ZK proof's Ligero rows hold at every layer, the layer randomness is non-degenerate,
and the claims the run *starts* from are wrong — which is what an unsatisfied circuit means
— then the prover was lucky in some sumcheck round of some layer, or the claims it ends on,
about the *input* layer, are wrong.

Composing this with `input_row_binds_hands` (which pins the input-layer claims to the
committed witness) rules out the second alternative, leaving only luck.
-/
theorem zk_multi_layer_soundness {nc nv logw logc : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F)
    (w : Witness) (hpos : 0 < logc + 2 * logw)
    (zls : List (ZkLayer M F)) (st0 : LayerState logw logc F)
    (hrows : ZkRowsHold LC betas pad 0 st0 none zls)
    (hshape : LayersShapeOK (zkLayerDatas pad st0 zls))
    (hrand : GoodRandomness LC w betas 0 st0 (zkLayerDatas pad st0 zls))
    (hwrong : ¬ ClaimsCorrect LC 0 w betas st0) :
    AnyLayerRoundBad LC w betas 0 st0 (zkLayerDatas pad st0 zls)
      ∨ ¬ ClaimsCorrect LC zls.length w betas (zkFinalState pad st0 zls) := by
  have h := layers_reduction LC w betas hpos (zkLayerDatas pad st0 zls) 0 st0
    (zkFinalState pad st0 zls) (zk_layers_verify LC betas pad zls 0 st0 none hrows)
    hshape hrand hwrong
  have hlen : (zkLayerDatas pad st0 zls).length = zls.length := zkLayerDatas_length pad st0 zls
  rw [hlen] at h
  simpa using h
