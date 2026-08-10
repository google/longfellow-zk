import Mathlib
import sumcheck_soundness
import types
import builder
import circuit
import ligero
import ligero_sys
import layers
import zk_layers
import zk_soundness
import zk_sim
import instantiate

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# From a generic Ligero theorem to Longfellow's row facts

`IsLigeroSound` (`ligero_sys.lean`) is the statement a Ligero paper proves: accepted runs
whose extraction succeeds yield an assignment satisfying the **public** system.  This file
derives Longfellow's Ligero hypotheses from it, so that nothing Longfellow-specific is assumed
about Ligero any more.

Two bridges, one per shape of system:

* `isLigeroKnowledgeSound_of_sound` — the one-layer bundle `IsLigeroKnowledgeSound`
  (`ligero.lean`) from `IsLigeroSound` at `buildSystem`.  Both of its row fields come out of
  `buildSystem_Sat`, and `extraction_bound` is `IsLigeroSound.extraction` transported along
  `Option.map`.
* `zkRowsHold_of_sound` — the multi-layer hypothesis `h_rows` of `multi_layer_core_soundness`
  (`zk_soundness.lean`) from `IsLigeroSound` at `buildSystemMulti`, plus
  `ligeroInputRow_of_sound` for the input row of the same system.

What is *not* here: turning the input row into `MEvent_Input`'s bound.  On the one-layer path
that step is `input_row_binds_hands`, which reads the extracted columns through
`ArithmetizedCircuit.W_col`.  The layered model has no `ArithmetizedCircuit` — `LayeredCircuit.V`
is abstract — so the same step needs an interface law saying that the *input* layer's value
function is the committed wire MLE.  `LayeredInputMLE` below states that law and
`mevent_input_card_of_row` completes the derivation from it.
-/

variable {F : Type} [Field F] [Fintype F]
variable {Circuit Input Witness : Type}
variable {Ω : Type} [Fintype Ω]
variable {nc nv : ℕ}

/-!
## One layer

The Longfellow-specific bundle, derived.  Note the shape of the extractor: a Ligero theorem
returns *columns*, not a witness, so the composition goes through `AC.W_col` at the
transcript's own copy point.
-/

/-- The system a one-layer Longfellow run presents to Ligero: `buildSystem` at the layer's
own `(alpha, beta)` and the fresh `alpha_in`. -/
noncomputable def longfellowSystem {nc nv ninp npub logv logw logc M : ℕ}
    [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (T_p : Ω → EncTranscript M F) (c : Circuit) (inp : Input) (w_ref : Witness)
    (alpha beta alpha_in : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwL var_dwR var_dwL_dwR : Fin M) (ω : Ω) : LigeroSystem ninp M F :=
  buildSystem npub (T_p ω).e
    (layer_eqq AC c (alpha ω) (beta ω) q_challenge g0 g1 (T_p ω).challenges)
    (T_p ω).wc0 (T_p ω).wc1
    (input_row_coeffs (logw := logw) (logc := logc) (ninp := ninp) (alpha_in ω)
      (T_p ω).challenges)
    (pubBinding AC inp w_ref (alpha_in ω) (T_p ω).challenges)
    (alpha_in ω) var_dwL var_dwR var_dwL_dwR

/-- The assignment a Longfellow extractor presents to Ligero: the extracted witness read as
input columns at the transcript's copy point, together with the extracted pad. -/
noncomputable def longfellowAssignment {nc nv ninp npub logv logw logc M : ℕ}
    [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (T_p : Ω → EncTranscript M F) (inp : Input)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) :
    Option (LigeroAssignment ninp M F) :=
  (E_L ω).map (fun a =>
    (AC.W_col inp a.1
      (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).1, a.2))

omit [Fintype Ω] in
lemma longfellowAssignment_none {nc nv ninp npub logv logw logc M : ℕ} [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (T_p : Ω → EncTranscript M F) (inp : Input)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) :
    longfellowAssignment (logw := logw) (logc := logc) AC T_p inp E_L ω = none
      ↔ E_L ω = none := by
  simp [longfellowAssignment]

/--
**`IsLigeroKnowledgeSound`, derived.**

Every field of the Longfellow bundle comes out of the generic one:

* `extraction_bound` — `Option.map` does not change whether extraction failed, so `Event_A` and
  the generic extraction event are the same set;
* `layer_constraint` and `input_row` — `buildSystem_Sat` says satisfaction of the built system
  *is* the conjunction of the two, so both are projections of `IsLigeroSound.sound`.

This is what makes `IsLigeroKnowledgeSound` a convenience packaging rather than an assumption
in its own right: a Ligero formalisation supplying `IsLigeroSound` supplies all of it.
-/
theorem isLigeroKnowledgeSound_of_sound {nc nv ninp npub logv logw logc M : ℕ}
    [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F)
    (c : Circuit) (inp : Input) (w_ref : Witness)
    (alpha beta alpha_in : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (eps : ℕ)
    (gen : IsLigeroSound accepts
      (longfellowSystem (npub := npub) AC T_p c inp w_ref alpha beta alpha_in q_challenge g0 g1
        var_dwL var_dwR var_dwL_dwR)
      (longfellowAssignment (logw := logw) (logc := logc) AC T_p inp E_L) eps) :
    IsLigeroKnowledgeSound AC accepts T_p c inp w_ref alpha beta alpha_in q_challenge g0 g1
      var_dwR var_dwL var_dwL_dwR E_L eps where
  extraction_bound := by
    refine le_trans (Finset.card_le_card ?_) gen.extraction
    intro ω hω
    simp only [Event_A, Finset.mem_filter, Finset.mem_univ, true_and] at hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    exact ⟨hω.1, (longfellowAssignment_none (logw := logw) (logc := logc) AC T_p inp E_L ω).mpr
      hω.2⟩
  layer_constraint := by
    intro ω w p hacc hE
    have hs := gen.sound ω _ hacc (by
      show (E_L ω).map _ = _
      rw [hE]; rfl)
    exact ((buildSystem_Sat npub _ _ _ _ _ _ _ _ _ _ _ _).mp hs).1
  input_row := by
    intro ω w p hacc hE
    have hs := gen.sound ω _ hacc (by
      show (E_L ω).map _ = _
      rw [hE]; rfl)
    exact ((buildSystem_Sat npub _ _ _ _ _ _ _ _ _ _ _ _).mp hs).2

/-!
## A whole run

`buildSystemMulti_Sat` already characterises satisfaction of the run's system as the per-layer
`ligero_layer_checks` plus one input row.  What remains is to line the run's `ZkLayer` list up
with the `LayerRowData` list the system is built from, and to observe that the *other* conjunct
of `ZkLayerRow` — that the layer's starting expression evaluates to the incoming claim — is a
theorem, not a row: `zkExpr_some_eval` at every interior layer, and `Expression.zero` at
layer 0.
-/

-- `DecidableEq (Fin M)` is deliberately *not* a section variable here: `zk_layers.lean`
-- states `ligero_layer_checks` at the canonical `instDecidableEqFin`, and a competing instance
-- would make the two statements fail to match.
variable {M : ℕ} [DecidableEq F] [SumcheckInterp F]
variable {logw logc : ℕ}

/--
**The `LayerRowData` list a run of `ZkLayer`s determines — and it is public.**

Layer `ly`'s expression is its rounds run from its starting expression (`ConstraintBuilder::first`
on the previous layer's transmitted claims, `Expression.zero` at layer 0), and its coefficient
is read off `eqqs`, the verifier's own layer coefficients.

Nothing here mentions the pad, the witness or the `LayeredCircuit`: a Ligero system has to be a
function of public data and transmitted values, and this is where that is enforced.  The link
back to the model's `LayeredCircuit.eqq` is a *separate* condition, `EqqAgree`, precisely so
that it cannot smuggle secret data into the system.
-/
noncomputable def zkLayerRowDatas (eqqs : ℕ → F) :
    ℕ → Option (ZkLayer M F) → List (ZkLayer M F) → List (LayerRowData M F)
  | _, _, [] => []
  | ly, prev, zl :: rest =>
      ({ e := builder_run (zkExpr prev zl.alpha) zl.rounds
         eqq := eqqs ly
         wc0 := zl.wc0
         wc1 := zl.wc1
         var_dwL := zl.dwL
         var_dwR := zl.dwR
         var_dwLR := zl.dwLR } : LayerRowData M F)
        :: zkLayerRowDatas eqqs (ly + 1) (some zl) rest

/--
**The public layer coefficients are the model's, along this run.**

`LayeredCircuit.eqq` takes the whole `LayerData`, which carries pad-dependent fields, so it
cannot be used to *build* the system.  `EqqAgree` says the public `eqqs` the system was built
from agree with it at the states this particular run passes through — which is what the
implementation computes, since `layer_eqq` reads only challenges.

Stating it as a run-indexed conjunction rather than as `∀ ly st ld` is deliberate: the
universally quantified version would be false, since `eqqs ly` is one number and `LC.eqq` varies
with the state.
-/
def EqqAgree (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F)
    (eqqs : ℕ → F) : ℕ → LayerState logw logc F → List (ZkLayer M F) → Prop
  | _, _, [] => True
  | ly, st, zl :: rest =>
      eqqs ly = LC.eqq betas ly st (zl.toLayerData (logw := logw) (logc := logc) pad
        (st.claim0 + zl.alpha * st.claim1)) ∧
      EqqAgree LC betas pad eqqs (ly + 1)
        (next_state (zl.toLayerData (logw := logw) (logc := logc) pad
          (st.claim0 + zl.alpha * st.claim1))) rest

/--
**The run's rows, from the per-layer checks.**

The induction carries one invariant: the layer about to run starts from an expression that
evaluates to its incoming claim.  At an interior layer that is `zkExpr_some_eval` — a theorem
about `ConstraintBuilder::first` — so the only place it is a real condition is layer 0, where
it says the run starts from claims of zero.
-/
theorem zkRowsHold_of_checks (LC : LayeredCircuit Witness nc nv logw logc F)
    (betas : ℕ → F) (pad : Pad M F) (eqqs : ℕ → F) :
    ∀ (zls : List (ZkLayer M F)) (ly : ℕ) (st : LayerState logw logc F)
      (prev : Option (ZkLayer M F)),
      (∀ zl ∈ zls.head?, evaluates_to (zkExpr prev zl.alpha) pad
        = st.claim0 + zl.alpha * st.claim1) →
      EqqAgree LC betas pad eqqs ly st zls →
      (∀ L ∈ zkLayerRowDatas (M := M) eqqs ly prev zls,
        ligero_layer_checks L.e pad L.eqq L.wc0 L.wc1 L.var_dwL L.var_dwR L.var_dwLR) →
      ZkRowsHold LC betas pad ly st prev zls := by
  intro zls
  induction zls with
  | nil => intro _ _ _ _ _ _; trivial
  | cons zl rest ih =>
    intro ly st prev hstart heqq hrows
    obtain ⟨heq0, heqrest⟩ := heqq
    refine ⟨⟨hstart zl (by simp), ?_⟩, ?_⟩
    · have := hrows _ (by rw [zkLayerRowDatas]; exact List.mem_cons_self ..)
      rw [← heq0]
      exact this
    · refine ih (ly + 1) _ (some zl) ?_ heqrest ?_
      · intro zl' _
        exact zkExpr_some_eval (logw := logw) (logc := logc) zl zl' pad
          (st.claim0 + zl.alpha * st.claim1)
      · intro L hL
        refine hrows L ?_
        rw [zkLayerRowDatas]
        exact List.mem_cons_of_mem _ hL

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- At layer `0` the invariant is exactly "the run starts from claims of zero", which is how
both verifiers initialise (`claims_state.claim = [zero, zero]`). -/
theorem zkStart_zero (pad : Pad M F) (st0 : LayerState logw logc F) (alpha : F)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0) :
    evaluates_to (zkExpr (M := M) none alpha) pad = st0.claim0 + alpha * st0.claim1 := by
  rw [hzero0, hzero1, zkExpr]
  show evaluates_to (Expression.zero M F) pad = _
  rw [Expression.evaluates_to_zero]
  ring

/--
**`h_rows`, derived.**

`multi_layer_core_soundness` takes `ZkRowsHold` as a hypothesis.  This derives it from the
generic Ligero guarantee at the run's own system, so the multi-layer theorem no longer assumes
anything Ligero-specific beyond `IsLigeroSound` and the refinement condition `EqqAgree`.

Note what the system is a function of: `T ω` (the transmitted layers), `eqqs ω` (the verifier's
own coefficients) and the input-row data.  Not the pad, and not the witness.
-/
theorem zkRowsHold_of_sound {ninp npub : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : Ω → Prop) (betas : Ω → ℕ → F)
    (st0 : LayerState logw logc F) (T : Ω → List (ZkLayer M F)) (eqqs : Ω → ℕ → F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (colOf : Ω → Witness → Fin ninp → F)
    (bcoef : Ω → Fin ninp → F) (pub_binding got alpha : Ω → F) (ivL ivR : Ω → Fin M)
    (eps : ℕ)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω) 0 none (T ω))
        (bcoef ω) (pub_binding ω) (got ω) (alpha ω) (ivL ω) (ivR ω))
      (fun ω => (E_L ω).map (fun a => (colOf ω a.1, a.2))) eps)
    (ω : Ω) (w : Witness) (pad : Pad M F) (hacc : accepts ω) (hE : E_L ω = some (w, pad))
    (heqq : EqqAgree LC (betas ω) pad (eqqs ω) 0 st0 (T ω)) :
    ZkRowsHold LC (betas ω) pad 0 st0 none (T ω) := by
  have hs := gen.sound ω (colOf ω w, pad) hacc (by rw [hE]; rfl)
  have hrows := (buildSystemMulti_Sat npub _ _ _ _ _ _ _ (colOf ω w) pad).mp hs
  refine zkRowsHold_of_checks LC (betas ω) pad (eqqs ω) (T ω) 0 st0 none ?_ heqq hrows.1
  intro zl _
  exact zkStart_zero pad st0 zl.alpha hzero0 hzero1

omit [Fintype F] [DecidableEq F] in
/-- The run's **input row**, from the same generic guarantee.  This is the other half of
`buildSystemMulti_Sat`: what pins the last layer's claims to the committed columns. -/
theorem ligeroInputRow_of_sound {ninp npub : ℕ}
    (accepts : Ω → Prop) (T : Ω → List (ZkLayer M F)) (eqqs : Ω → ℕ → F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (colOf : Ω → Witness → Fin ninp → F)
    (bcoef : Ω → Fin ninp → F) (pub_binding got alpha : Ω → F) (ivL ivR : Ω → Fin M)
    (eps : ℕ)
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω) 0 none (T ω))
        (bcoef ω) (pub_binding ω) (got ω) (alpha ω) (ivL ω) (ivR ω))
      (fun ω => (E_L ω).map (fun a => (colOf ω a.1, a.2))) eps)
    (ω : Ω) (w : Witness) (pad : Pad M F) (hacc : accepts ω) (hE : E_L ω = some (w, pad)) :
    ligero_input_row npub (colOf ω w) pad (bcoef ω) (pub_binding ω) (got ω) (alpha ω)
      (ivL ω) (ivR ω) := by
  have hs := gen.sound ω (colOf ω w, pad) hacc (by rw [hE]; rfl)
  exact ((buildSystemMulti_Sat npub _ _ _ _ _ _ _ (colOf ω w) pad).mp hs).2

/-!
## The input binding, derived

`multi_layer_core_soundness` takes `h_bind : event_card (MEvent_Input …) ≤ eps_bind` as a
hypothesis, with `eps_bind` supplied by the caller.  On the one-layer path that number is
*earned*: `input_row_binds_hands` turns the Ligero input row into the claim equalities, and
`Event_AlphaBad` costs `1/|F|` because `alpha_in` is fresh.  This section does the same for a
whole run.

One thing has to be added, and it is unavoidable: `LayeredCircuit.V` is abstract, so nothing
yet says the *input* layer's value function is the multilinear extension of the committed
columns.  `LayeredInputMLE` states exactly that and nothing more.  It is the layered twin of
`ArithmetizedCircuit.W_mle_is_mle`, which on the one-layer path is definitional.
-/

omit [Fintype F] [DecidableEq F] in
/-- **The state a run ends in is the last layer's.**  Its claims are that layer's unpadded
hand evaluations and its points are that layer's challenge split — which is what the input row
has to be compared against. -/
theorem zkFinalState_last (pad : Pad M F) :
    ∀ (zls : List (ZkLayer M F)) (st : LayerState logw logc F) (zl : ZkLayer M F),
      zls.getLast? = some zl →
      (zkFinalState (logw := logw) (logc := logc) pad st zls).claim0 = zl.wc0 + pad zl.dwL ∧
      (zkFinalState (logw := logw) (logc := logc) pad st zls).claim1 = zl.wc1 + pad zl.dwR ∧
      (zkFinalState (logw := logw) (logc := logc) pad st zls).q
        = (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1 ∧
      (zkFinalState (logw := logw) (logc := logc) pad st zls).g0
        = (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.1 ∧
      (zkFinalState (logw := logw) (logc := logc) pad st zls).g1
        = (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.2 := by
  intro zls
  induction zls with
  | nil => intro _ _ h; simp at h
  | cons a rest ih =>
    intro st zl hlast
    cases rest with
    | nil =>
      have : a = zl := by simpa using hlast
      subst this
      exact ⟨rfl, rfl, rfl, rfl, rfl⟩
    | cons b tl =>
      have hlast' : (b :: tl).getLast? = some zl := by
        rw [← hlast]; simp [List.getLast?_cons_cons]
      exact ih _ zl hlast'

/--
**The input layer's value function is the committed wire MLE.**

`LayeredCircuit.V nl` is the value function *below* the last layer — the circuit's input
wires.  This says it is the multilinear extension of the columns Ligero committed to, which is
what lets the input row say anything about the model at all.

It is an interface law, not a theorem, because `LayeredCircuit` is abstract; a construction of
a `LayeredCircuit` from a compiled circuit would discharge it definitionally, exactly as
`ArithmetizedCircuit.W_mle_is_mle` does on the one-layer path.
-/
def LayeredInputMLE {ninp : ℕ} (LC : LayeredCircuit Witness nc nv logw logc F) (nl : ℕ)
    (betas : ℕ → F) (colOf : Vector F logc → Witness → Fin ninp → F) : Prop :=
  ∀ (w : Witness) (g : Vector F logw) (q : Vector F logc),
    LC.V nl w betas g q = ∑ i : Fin ninp, eq_mle_basis i.val g * colOf q w i

/--
**`ClaimsCorrect`, from the input row.**

The run's final claims are the last layer's `wc + pad dw`; the input row forces their
`alpha_in`-combination to equal the same combination of the committed columns' multilinear
extensions at the last layer's two hand points.  A fresh `alpha_in` separates the two, and
`LayeredInputMLE` identifies the extensions with `LC.V nl`.

This is the multi-layer twin of `input_row_binds_hands`, and it is what makes `eps_bind` an
*earned* `1/|F|` rather than a supplied number.
-/
theorem claimsCorrect_of_inputRow {ninp npub nl : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (betas : ℕ → F) (pad : Pad M F)
    (colOf : Vector F logc → Witness → Fin ninp → F)
    (hV : LayeredInputMLE LC nl betas colOf)
    (w : Witness) (alpha_in : F) (pub_binding : F)
    (zls : List (ZkLayer M F)) (zl : ZkLayer M F) (st0 : LayerState logw logc F)
    (hlast : zls.getLast? = some zl)
    (hpub : pub_binding = ∑ i ∈ Finset.univ \ privIdx ninp npub,
      input_row_coeffs (logw := logw) (logc := logc) alpha_in (run_challenges zl.rounds) i
        * colOf (challenge_split (logw := logw) (logc := logc)
            (run_challenges zl.rounds)).1 w i)
    (hrow : ligero_input_row npub
      (colOf (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1 w)
      pad
      (input_row_coeffs (logw := logw) (logc := logc) alpha_in (run_challenges zl.rounds))
      pub_binding (zl.wc0 + alpha_in * zl.wc1) alpha_in zl.dwL zl.dwR)
    (hnb : ¬ InputBindingBad
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.1
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.2
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (zl.wc0 + pad zl.dwL) (zl.wc1 + pad zl.dwR) alpha_in) :
    ClaimsCorrect LC nl w betas (zkFinalState (logw := logw) (logc := logc) pad st0 zls) := by
  obtain ⟨hc0, hc1, hq, hg0, hg1⟩ := zkFinalState_last pad zls st0 zl hlast
  set sp := challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds) with hsp
  set col := colOf sp.1 w with hcol
  -- the row forces the full weighted column sum
  have hsum := input_row_soundness npub col pad
    (input_row_coeffs (logw := logw) (logc := logc) alpha_in (run_challenges zl.rounds))
    pub_binding (zl.wc0 + alpha_in * zl.wc1) alpha_in zl.dwL zl.dwR hpub hrow
  -- and that sum is the alpha_in-combination of the two multilinear extensions
  have hsplit : (∑ i : Fin ninp,
      input_row_coeffs (logw := logw) (logc := logc) alpha_in (run_challenges zl.rounds) i
        * col i)
      = (∑ i : Fin ninp, eq_mle_basis i.val sp.2.1 * col i)
        + alpha_in * ∑ i : Fin ninp, eq_mle_basis i.val sp.2.2 * col i := by
    rw [Finset.mul_sum, ← Finset.sum_add_distrib]
    refine Finset.sum_congr rfl (fun i _ => ?_)
    simp only [input_row_coeffs, ← hsp]
    ring
  rw [hsplit, ← hV w sp.2.1 sp.1, ← hV w sp.2.2 sp.1] at hsum
  -- separate the two hands with the fresh challenge
  obtain ⟨h0, h1⟩ := alpha_separates _ _ _ _ alpha_in hnb (by linear_combination hsum)
  exact ⟨by rw [hc0, hg0, hq, ← h0], by rw [hc1, hg1, hq, ← h1]⟩

/-- The quantities the fresh `alpha_in` has to separate at the end of a run: the model's two
input-layer values against the run's two final claims.  Empty runs have nothing to separate,
which is why this is an `∃` over the last layer rather than a `∀`. -/
def RunBindingBad (LC : LayeredCircuit Witness nc nv logw logc F) (nl : ℕ)
    (betas : ℕ → F) (zls : List (ZkLayer M F)) (w : Witness) (pad : Pad M F) (a : F) : Prop :=
  ∃ zl ∈ zls.getLast?,
    InputBindingBad
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.1
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.2
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (zl.wc0 + pad zl.dwL) (zl.wc1 + pad zl.dwR) a

omit [SumcheckInterp F] in
/-- **At most one `alpha_in` in the field is bad**, for any fixed run and extracted
assignment — `input_binding_bad_card`, transported across the last-layer projection.  This is
what makes the input binding cost `1/|F|` and not more. -/
lemma runBindingBad_card (LC : LayeredCircuit Witness nc nv logw logc F) (nl : ℕ)
    (betas : ℕ → F) (zls : List (ZkLayer M F)) (w : Witness) (pad : Pad M F) :
    (Finset.filter (fun a : F => RunBindingBad LC nl betas zls w pad a)
      Finset.univ).card ≤ 1 := by
  cases hl : zls.getLast? with
  | none =>
    refine le_trans (Finset.card_le_card (t := (∅ : Finset F)) ?_) (by simp)
    intro a ha
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, RunBindingBad] at ha
    obtain ⟨zl, hzl, -⟩ := ha
    rw [hl] at hzl
    simp at hzl
  | some zl =>
    refine le_trans (Finset.card_le_card (t := Finset.filter (fun a : F => InputBindingBad
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.1
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (LC.V nl w betas
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).2.2
        (challenge_split (logw := logw) (logc := logc) (run_challenges zl.rounds)).1)
      (zl.wc0 + pad zl.dwL) (zl.wc1 + pad zl.dwR) a) Finset.univ) ?_)
      (input_binding_bad_card _ _ _ _)
    intro a ha
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, RunBindingBad] at ha ⊢
    obtain ⟨zl', hzl', hbad⟩ := ha
    rw [hl] at hzl'
    cases Option.some.inj hzl'
    exact hbad

/--
**`h_bind`, earned.**

Over a sample space split as `D × F` — everything decided before the input challenge, then the
challenge itself — the input binding costs at most `|D|` out of `|D| · |F|`, a `1/|F|`
fraction.  This is the multi-layer twin of the one-layer `Event_AlphaBad` bound, and it is what
`multi_layer_core_soundness` was previously handed as the unexplained number `eps_bind`.

`hbind` is the hypothesis `claimsCorrect_of_inputRow` discharges: on a run where `alpha_in` is
*not* bad, the Ligero input row forces the final claims to be the model's input-layer values.
The counting itself is `option_bad_pairs_card`: the extractor's output is fixed before the
challenge is drawn, so the two quantities the challenge must separate are constants and at most
one draw fails.
-/
theorem mevent_input_card {D : Type} [Fintype D] {nl : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : D × F → Prop)
    (betas : D → ℕ → F) (st0 : LayerState logw logc F)
    (T : D → List (ZkLayer M F)) (E_pre : D → Option (AugmentedWitness M F Witness))
    (hlen : ∀ d, (T d).length = nl)
    (hbind : ∀ (d : D) (a : F) (w : Witness) (pad : Pad M F),
      E_pre d = some (w, pad) → ¬ RunBindingBad LC nl (betas d) (T d) w pad a →
      ClaimsCorrect LC nl w (betas d)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (T d))) :
    event_card (MEvent_Input LC accepts (fun p => betas p.1) st0 (fun p => T p.1)
      (fun p => E_pre p.1)) ≤ Fintype.card D := by
  refine le_trans (Finset.card_le_card (t := Finset.filter
    (fun p : D × F => ∃ v : AugmentedWitness M F Witness, E_pre p.1 = some v ∧
      RunBindingBad LC nl (betas p.1) (T p.1) v.1 v.2 p.2) Finset.univ) ?_) ?_
  · intro p hp
    simp only [MEvent_Input, Finset.mem_filter, Finset.mem_univ, true_and] at hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and]
    obtain ⟨-, w, pad, hE, hno⟩ := hp
    refine ⟨(w, pad), hE, ?_⟩
    by_contra hgood
    exact hno (by rw [hlen p.1]; exact hbind p.1 p.2 w pad hE hgood)
  · exact option_bad_pairs_card E_pre
      (fun d v a => RunBindingBad LC nl (betas d) (T d) v.1 v.2 a)
      (fun d v => runBindingBad_card LC nl (betas d) (T d) v.1 v.2)

/-!
## Non-vacuity

`IsLigeroSound` is a hypothesis of everything above, so the bridges say nothing unless it is
inhabitable — and inhabitable at a system with rows in it, not at the empty one.
-/

omit [Fintype F] [DecidableEq F] in
/-- One row per layer: the run's system has exactly as many layer rows as the run has layers,
so `zkRowsHold_of_sound` is not about a truncated run. -/
@[simp] lemma zkLayerRowDatas_length (eqqs : ℕ → F) :
    ∀ (zls : List (ZkLayer M F)) (ly : ℕ) (prev : Option (ZkLayer M F)),
      (zkLayerRowDatas (M := M) eqqs ly prev zls).length = zls.length := by
  intro zls
  induction zls with
  | nil => intro _ _; rfl
  | cons a rest ih => intro ly prev; simp [zkLayerRowDatas, ih]

namespace LigeroSoundExample

instance : Fact (Nat.Prime 7) := ⟨by norm_num⟩

abbrev F7 := ZMod 7

/-- A one-row system over one input column and a two-slot pad: `wcol 0 = pad 0`, with the
quadratic triple `pad 1 = pad 0 · pad 0`. -/
noncomputable def sys1 : LigeroSystem 1 2 F7 :=
  { linear := [{ cw := fun _ => 1, cp := fun j => if j = 0 then -1 else 0, rhs := 0 }]
    quad := [(0, 0, 1)] }

/-- The assignment an honest prover commits: `wcol = v`, `pad = (v, v²)`. -/
noncomputable def asg (v : F7) : LigeroAssignment 1 2 F7 :=
  (fun _ => v, fun j => if j = 0 then v else v * v)

/-- **`IsLigeroSound` is inhabited at a system with a real row and a real triple**, with a
knowledge error of `0`: over the sample space `F7` of committed values, extraction always
succeeds and what it returns satisfies the system. -/
theorem sound1 : IsLigeroSound (Ω := F7) (fun _ => True) (fun _ => sys1)
    (fun v => some (asg v)) 0 where
  extraction := by
    simp [event_card]
  sound := by
    rintro v a - ha
    cases Option.some.inj ha
    refine ⟨?_, ?_⟩
    · intro row hrow
      have : row = { cw := fun _ => 1, cp := fun j => if j = 0 then -1 else 0, rhs := 0 } := by
        simpa [sys1] using hrow
      subst this
      show (∑ _i : Fin 1, (1 : F7) * v) + (∑ j : Fin 2, (if j = 0 then -1 else 0) * _) = 0
      simp [asg, Fin.sum_univ_two]
    · intro t ht
      have : t = ((0 : Fin 2), (0 : Fin 2), (1 : Fin 2)) := by simpa [sys1] using ht
      subst this
      show (if (1 : Fin 2) = 0 then v else v * v) = _
      simp [asg]

/-- And the system it is inhabited at is not the empty one. -/
example : sys1.linear.length = 1 ∧ sys1.quad.length = 1 := ⟨rfl, rfl⟩

end LigeroSoundExample

/-- `eps_bind`, over an abstract sample space that splits at `alpha_in`. -/
theorem mevent_input_card_split {D : Type} [Fintype D] [DecidableEq D] {nl : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F) (accepts : Ω → Prop)
    (betas : D → ℕ → F) (st0 : LayerState logw logc F)
    (dataOf : Ω → D) (ainOf : Ω → F)
    (hinj : Function.Injective (fun ω => (dataOf ω, ainOf ω)))
    (T : D → List (ZkLayer M F)) (E_pre : D → Option (AugmentedWitness M F Witness))
    (hlen : ∀ d, (T d).length = nl)
    (hbind : ∀ (d : D) (a : F) (w : Witness) (pad : Pad M F),
      E_pre d = some (w, pad) → ¬ RunBindingBad LC nl (betas d) (T d) w pad a →
      ClaimsCorrect LC nl w (betas d)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (T d))) :
    event_card (MEvent_Input LC accepts (fun ω => betas (dataOf ω)) st0
      (fun ω => T (dataOf ω)) (fun ω => E_pre (dataOf ω))) ≤ Fintype.card D := by
  classical
  obtain ⟨Q, hQdef⟩ : ∃ Q : D × F → Prop, Q = fun p =>
      (fun _ : D × F => True) p ∧ ∃ w pad, E_pre p.1 = some (w, pad) ∧
        ¬ ClaimsCorrect LC (T p.1).length w (betas p.1)
          (zkFinalState (logw := logw) (logc := logc) pad st0 (T p.1)) := ⟨_, rfl⟩
  have hQ : (Finset.filter Q Finset.univ).card ≤ Fintype.card D := by
    refine le_trans (Finset.card_le_card ?_)
      (mevent_input_card (D := D) LC (fun _ : D × F => True) betas st0 T E_pre hlen hbind)
    intro p hp
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hQdef, MEvent_Input] at hp ⊢
    exact hp
  have hmain := event_card_le_split (Ω := Ω) dataOf ainOf hinj
    (fun ω => accepts ω ∧ ∃ w pad, E_pre (dataOf ω) = some (w, pad) ∧
      ¬ ClaimsCorrect LC (T (dataOf ω)).length w (betas (dataOf ω))
        (zkFinalState (logw := logw) (logc := logc) pad st0 (T (dataOf ω))))
    Q (fun ω hω => by
      obtain ⟨-, w, pad, hE, hno⟩ := hω
      rw [hQdef]
      exact ⟨trivial, w, pad, hE, hno⟩)
    (Fintype.card D) hQ
  refine le_trans (Finset.card_le_card ?_) hmain
  intro ω hω
  simp only [MEvent_Input, Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  exact hω

/-!
## The composition

`multi_layer_core_soundness` is a union bound over six events, and it takes five of them as
numbers.  Three of those five now have derivations: `h_extract` and `h_rows` from
`IsLigeroSound`, `h_bind` from `mevent_input_card`, and `h_deg` from `mevent_degenerate_card`.
What was missing was a sample space with room for all of them at once — `mevent_degenerate_card`
needs the layer-0 `(beta, alpha)` pair as a coordinate and `mevent_input_card` needs `alpha_in`
as one, and the multi-layer theorem had neither.

The space here is the one the protocol's schedule dictates, and it is the same shape the
one-layer path already uses (`core_soundness_probability`):

```
Ω  =  (D × (beta₀, alpha₀)) × alpha_in
```

* `D` — the commitment and the prover's coins, fixed by `ZkProver::commit` before any
  challenge exists.  The extractor reads only this;
* `(beta₀, alpha₀)` — what `begin_layer` draws at layer 0 (`symbolic_sumcheck_verifier.rs:L73`).
  The transmitted layers may depend on it, since it is drawn first;
* `alpha_in` — drawn after the whole layer loop (`symbolic_sumcheck_verifier.rs:L247`).  Only
  the input row reads it, which is what makes its collision bound `1/|F|`.

The beta *schedule* is `Function.update tail 0 beta₀`: layer 0's coefficient is the sampled
coordinate and later layers keep a fixed tail, which is exactly what `mevent_degenerate_card`
counts against.

Two terms stay as hypotheses, and deliberately: `eps_alpha` and `eps_round` are the sumcheck
side — the per-layer claim combination and the per-layer round luck — bounded by the
Fiat–Shamir machinery in `fiat_shamir.lean`, not by anything Ligero says.
-/

section MultiComposition

variable {D : Type} [Fintype D]

omit [Fintype F] [DecidableEq F] [SumcheckInterp F] in
/-- `Event_A` is the generic extraction event: `Option.map` cannot change whether extraction
failed, so the Longfellow-shaped assignment has the same failure set as the raw extractor. -/
lemma event_A_le_of_sound {ninp : ℕ}
    (accepts : Ω → Prop) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (colOf : Ω → Witness → Fin ninp → F) (system : Ω → LigeroSystem ninp M F) (eps : ℕ)
    (gen : IsLigeroSound accepts system
      (fun ω => (E_L ω).map (fun a => (colOf ω a.1, a.2))) eps) :
    event_card (Event_A accepts E_L) ≤ eps := by
  refine le_trans (Finset.card_le_card ?_) gen.extraction
  intro ω hω
  simp only [Event_A, Finset.mem_filter, Finset.mem_univ, true_and] at hω
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]
  exact ⟨hω.1, by rw [hω.2]; rfl⟩

/--
**Multi-layer knowledge soundness, composed.**

Every Ligero-side term is derived rather than supplied:

```
|MEvent_Fail|  ≤  eps_FSK  +  nl·eps_alpha  +  nl·eps_round  +  |D|·|F|²  +  2·|D|·|F|²
```

out of `|Ω| = |D|·|F|³`, so the last two are the `1/|F|` input binding and the `2/|F|`
layer-0 degeneracy.  `eps_FSK` is `IsLigeroSound`'s knowledge error and nothing else.

The hypotheses that remain are of three kinds.  Structural: `hpos`, `hlen`, `hzero0`,
`hzero1`, `hshape`.  Refinement: `heqq`, that the verifier's public layer coefficients are the
ones the model computes along the run, and `hbind`, which `claimsCorrect_of_inputRow` discharges
from the input row that `ligeroInputRow_of_sound` extracts from the same `gen`.  Arithmetic:
`hne`, that an unsatisfying witness does not give an identically-zero output claim — the
multi-layer face of `ArithmetizedCircuit.arith`.
-/
theorem multi_layer_soundness_composed {ninp npub nl : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : (D × (F × F)) × F → Prop)
    (st0 : LayerState logw logc F) (tail : ℕ → F)
    (T_pre : D × (F × F) → List (ZkLayer M F)) (eqqs : D × (F × F) → ℕ → F)
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (colOf : (D × (F × F)) × F → Witness → Fin ninp → F)
    (bcoef : (D × (F × F)) × F → Fin ninp → F)
    (pub_binding got : (D × (F × F)) × F → F)
    (ivL ivR : (D × (F × F)) × F → Fin M)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (eps_FSK eps_alpha eps_round : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hlen : ∀ p : D × (F × F), (T_pre p).length = nl)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : (D × (F × F)) × F) (w : Witness) (pad : Pad M F),
      accepts ω → E_pre ω.1.1 = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T_pre ω.1)))
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω.1) 0 none (T_pre ω.1))
        (bcoef ω) (pub_binding ω) (got ω) ω.2 (ivL ω) (ivR ω))
      (fun ω => (E_pre ω.1.1).map (fun a => (colOf ω a.1, a.2))) eps_FSK)
    (heqq : ∀ (ω : (D × (F × F)) × F) (w : Witness) (pad : Pad M F),
      accepts ω → E_pre ω.1.1 = some (w, pad) →
      EqqAgree LC (Function.update tail 0 ω.1.2.1) pad (eqqs ω.1) 0 st0 (T_pre ω.1))
    (hbind : ∀ (p : D × (F × F)) (a : F) (w : Witness) (pad : Pad M F),
      E_pre p.1 = some (w, pad) →
      ¬ RunBindingBad LC nl (Function.update tail 0 p.2.1) (T_pre p) w pad a →
      ClaimsCorrect LC nl w (Function.update tail 0 p.2.1)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (T_pre p)))
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0))
    (h_alpha : ∀ i, i < nl →
      event_card (MEvent_RandAt LC accepts (fun ω => Function.update tail 0 ω.1.2.1) st0
        (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) i) ≤ eps_alpha)
    (h_round : ∀ i, i < nl →
      event_card (MEvent_RoundAt LC accepts (fun ω => Function.update tail 0 ω.1.2.1) st0
        (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) i) ≤ eps_round) :
    event_card (MEvent_Fail accepts ev c inp (fun ω => E_pre ω.1.1))
      ≤ eps_FSK + nl * eps_alpha + nl * eps_round
        + Fintype.card D * Fintype.card F * Fintype.card F
        + Fintype.card D * (2 * Fintype.card F) * Fintype.card F := by
  classical
  -- the run's beta schedule: layer 0's coefficient is the sampled coordinate
  set betas : (D × (F × F)) × F → ℕ → F :=
    fun ω => Function.update tail 0 ω.1.2.1 with hbetas
  -- `h_bind`: the input binding, at `|D'| = |D|·|F|²`
  have h_bind : event_card (MEvent_Input LC accepts betas st0
      (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1))
      ≤ Fintype.card D * Fintype.card F * Fintype.card F := by
    refine le_trans (mevent_input_card (D := D × (F × F)) LC accepts
      (fun p => Function.update tail 0 p.2.1) st0 T_pre (fun p => E_pre p.1) hlen hbind)
      (le_of_eq ?_)
    simp [Fintype.card_prod, mul_assoc]
  -- `h_deg`: the layer-0 pair, at `|D|·2|F|` on the prefix, carried across `alpha_in`
  have h_deg : event_card (MEvent_Degenerate LC accepts betas st0 (fun ω => ω.1.2.2)
      (fun ω => E_pre ω.1.1) ev c inp)
      ≤ Fintype.card D * (2 * Fintype.card F) * Fintype.card F := by
    set S := MEvent_Degenerate LC (fun _ : D × (F × F) => True)
      (fun p => Function.update tail 0 p.2.1) st0 (fun p => p.2.2) (fun p => E_pre p.1)
      ev c inp with hS
    have hSle : (Finset.filter (fun p : D × (F × F) => p ∈ S) Finset.univ).card
        ≤ Fintype.card D * (2 * Fintype.card F) := by
      have : Finset.filter (fun p : D × (F × F) => p ∈ S) Finset.univ = S := by
        ext p; simp
      rw [this, hS]
      exact mevent_degenerate_card LC _ st0 E_pre ev c inp tail hne
    refine le_trans (Finset.card_le_card ?_)
      (card_filter_fst_le (X := D × (F × F)) (Y := F) (fun p => p ∈ S)
        (Fintype.card D * (2 * Fintype.card F)) hSle)
    intro ω hω
    simp only [MEvent_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, hS, MEvent_Degenerate]
    obtain ⟨-, w, pad, hE, hev, hdeg⟩ := hω
    exact ⟨w, pad, hE, hev, hdeg⟩
  refine multi_layer_core_soundness LC accepts betas st0 (fun ω => ω.1.2.2)
    (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) ev c inp nl eps_FSK eps_alpha eps_round
    _ _ hpos (fun ω => le_of_eq (hlen ω.1)) hzero0 hzero1 hshape ?_ ?_ h_alpha h_round
    h_bind h_deg
  · exact event_A_le_of_sound accepts (fun ω => E_pre ω.1.1) colOf _ eps_FSK gen
  · intro ω w pad hacc hE
    exact zkRowsHold_of_sound (npub := npub) LC accepts betas st0 (fun ω => T_pre ω.1)
      (fun ω => eqqs ω.1) (fun ω => E_pre ω.1.1) colOf bcoef pub_binding got
      (fun ω => ω.2) ivL ivR eps_FSK hzero0 hzero1 gen ω w pad hacc hE
      (heqq ω w pad hacc hE)



/--
**The same bound, as a probability.**

Divide by `|Ω| = |D|·|F|³`.  The two derived randomness terms are `|D|·|F|²` and `2·|D|·|F|²`,
so they contribute `1/|F|` and `2/|F|`; together with the one the layer relation already pays
inside `count_to_prob`, that is the `3/|F|`.  What is left over is `eps_FSK` — Ligero's
knowledge error — and the sumcheck terms, both still as fractions of the sample space.

This is the multi-layer twin of `core_soundness_probability`, and the shape is the same:

```
Pr[accepts ∧ extraction fails]  ≤  eps_FSK/|Ω|  +  3/|F|  +  nl·(eps_alpha + eps_round)/|Ω|
```
-/
theorem multi_layer_soundness_probability {ninp npub nl : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : (D × (F × F)) × F → Prop)
    (st0 : LayerState logw logc F) (tail : ℕ → F)
    (T_pre : D × (F × F) → List (ZkLayer M F)) (eqqs : D × (F × F) → ℕ → F)
    (E_pre : D → Option (AugmentedWitness M F Witness))
    (colOf : (D × (F × F)) × F → Witness → Fin ninp → F)
    (bcoef : (D × (F × F)) × F → Fin ninp → F)
    (pub_binding got : (D × (F × F)) × F → F)
    (ivL ivR : (D × (F × F)) × F → Fin M)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (eps_FSK eps_alpha eps_round : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hlen : ∀ p : D × (F × F), (T_pre p).length = nl)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : (D × (F × F)) × F) (w : Witness) (pad : Pad M F),
      accepts ω → E_pre ω.1.1 = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T_pre ω.1)))
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω.1) 0 none (T_pre ω.1))
        (bcoef ω) (pub_binding ω) (got ω) ω.2 (ivL ω) (ivR ω))
      (fun ω => (E_pre ω.1.1).map (fun a => (colOf ω a.1, a.2))) eps_FSK)
    (heqq : ∀ (ω : (D × (F × F)) × F) (w : Witness) (pad : Pad M F),
      accepts ω → E_pre ω.1.1 = some (w, pad) →
      EqqAgree LC (Function.update tail 0 ω.1.2.1) pad (eqqs ω.1) 0 st0 (T_pre ω.1))
    (hbind : ∀ (p : D × (F × F)) (a : F) (w : Witness) (pad : Pad M F),
      E_pre p.1 = some (w, pad) →
      ¬ RunBindingBad LC nl (Function.update tail 0 p.2.1) (T_pre p) w pad a →
      ClaimsCorrect LC nl w (Function.update tail 0 p.2.1)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (T_pre p)))
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0))
    (h_alpha : ∀ i, i < nl →
      event_card (MEvent_RandAt LC accepts (fun ω => Function.update tail 0 ω.1.2.1) st0
        (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) i) ≤ eps_alpha)
    (h_round : ∀ i, i < nl →
      event_card (MEvent_RoundAt LC accepts (fun ω => Function.update tail 0 ω.1.2.1) st0
        (fun ω => T_pre ω.1) (fun ω => E_pre ω.1.1) i) ≤ eps_round)
    (hDpos : 0 < Fintype.card D) (hFpos : 0 < Fintype.card F) :
    (event_card (MEvent_Fail accepts ev c inp (fun ω => E_pre ω.1.1)) : ℚ)
        / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F)
      ≤ (eps_FSK : ℚ)
          / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F)
        + 3 / Fintype.card F
        + ((nl * eps_alpha + nl * eps_round : ℕ) : ℚ)
            / (Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F) := by
  refine count_to_prob (b := Fintype.card D * Fintype.card F * Fintype.card F)
    (c := Fintype.card D * (2 * Fintype.card F) * Fintype.card F) hDpos hFpos ?_ le_rfl
    (le_of_eq (by ring))
  refine le_trans (multi_layer_soundness_composed (npub := npub) LC accepts st0 tail T_pre eqqs
    E_pre colOf bcoef pub_binding got ivL ivR ev c inp eps_FSK eps_alpha eps_round hpos hlen
    hzero0 hzero1 hshape gen heqq hbind hne h_alpha h_round) (le_of_eq (by ring))

omit [Field F] [DecidableEq F] [SumcheckInterp F] in
/-- **The denominator really is the sample space.**  `multi_layer_soundness_probability`
divides by `|D|·|F|³`; this is what makes that a probability rather than an arbitrary
normalisation. -/
lemma card_runSpace :
    Fintype.card ((D × (F × F)) × F)
      = Fintype.card D * Fintype.card F * Fintype.card F * Fintype.card F := by
  simp [Fintype.card_prod, mul_assoc]

end MultiComposition

/-!
## Every term derived, over an abstract sample space

`multi_layer_soundness_composed` fixes `Ω = (D × (beta₀, alpha₀)) × alpha_in`, which has room
for layer 0's pair and `alpha_in` but not for the per-layer challenges, so it takes `eps_alpha`
and `eps_round` as numbers.

Here the sample space is abstract and the protocol's causality is supplied as *splittings*:
for each challenge the verifier sends, a pair of maps saying "everything decided before it"
and "it".  That is what each counting lemma needs, without committing the development to one
product encoding.

The resulting bound is

```
|MEvent_Fail| ≤ eps_FSK + nl·|Dα| + nl·K·|S|·n·d·|F|^(n−1) + |Dbind| + 2·|Ddeg|·|F|
```

**This is a count, and only a count.**  The splittings here are `Function.Injective`, which
embeds `Ω` into `D × B` and so gives `|Ω| ≤ |D| · |B|` — *not* `|D| = |Ω| / |B|`.  Over a
one-point sample space every map is injective and `|D| = |Ω|`, so the bound is the trivial one;
`split_injective_not_pinning` (`types.lean`) is that counterexample.  `K` is likewise only
constrained by a `≤`, and `K = |Ω|` discharges `h_unifR` by `card_le_univ`.

To read any of these as a *fraction* the splittings must be **bijections**.  `card_of_split_bij`
then pins `|Ω| = |D| · |B|`, `pair_fiber_le_one` pins `K = 1`, and `multi_layer_prob_of_cards`
does the division, giving

```
eps_FSK/|Ω|  +  3/|F|  +  nl·(1 + n·d)/|F|.
```
-/

section AllDerived

variable {Dα Dbind Ddeg S : Type}
variable [Fintype Dα] [DecidableEq Dα] [Fintype Dbind] [DecidableEq Dbind]
variable [Fintype Ddeg] [DecidableEq Ddeg] [Fintype S] [DecidableEq S]

theorem multi_layer_soundness_all_derived {ninp npub nl n dd : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F) (tail : ℕ → F)
    (betas : Ω → ℕ → F) (T : Ω → List (ZkLayer M F)) (eqqs : Ω → ℕ → F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (colOf : Ω → Witness → Fin ninp → F) (bcoef : Ω → Fin ninp → F)
    (pub_binding got alpha_in : Ω → F) (ivL ivR : Ω → Fin M)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (eps_FSK : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω)))
    -- Ligero, as a black box, over the run's own public system
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω) 0 none (T ω))
        (bcoef ω) (pub_binding ω) (got ω) (alpha_in ω) (ivL ω) (ivR ω))
      (fun ω => (E_L ω).map (fun a => (colOf ω a.1, a.2))) eps_FSK)
    (heqq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      EqqAgree LC (betas ω) pad (eqqs ω) 0 st0 (T ω))
    -- the splitting at each layer's `alpha`
    (dataα : ℕ → Ω → Dα) (alphaα : ℕ → Ω → F)
    (hinjα : ∀ i, Function.Injective (fun ω => (dataα i ω, alphaα i ω)))
    (betasα : ℕ → Dα → ℕ → F) (hbetasα : ∀ i, (fun ω => betasα i (dataα i ω)) = betas)
    (E_preα : ℕ → Dα → Option (AugmentedWitness M F Witness))
    (hEα : ∀ i, (fun ω => E_preα i (dataα i ω)) = E_L)
    (STα : ℕ → Dα → Pad M F → LayerState logw logc F)
    (hstateα : ∀ i (ω : Ω) (pad : Pad M F),
      stateAfter st0 (zkLayerDatas pad st0 (T ω)) i = STα i (dataα i ω) pad)
    (halphaα : ∀ i (ω : Ω) (pad : Pad M F) (ld : LayerData logw logc F),
      (zkLayerDatas pad st0 (T ω))[i]? = some ld → ld.alpha = alphaα i ω)
    (hlenα : ∀ i (ω : Ω) (pad : Pad M F), i < nl → i < (zkLayerDatas pad st0 (T ω)).length)
    -- the splitting at each layer's round challenges
    (fam : IsFiatShamirFamily S F n dd)
    (stateR : ℕ → Ω → S) (chalR : ℕ → Ω → (Fin n → F)) (K : ℕ)
    (h_unifR : ∀ i (s : S) (cs : Fin n → F),
      (Finset.filter (fun ω => stateR i ω = s ∧ chalR i ω = cs) Finset.univ).card ≤ K)
    (naR : ∀ i, i < nl →
      IsLayerNonAdaptive LC fam accepts betas st0 T E_L i (stateR i) (chalR i))
    -- the splitting at `alpha_in`
    (dataB : Ω → Dbind) (ainB : Ω → F)
    (hinjB : Function.Injective (fun ω => (dataB ω, ainB ω)))
    (betasB : Dbind → ℕ → F) (hbetasB : (fun ω => betasB (dataB ω)) = betas)
    (TB : Dbind → List (ZkLayer M F)) (hTB : (fun ω => TB (dataB ω)) = T)
    (E_preB : Dbind → Option (AugmentedWitness M F Witness))
    (hEB : (fun ω => E_preB (dataB ω)) = E_L)
    (hlenB : ∀ d, (TB d).length = nl)
    (hbindB : ∀ (d : Dbind) (a : F) (w : Witness) (pad : Pad M F),
      E_preB d = some (w, pad) → ¬ RunBindingBad LC nl (betasB d) (TB d) w pad a →
      ClaimsCorrect LC nl w (betasB d)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (TB d)))
    -- the splitting at layer 0's `(beta, alpha)` pair
    (dataG : Ω → Ddeg) (pairG : Ω → F × F)
    (hinjG : Function.Injective (fun ω => (dataG ω, pairG ω)))
    (hbetasG : (fun ω => Function.update tail 0 (pairG ω).1) = betas)
    (E_preG : Ddeg → Option (AugmentedWitness M F Witness))
    (hEG : (fun ω => E_preG (dataG ω)) = E_L)
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0)) :
    event_card (MEvent_Fail accepts ev c inp E_L)
      ≤ eps_FSK + nl * Fintype.card Dα
        + nl * (K * (Fintype.card S * (n * dd * (Fintype.card F) ^ (n - 1))))
        + Fintype.card Dbind
        + Fintype.card Ddeg * (2 * Fintype.card F) := by
  classical
  refine multi_layer_core_soundness LC accepts betas st0 (fun ω => (pairG ω).2) T E_L ev c inp
    nl eps_FSK (Fintype.card Dα)
    (K * (Fintype.card S * (n * dd * (Fintype.card F) ^ (n - 1))))
    (Fintype.card Dbind) (Fintype.card Ddeg * (2 * Fintype.card F))
    hpos hnl hzero0 hzero1 hshape ?_ ?_ ?_ ?_ ?_ ?_
  · exact event_A_le_of_sound accepts E_L colOf _ eps_FSK gen
  · intro ω w pad hacc hE
    exact zkRowsHold_of_sound (npub := npub) LC accepts betas st0 T eqqs E_L colOf bcoef
      pub_binding got alpha_in ivL ivR eps_FSK hzero0 hzero1 gen ω w pad hacc hE
      (heqq ω w pad hacc hE)
  · intro i _
    have h := mevent_randAt_card_split LC accepts (betasα i) st0 (dataα i) (alphaα i)
      (hinjα i) T (E_preα i) i (STα i) (hstateα i) (halphaα i)
      (fun ω pad => hlenα i ω pad (by omega))
    rw [hbetasα i, hEα i] at h
    exact h
  · intro i hi
    exact mevent_roundAt_card LC fam accepts betas st0 T E_L i (stateR i) (chalR i) K
      (h_unifR i) (naR i hi)
  · have h := mevent_input_card_split (nl := nl) LC accepts betasB st0 dataB ainB hinjB TB
      E_preB hlenB hbindB
    rw [hbetasB, hTB, hEB] at h
    exact h
  · have h := mevent_degenerate_card_split LC accepts st0 dataG pairG hinjG E_preG ev c inp
      tail hne
    rw [hbetasG, hEG] at h
    exact h

/-!
## The probability, assembled

`multi_layer_soundness_all_derived` is a count, and its splittings are only injective — which
embeds `Ω` into `D × B` and does not pin `|D| = |Ω| / |B|`.  This is the same statement with
the splittings strengthened to **bijections**, which is what the protocol's sample space
actually is: at each challenge the run really does decompose as "everything before it" times
"it", with nothing left over and nothing repeated.

Strengthening buys three things at once, and they are exactly the gaps in the count's
interpretation:

* every cardinality equality is *derived* here (`card_of_split_bij`) rather than assumed;
* the load factor `K` disappears — a bijective splitting at the round challenges makes
  `pair_fiber_le_one` give `K = 1`, so it is no longer a number a caller supplies;
* the conclusion is the probability, so a reader has no arithmetic left to perform.
-/
theorem multi_layer_soundness_probability_all_derived {ninp npub nl n dd : ℕ}
    (LC : LayeredCircuit Witness nc nv logw logc F)
    (accepts : Ω → Prop) (st0 : LayerState logw logc F) (tail : ℕ → F)
    (betas : Ω → ℕ → F) (T : Ω → List (ZkLayer M F)) (eqqs : Ω → ℕ → F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (colOf : Ω → Witness → Fin ninp → F) (bcoef : Ω → Fin ninp → F)
    (pub_binding got alpha_in : Ω → F) (ivL ivR : Ω → Fin M)
    (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input)
    (eps_FSK : ℕ)
    (hpos : 0 < logc + 2 * logw)
    (hnl : ∀ ω : Ω, (T ω).length ≤ nl)
    (hzero0 : st0.claim0 = 0) (hzero1 : st0.claim1 = 0)
    (hshape : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      LayersShapeOK (zkLayerDatas pad st0 (T ω)))
    -- Ligero, as a black box, over the run's own public system
    (gen : IsLigeroSound accepts
      (fun ω => buildSystemMulti npub (zkLayerRowDatas (M := M) (eqqs ω) 0 none (T ω))
        (bcoef ω) (pub_binding ω) (got ω) (alpha_in ω) (ivL ω) (ivR ω))
      (fun ω => (E_L ω).map (fun a => (colOf ω a.1, a.2))) eps_FSK)
    (heqq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
      EqqAgree LC (betas ω) pad (eqqs ω) 0 st0 (T ω))
    -- the splitting at each layer's `alpha`
    (dataα : ℕ → Ω → Dα) (alphaα : ℕ → Ω → F)
    (hbijα : ∀ i, Function.Bijective (fun ω => (dataα i ω, alphaα i ω)))
    (betasα : ℕ → Dα → ℕ → F) (hbetasα : ∀ i, (fun ω => betasα i (dataα i ω)) = betas)
    (E_preα : ℕ → Dα → Option (AugmentedWitness M F Witness))
    (hEα : ∀ i, (fun ω => E_preα i (dataα i ω)) = E_L)
    (STα : ℕ → Dα → Pad M F → LayerState logw logc F)
    (hstateα : ∀ i (ω : Ω) (pad : Pad M F),
      stateAfter st0 (zkLayerDatas pad st0 (T ω)) i = STα i (dataα i ω) pad)
    (halphaα : ∀ i (ω : Ω) (pad : Pad M F) (ld : LayerData logw logc F),
      (zkLayerDatas pad st0 (T ω))[i]? = some ld → ld.alpha = alphaα i ω)
    (hlenα : ∀ i (ω : Ω) (pad : Pad M F), i < nl → i < (zkLayerDatas pad st0 (T ω)).length)
    -- the splitting at each layer's round challenges
    (fam : IsFiatShamirFamily S F n dd)
    (stateR : ℕ → Ω → S) (chalR : ℕ → Ω → (Fin n → F))
    (hbijR : ∀ i, Function.Bijective (fun ω => (stateR i ω, chalR i ω)))
    (naR : ∀ i, i < nl →
      IsLayerNonAdaptive LC fam accepts betas st0 T E_L i (stateR i) (chalR i))
    -- the splitting at `alpha_in`
    (dataB : Ω → Dbind) (ainB : Ω → F)
    (hbijB : Function.Bijective (fun ω => (dataB ω, ainB ω)))
    (betasB : Dbind → ℕ → F) (hbetasB : (fun ω => betasB (dataB ω)) = betas)
    (TB : Dbind → List (ZkLayer M F)) (hTB : (fun ω => TB (dataB ω)) = T)
    (E_preB : Dbind → Option (AugmentedWitness M F Witness))
    (hEB : (fun ω => E_preB (dataB ω)) = E_L)
    (hlenB : ∀ d, (TB d).length = nl)
    (hbindB : ∀ (d : Dbind) (a : F) (w : Witness) (pad : Pad M F),
      E_preB d = some (w, pad) → ¬ RunBindingBad LC nl (betasB d) (TB d) w pad a →
      ClaimsCorrect LC nl w (betasB d)
        (zkFinalState (logw := logw) (logc := logc) pad st0 (TB d)))
    -- the splitting at layer 0's `(beta, alpha)` pair
    (dataG : Ω → Ddeg) (pairG : Ω → F × F)
    (hbijG : Function.Bijective (fun ω => (dataG ω, pairG ω)))
    (hbetasG : (fun ω => Function.update tail 0 (pairG ω).1) = betas)
    (E_preG : Ddeg → Option (AugmentedWitness M F Witness))
    (hEG : (fun ω => E_preG (dataG ω)) = E_L)
    (hne : ∀ w : Witness, ev c inp w = false →
      ¬ (layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 0) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 0
            st0.q st0.g0 st0.g1 = 0 ∧
         layer_claim (nc := nc) (nv := nv) (LC.Quad 0 1) (LC.V 1 w tail) 1
            st0.q st0.g0 st0.g1 = 0))
    -- the run has at least one sumcheck round, and the sample space is non-empty
    (hn : 0 < n) (hFpos : 0 < Fintype.card F) (hΩpos : 0 < Fintype.card Ω) :
    (event_card (MEvent_Fail accepts ev c inp E_L) : ℚ) / Fintype.card Ω
      ≤ (eps_FSK : ℚ) / Fintype.card Ω + 3 / Fintype.card F
        + (nl : ℚ) * (1 + n * dd) / Fintype.card F := by
  classical
  -- the count, at `K = 1`
  have hcount := multi_layer_soundness_all_derived (npub := npub) LC accepts st0 tail betas T
    eqqs E_L colOf bcoef pub_binding got alpha_in ivL ivR ev c inp eps_FSK hpos hnl hzero0
    hzero1 hshape gen heqq dataα alphaα (fun i => (hbijα i).1) betasα hbetasα E_preα hEα STα
    hstateα halphaα hlenα fam stateR chalR 1
    (fun i s cs => pair_fiber_le_one _ _ (hbijR i).1 s cs) naR
    dataB ainB hbijB.1 betasB hbetasB TB hTB E_preB hEB hlenB hbindB
    dataG pairG hbijG.1 hbetasG E_preG hEG hne
  -- the four cardinality equalities the bijections pin down
  have hΩα : Fintype.card Ω = Fintype.card Dα * Fintype.card F :=
    card_of_split_bij (dataα 0) (alphaα 0) (hbijα 0)
  have hΩb : Fintype.card Ω = Fintype.card Dbind * Fintype.card F :=
    card_of_split_bij dataB ainB hbijB
  have hΩd : Fintype.card Ω = Fintype.card Ddeg * (Fintype.card F * Fintype.card F) := by
    have h := card_of_split_bij dataG pairG hbijG
    rwa [Fintype.card_prod] at h
  have hΩs : Fintype.card Ω = Fintype.card S * Fintype.card F ^ n := by
    have h := card_of_split_bij (stateR 0) (chalR 0) (hbijR 0)
    rwa [show Fintype.card (Fin n → F) = Fintype.card F ^ n by simp] at h
  exact multi_layer_prob_of_cards hΩα hΩb hΩd hΩs hn hFpos hΩpos hcount

end AllDerived
