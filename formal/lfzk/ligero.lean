import Mathlib
import sumcheck_soundness
import types
import circuit

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

/--
`ligero_layer_checks` defines the mathematical predicate representing the
linear and quadratic constraints verified by the Ligero verifier for a sumcheck layer.

Specifically, it checks that:
1. **Linear Constraint**: The dot product `∑ i, lhs[i] * pad[i] = rhs` holds for the
   `builder_finalize` linear row.
   - **Code Reference**: `ConstraintBuilder::finalize` in `privacy/proofs/zk/lib/zk/zk_common.h:L359-L377`.
2. **Quadratic Constraint**: The quadratic pad multiplication check `pad[var_dwL_dwR] = pad[var_dwL] * pad[var_dwR]` holds.
   - **Code Reference**: Quadratic constraint generation in `privacy/proofs/zk/lib/zk/ligero.cc`.
-/
def ligero_layer_checks {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
  (e_in : Expression M F) (pad : Fin M → F)
  (eqq : F) (wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) : Prop :=
  let lr := builder_finalize e_in eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR
  let lhs := lr.1
  let rhs := lr.2
  (∑ i, lhs i * pad i = rhs) ∧ (pad var_dwL_dwR = pad var_dwL * pad var_dwR)


/--
Theorem 1: If the Ligero layer constraints hold, then the unpadded sumcheck relation holds.
-/
theorem layer_checks_imply_sumcheck {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (e_in : Expression M F) (pad : Fin M → F)
    (eqq : F) (wc0 wc1 : F) (var_dwL var_dwR var_dwL_dwR : Fin M) :
    ligero_layer_checks e_in pad eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR →
    evaluates_to e_in pad = eqq * (wc0 + pad var_dwL) * (wc1 + pad var_dwR) := by
  intro h
  dsimp [ligero_layer_checks] at h
  rcases h with ⟨h_lin, h_quad⟩
  exact builder_finalize_soundness e_in pad eqq wc0 wc1 var_dwL var_dwR var_dwL_dwR h_lin h_quad


/-!
## The input binding row

This is where the extracted witness enters the constraint system.

The Ligero-committed vector is the private input wires followed by the proof pad.
`ZkCommon::input_constraint` (`zk_common.h:L406`) emits **one** row:

    ∑_{i ≥ npub} b_i · W_col_i  −  dW[L]  −  alpha · dW[R]  =  got − pub_binding

with `b_i = eq0.at(i) + alpha * eq1.at(i)` on the committed wires
(`a.push_back(Llc{ci, i - pub_inputs, b_i})`), `F.mone()` and `F.negf(alpha)` on the two
claim pads, and `got = wc[0] + alpha * wc[1]` taken from the last layer (`zk_common.h:L133`).

Previously this file modelled the binding with `ligero_input_checks`, which summed only over
*pad* variables and was instantiated twice, at `(beta, alpha) = (0,1)` and `(1,0)`.  That
was both stronger than the code (two exact constraints instead of one random combination)
and vacuous as a witness binding (the witness never appeared).  Both are fixed here.
-/

/-- The indices of the committed **private** input wires. -/
def privIdx (ninp npub : ℕ) : Finset (Fin ninp) :=
  Finset.univ.filter (fun i : Fin ninp => npub ≤ i.val)

/-- The input binding row of `ZkCommon::input_constraint`. -/
def ligero_input_row {ninp M : ℕ} {F : Type} [Field F]
    (npub : ℕ) (wcol : Fin ninp → F) (pad : Fin M → F) (b : Fin ninp → F)
    (pub_binding got alpha : F) (var_dwL var_dwR : Fin M) : Prop :=
  (∑ i ∈ privIdx ninp npub, b i * wcol i) - pad var_dwL - alpha * pad var_dwR
    = got - pub_binding

/--
The input row forces the full (public + private) weighted sum of the committed input
columns to equal the unpadded, `alpha`-combined witness claim.

The hypothesis `h_pub` is public-input consistency: the verifier's `pub_binding`, computed
from the *actual* public input at `zk_common.h:L417`, agrees with what the extracted
columns contribute on the public positions.
-/
theorem input_row_soundness {ninp M : ℕ} {F : Type} [Field F]
    (npub : ℕ) (wcol : Fin ninp → F) (pad : Fin M → F) (b : Fin ninp → F)
    (pub_binding got alpha : F) (var_dwL var_dwR : Fin M)
    (h_pub : pub_binding = ∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i) :
    ligero_input_row npub wcol pad b pub_binding got alpha var_dwL var_dwR →
    (∑ i, b i * wcol i) = got + pad var_dwL + alpha * pad var_dwR := by
  intro h
  dsimp [ligero_input_row] at h
  have hsplit : (∑ i ∈ privIdx ninp npub, b i * wcol i)
      + (∑ i ∈ Finset.univ \ privIdx ninp npub, b i * wcol i) = ∑ i, b i * wcol i :=
    Finset.sum_add_sum_compl (privIdx ninp npub) _
  rw [h_pub] at h
  linear_combination h - hsplit

/-!
### The public wires are not extracted

`ZkCommon::input_constraint` never commits the public wires.  For `i < npub` it folds
`b_i · pub.at(i)` into the constant term using the verifier's *own* `pub`
(`zk_common.h:L414-L418`); only `i ≥ npub` become Ligero columns
(`a.push_back(Llc{ci, i - pub_inputs, b_i}`).  So the extractor neither produces the public
wires nor can alter them.

`ArithmetizedCircuit.W_col` is *built* as `pub ++ priv`, so this needs no assumption at all:
`W_col_pub` is definitional and `pub_consistent_of_indep` below is unconditional.
-/

/-- The verifier's `pub_binding`, as the code computes it: the public part of the weighted
input sum, from data the verifier already has (`zk_common.h:L414-L418`). -/
noncomputable def pubBinding {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w_ref : Witness) (alpha : F) (chal : List F) : F :=
  ∑ i ∈ Finset.univ \ privIdx ninp npub,
    input_row_coeffs (logw := logw) (logc := logc) (ninp := ninp) alpha chal i
      * AC.W_col inp w_ref (challenge_split (logw := logw) (logc := logc) chal).1 i

/--
**Public-input consistency, unconditionally.**

The verifier's `pub_binding` agrees with *whatever* witness the extractor returns, because
the public half of the wire vector does not mention the witness.  This is what
`input_row_soundness` needs as `h_pub`, and it is now a theorem with no hypotheses.
-/
lemma pub_consistent_of_indep {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F}
    (inp : Input) (w_ref w : Witness) (alpha : F) (chal : List F) :
    pubBinding AC inp w_ref alpha chal
      = ∑ i ∈ Finset.univ \ privIdx ninp npub,
          input_row_coeffs (logw := logw) (logc := logc) (ninp := ninp) alpha chal i
            * AC.W_col inp w (challenge_split (logw := logw) (logc := logc) chal).1 i := by
  refine Finset.sum_congr rfl (fun i hi => ?_)
  have hpub : i.val < npub := by
    simp only [Finset.mem_sdiff, privIdx, Finset.mem_filter, Finset.mem_univ, true_and,
      not_le] at hi
    exact hi
  rw [AC.W_col_pub inp w_ref w _ i hpub]

/--
With the code's coefficients `b_i = eq(L, i) + alpha * eq(R, i)`, the weighted sum of the
committed columns *is* the `alpha`-combination of the two honest multilinear evaluations.

This is the step that converts a statement about committed wires into a statement about
`W_mle`, i.e. about the quantity the final layer identity is written in.
-/
lemma input_row_coeffs_give_mle {nc nv ninp npub logv logw logc : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (inp : Input) (w : Witness) (copy : Vector F logc) (l r : Vector F logw) (alpha : F) :
    (∑ i : Fin ninp, (eq_mle_basis i.val l + alpha * eq_mle_basis i.val r) * AC.W_col inp w copy i)
      = AC.W_mle inp w l copy + alpha * AC.W_mle inp w r copy := by
  rw [AC.W_mle_is_mle, AC.W_mle_is_mle, Finset.mul_sum, ← Finset.sum_add_distrib]
  exact Finset.sum_congr rfl (fun i _ => by ring)

/--
`Event_A` is the Ligero *extraction failure* event: the ZK verifier **accepted**
(`accepts ω`) yet the Ligero extractor produced nothing.

Conditioning on `accepts` is essential.  Without it the event also contains every
run in which the prover simply sent garbage and was rejected — bounding *that* set
is not knowledge soundness, and no real extractor satisfies it.
-/
noncomputable def Event_A {M : ℕ} {F : Type} [Field F] (accepts : Ω → Prop) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ E_L ω = none) Finset.univ


/--
**Assumption bundle: Ligero Knowledge Soundness**

This structure models knowledge soundness.
It guarantees that if the Ligero extractor successfully outputs a witness and a pad (`w, p`),
the extracted witness columns and pad are guaranteed to satisfy the constraints that were
fed into the Ligero verifier: the `builder_finalize` row and quadratic pad relation
(`ligero_layer_checks`) and the input binding row (`ligero_input_row`).

This is packaged as a *hypothesis* of the theorems that need it,
with `eps_FSK` fixed, every clause conditioned on the verifier having accepted,
and every clause instantiated at the **actual** transcript `T_p ω` and the
**actual** pad indices rather than universally quantified.  `example.lean`
exhibits an inhabitant, so the bundle is consistent.

Fields:
* `extraction_bound` — knowledge soundness of Ligero (`ZkVerifier::verify`,
  `zk_verifier.h`), treated as an ideal primitive.
* `layer_constraint` — the extracted pad satisfies the linear row emitted by
  `ConstraintBuilder::finalize` (`zk_common.h:L373`) together with the quadratic
  pad relation registered by `setup_lqc` (`zk_common.h:L149`).
* `input_row` — the extracted **witness columns and pad** satisfy the single input
  binding row of `ZkCommon::input_constraint` (`zk_common.h:L406`).

### Three challenges, not two

`alpha` and `beta` are the *layer* challenges, drawn together by `begin_layer` before any of
the layer's messages (`transcript.rs:L106`, `zk_common.h:L80`).  `alpha_in` is a **separate,
fresh** challenge drawn after every layer has closed —
`let alpha = transcript.elt_field(f)` in `symbolic_sumcheck_verifier_core`
(`symbolic_sumcheck_verifier.rs:L247`, `zk_common.h:L129`) — and it is the one the input row
uses, in all four places: the coefficients `b_i = eq0_i + alpha_in * eq1_i`, the `pub_binding`
constant folded from the verifier's own public input, the combined claim
`got = wc0 + alpha_in * wc1`, and the coefficient of the second claim pad.

Keeping `alpha` and `alpha_in` distinct is what keeps the model faithful: one shared draw
would let the layer relation and the input binding fail together, which is not something a
prover can arrange.

The public wires are never committed, so the extractor cannot touch them.  `pub_binding` is
*defined* as `pubBinding`, and the agreement with the extracted columns is the unconditional
theorem `pub_consistent_of_indep`.

None of the three challenges is assumed lucky: `eps_bind` (the `alpha_in` collision) and
`eps_deg` (the layer pair collapsing the claim) are counted error terms in
`core_soundness_theorem`, worth `1/|F|` and `2/|F|`.

The bundle used to carry a sixth field, `accepted_sumcheck`, asserting that on an accepted
run the sumcheck rounds close on the decrypted expression `e(pad)`.  That was the whole
link between the Ligero constraint system and the sumcheck.  It is now the theorem
`EncTranscript.rounds_verify` (`builder.lean`), proved from the model of
`ConstraintBuilder::first`/`next`: the ZK verifier *substitutes* `p(1) = claim - p(0)`
rather than checking it, so every round check passes by construction.
-/
structure IsLigeroKnowledgeSound {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop)
    (T_p : Ω → EncTranscript M F)
    (c : Circuit) (inp : Input) (w_ref : Witness)
    (alpha beta alpha_in : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (eps_FSK : ℕ) : Prop where
  extraction_bound :
    event_card (Event_A accepts E_L) ≤ eps_FSK
  layer_constraint : ∀ (ω : Ω) (w : Witness) (p : Pad M F),
    accepts ω → E_L ω = some (w, p) →
    ligero_layer_checks (T_p ω).e p
      (layer_eqq AC c (alpha ω) (beta ω) q_challenge g0 g1 (T_p ω).challenges)
      (T_p ω).wc0 (T_p ω).wc1 var_dwL var_dwR var_dwL_dwR
  input_row : ∀ (ω : Ω) (w : Witness) (p : Pad M F),
    accepts ω → E_L ω = some (w, p) →
    ligero_input_row npub
      (AC.W_col inp w (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).1) p
      (input_row_coeffs (logw := logw) (logc := logc) (ninp := ninp) (alpha_in ω) (T_p ω).challenges)
      (pubBinding AC inp w_ref (alpha_in ω) (T_p ω).challenges)
      ((T_p ω).wc0 + alpha_in ω * (T_p ω).wc1) (alpha_in ω) var_dwL var_dwR


/--
**The witness binding, derived.**

From the input row (plus public-input consistency and a non-degenerate `alpha_in`), the
prover's *claimed* hand evaluations `W_hat + dW` equal the *honest* multilinear evaluations
of the extracted witness at the transcript's own hand challenge points.

The separating challenge is `alpha_in`, the fresh one drawn after all layers, not the layer's
own `alpha`.  This is what makes the `1/|F|` bound on `Event_AlphaBad` legitimate: at the
moment `alpha_in` is drawn, the transcript and the committed witness are already fixed, so the
two quantities it has to separate are constants and at most one draw is bad.

This is the fact that used to be assumed as `IsBoundTranscript.final_binding`.
-/
theorem input_row_binds_hands {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} {inp : Input} {w_ref : Witness}
    {alpha beta alpha_in : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (lig : IsLigeroKnowledgeSound AC accepts T_p c inp w_ref alpha beta alpha_in q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK)
    (ω : Ω) (w : Witness) (p : Pad M F) (hacc : accepts ω) (hE : E_L ω = some (w, p))
    (hab : ¬ InputBindingBad (true_evals AC inp w (T_p ω).challenges).1
        (true_evals AC inp w (T_p ω).challenges).2
        ((T_p ω).wc0 + p var_dwL) ((T_p ω).wc1 + p var_dwR) (alpha_in ω)) :
    (true_evals AC inp w (T_p ω).challenges).1 = (T_p ω).wc0 + p var_dwL ∧
    (true_evals AC inp w (T_p ω).challenges).2 = (T_p ω).wc1 + p var_dwR := by
  -- the row forces the full weighted column sum
  have h_sum := input_row_soundness npub
      (AC.W_col inp w (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).1) p
      (input_row_coeffs (logw := logw) (logc := logc) (ninp := ninp) (alpha_in ω) (T_p ω).challenges)
      (pubBinding AC inp w_ref (alpha_in ω) (T_p ω).challenges)
      ((T_p ω).wc0 + alpha_in ω * (T_p ω).wc1) (alpha_in ω) var_dwL var_dwR
      (pub_consistent_of_indep inp w_ref w _ _) (lig.input_row ω w p hacc hE)
  -- and the weighted column sum is the alpha_in-combination of the honest MLE evaluations
  have h_mle := input_row_coeffs_give_mle AC inp w
      (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).1
      (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).2.1
      (challenge_split (logw := logw) (logc := logc) (T_p ω).challenges).2.2 (alpha_in ω)
  simp only [input_row_coeffs] at h_sum
  rw [h_mle] at h_sum
  -- separate the two hands
  refine alpha_separates _ _ _ _ (alpha_in ω) hab ?_
  show AC.W_mle inp w _ _ + alpha_in ω * AC.W_mle inp w _ _ = _
  linear_combination h_sum
