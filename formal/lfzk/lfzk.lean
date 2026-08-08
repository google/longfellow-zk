import Mathlib
import sumcheck_soundness
import types
import fiat_shamir
import circuit
import ligero
import fs_derive

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

/-!
This file contains the main Longfellow ZK soundness theorem corresponding
to Theorem 6, Protocol 2.5 in the "Anonymous credentials from ECDSA" paper.
The main argument follows the paper proof.
-/


/-!
## The decrypted transcript of a run

`decrypt` needs the *honest* hand evaluations of the extracted witness; `true_evals`
supplies them, and `layer_eqq` supplies the `EQQ` scalar the verifier recomputes.  Both are
functions of the transcript's own challenges, so both are named once here.
-/

/-- The plaintext transcript of run `ω` under extracted witness `w` and pad `pad`. -/
noncomputable def run_transcript {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (ω : Ω) (w : Witness) (pad : Pad M F) : Transcript F :=
  (T_p ω).decrypt pad var_dwR var_dwL
    (true_evals AC w (T_p ω).challenges).1 (true_evals AC w (T_p ω).challenges).2

/-- The `EQQ` scalar of run `ω`. -/
noncomputable def run_eqq {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (T_p : Ω → EncTranscript M F) (ω : Ω) : F :=
  layer_eqq AC c (alpha ω) q_challenge g0 g1 (T_p ω).challenges


/--
`Event_B` describes the event where the verifier accepted, the extractor `E_L`
successfully extracts a witness and pad, but the decrypted transcript fails the
validity check `checkV`.
-/
noncomputable def Event_B {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    (run_transcript AC T_p var_dwR var_dwL ω w pad).checkV
      (run_eqq AC c alpha q_challenge g0 g1 T_p ω) = false) Finset.univ


/--
`Event_C` describes the event where the verifier accepted, the extractor `E_L` extracts a witness
and pad, the decrypted transcript passes the validity check `checkV`, but the circuit
evaluation for the extracted witness evaluates to false.

The "sumcheck rounds verify" conjunct that used to be here is gone: it is now automatic
(`EncTranscript.rounds_verify`), so including it would only have made the event smaller.
-/
noncomputable def Event_C {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ AC.Degenerate c w (alpha ω) q_challenge g0 g1 ∧
    (run_transcript AC T_p var_dwR var_dwL ω w pad).checkV
      (run_eqq AC c alpha q_challenge g0 g1 T_p ω) = true ∧ AC.eval c inp w = false) Finset.univ


/--
**Assumption bundle: the shape of an accepted transcript**

`ArithmetizedCircuit.soundness` is stated conditionally (see `circuit.lean`), so a caller
must supply the round counts the verifier enforces: it reads exactly `logc + 2 * logw`
round polynomials and challenges per layer (`verifier_layers.h:L102` and `L119`).

This bundle used to carry a third field, `final_binding`, asserting that the verifier's
final identity `CLAIM = EQQ * W[R,C] * W[L,C]` pins the last claim to the honest layer
polynomial.  That was the place where the extracted witness was smuggled into the argument.
It is now a *theorem* (`final_binding` below), derived from the Ligero input row via
`input_row_binds_hands`.
-/
structure IsWellFormedTranscript {logw logc : ℕ} {M : ℕ} {F : Type} [Field F]
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) : Prop where
  round_count : ∀ ω : Ω, accepts ω → (T_p ω).rounds.length = logc + 2 * logw


omit [Fintype Ω] in
/--
**The final binding, derived.**

`EQQ * W[R,C] * W[L,C]` — the quantity the verifier's last layer identity pins the final
claim to — equals the honest layer polynomial evaluated at the transcript's own challenge
point.  With `run_eqq` being the verifier's own `EQQ` and the transcript's `w_l_true` /
`w_r_true` being the honest evaluations, this is pure commutativity on top of
`layer_poly_factors`.

The content that used to be assumed here now lives in `input_row_binds_hands`, which proves
that the prover's *claimed* evaluations equal these honest ones.
-/
lemma final_binding {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (ω : Ω) (w : Witness) (pad : Pad M F) :
    run_eqq AC c alpha q_challenge g0 g1 T_p ω
        * (run_transcript AC T_p var_dwR var_dwL ω w pad).w_r_true
        * (run_transcript AC T_p var_dwR var_dwL ω w pad).w_l_true
      = layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w)
          (alpha ω) q_challenge g0 g1
          (Vector.ofFn (n := logc + 2 * logw) fun i =>
            (run_transcript AC T_p var_dwR var_dwL ω w pad).challenges.getD i.val 0) := by
  have hch : (run_transcript AC T_p var_dwR var_dwL ω w pad).challenges = (T_p ω).challenges := rfl
  rw [hch, layer_poly_factors, run_eqq]
  show layer_eqq AC c (alpha ω) q_challenge g0 g1 (T_p ω).challenges
        * (true_evals AC w (T_p ω).challenges).2 * (true_evals AC w (T_p ω).challenges).1 = _
  ring


/--
**Lemma: Sumcheck Protocol Soundness**
Proves that `P(Event_C) ≤ eps_sumcheck` by reducing `Event_C` to `multi_round_bad_event`
using `sumcheck_multi_reduction`.

This lemma serves as the bridge between abstract sumcheck bounds and the specific
Longfellow protocol. It bounds the protocol-specific `Event_C` by instantiating the
generic `multi_round_bad_event` with Longfellow's specific arithmetized quadratic
form polynomials (`circuit_true_polys`).
-/
lemma lemma_sumcheck_soundness (eps_sumcheck : ℕ) {nc nv ninp logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (hpos : 0 < logc + 2 * logw)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_p)
    (ci : IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c E_L alpha q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_C AC accepts c inp alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L) ≤ eps_sumcheck := by
  have h_subset : Event_C AC accepts c inp alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L ⊆
    Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      multi_round_bad_event (circuit_true_polys AC c w (run_transcript AC T_p var_dwR var_dwL ω w pad) (alpha ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ := by
    intro ω h_omega
    dsimp [Event_C] at h_omega ⊢
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at h_omega ⊢
    rcases h_omega with ⟨h_acc, w, pad, h_EL, hgood, h_check, h_ev⟩
    have h_ver := (T_p ω).rounds_verify pad
    refine ⟨h_acc, w, pad, h_EL, ?_⟩
    set eqq := run_eqq AC c alpha q_challenge g0 g1 T_p ω with h_eqq_def
    set t := run_transcript AC T_p var_dwR var_dwL ω w pad with h_t_def
    have h_shape1 : t.polys.length = logc + 2 * logw := by
      simpa [t, run_transcript, EncTranscript.decrypt] using wf.round_count ω h_acc
    have h_shape2 : t.challenges.length = logc + 2 * logw := by
      simpa [t, run_transcript, EncTranscript.decrypt] using wf.round_count ω h_acc
    have h_target : eqq * t.w_r_true * t.w_l_true =
        layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c) (AC.W_mle w)
          (alpha ω) q_challenge g0 g1
          (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) :=
      final_binding AC c alpha q_challenge g0 g1 T_p var_dwR var_dwL ω w pad
    have h_circ := AC.soundness c inp w t (alpha ω) q_challenge g0 g1
      (eqq * t.w_r_true * t.w_l_true) h_ev hgood hpos h_shape1 h_shape2 h_target
    rcases h_circ with ⟨P_first, P_rest, h_eq, h_len1, h_len2, h_cons, h_neq, h_last⟩
    have h_polys_nnil : (T_p ω).polys pad ≠ [] := by
      intro h_nil
      have h_len_zero : ((T_p ω).polys pad).length = 0 := by rw [h_nil, List.length_nil]
      dsimp [t, run_transcript, EncTranscript.decrypt] at h_len1
      rw [h_len_zero] at h_len1
      contradiction

    have h_check_true : t.claim_last = eqq * t.w_r_eval * t.w_l_eval ∧ t.w_r_eval = t.w_r_true ∧ t.w_l_eval = t.w_l_true := by
      dsimp [Transcript.checkV] at h_check
      rw [Bool.and_eq_true, Bool.and_eq_true] at h_check
      rcases h_check with ⟨⟨h1, h2⟩, h3⟩
      exact ⟨beq_iff_eq.mp h1, beq_iff_eq.mp h2, beq_iff_eq.mp h3⟩

    rcases h_check_true with ⟨h_last_eq, h_r_eq, h_l_eq⟩
    have h_target_eq : eqq * t.w_r_true * t.w_l_true = t.claim_last := by
      rw [←h_r_eq, ←h_l_eq]
      exact h_last_eq.symm

    rw [h_target_eq] at h_last
    have h_claim_last_def : t.claim_last = evaluates_to (T_p ω).e pad := rfl
    rw [h_claim_last_def] at h_last

    have h_reduce := sumcheck_multi_reduction (P_first :: P_rest) ((T_p ω).polys pad) (T_p ω).challenges 0 (evaluates_to (T_p ω).e pad)

    have h_reduce_apply := h_reduce h_ver h_len1 h_len2 h_cons h_polys_nnil
    have h_head : (P_first :: P_rest).head! = P_first := rfl
    rw [h_head] at h_reduce_apply
    have h_reduce_final := h_reduce_apply h_neq

    cases h_reduce_final with
    | inl h_false =>
      exfalso
      apply h_false h_last
    | inr h_true =>
      dsimp [circuit_true_polys]
      rw [h_eq]
      exact h_true

  have h_mono : event_card (Event_C AC accepts c inp alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L) ≤ event_card (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧ multi_round_bad_event (circuit_true_polys AC c w (run_transcript AC T_p var_dwR var_dwL ω w pad) (alpha ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ) := by
    apply Finset.card_le_card
    exact h_subset
  have h_prob := ci.ci_bound
  exact le_trans h_mono h_prob

noncomputable def E_prime {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (c : Circuit) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) : Option Witness :=
  match E_L ω with
  | none => none
  | some (w, pad) =>
    if (run_transcript AC T_p var_dwR var_dwL ω w pad).checkV
        (run_eqq AC c alpha q_challenge g0 g1 T_p ω) then some w else none


/--
`Event_Fail` is the knowledge-soundness failure event: the ZK verifier **accepted**
and yet the combined extractor `E_prime` either produced nothing or produced a
witness that does not satisfy the circuit.

The `accepts ω` conjunct is what makes this the right event to bound.  Runs the
verifier rejects carry no soundness obligation.
-/
noncomputable def Event_Fail {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧
    (E_prime AC c alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L ω = none ∨
     ∃ w, E_prime AC c alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L ω = some w ∧ AC.eval c inp w = false)) Finset.univ


omit [Fintype Ω] in
lemma union_bound_3 (A B C : Finset Ω) :
    event_card (A ∪ B ∪ C) ≤ event_card A + event_card B + event_card C := by
  dsimp [event_card]
  linarith [Finset.card_union_le (A ∪ B) C, Finset.card_union_le A B]

omit [Fintype Ω] in
lemma union_bound_4 (A B C D : Finset Ω) :
    event_card (A ∪ B ∪ C ∪ D) ≤ event_card A + event_card B + event_card C + event_card D := by
  dsimp [event_card]
  linarith [Finset.card_union_le (A ∪ B ∪ C) D, Finset.card_union_le (A ∪ B) C,
            Finset.card_union_le A B]


/--
**Lemma: Constraint to Sumcheck Bridge**

If the extracted pad satisfies the `builder_finalize` row and the quadratic pad relation,
and the extracted *witness columns* satisfy the input binding row, then the decrypted
transcript passes `Transcript.checkV`.

The two hand-binding conjuncts of `checkV` are now discharged by `input_row_binds_hands`
rather than by two hand-specific pad constraints — that is, they follow from the single
input row of `ZkCommon::input_constraint` acting on the committed witness columns.
-/
lemma extractor_soundness_bridge {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} {npub : ℕ} {pub_binding : Ω → F}
    {alpha : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (lig : IsLigeroKnowledgeSound AC accepts T_p c npub pub_binding alpha q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK)
    (ω : Ω) (w : Witness) (p : Pad M F) (hacc : accepts ω) (hE : E_L ω = some (w, p))
    (hab : ¬ InputBindingBad (true_evals AC w (T_p ω).challenges).1
        (true_evals AC w (T_p ω).challenges).2
        ((T_p ω).wc0 + p var_dwL) ((T_p ω).wc1 + p var_dwR) (alpha ω)) :
    (run_transcript AC T_p var_dwR var_dwL ω w p).checkV
      (run_eqq AC c alpha q_challenge g0 g1 T_p ω) = true := by
  obtain ⟨hL, hR⟩ := input_row_binds_hands lig ω w p hacc hE hab
  have hclaim := layer_checks_imply_sumcheck (T_p ω).e p
      (run_eqq AC c alpha q_challenge g0 g1 T_p ω) (T_p ω).wc0 (T_p ω).wc1
      var_dwL var_dwR var_dwL_dwR (lig.layer_constraint ω w p hacc hE)
  dsimp [run_transcript, Transcript.checkV, EncTranscript.decrypt]
  rw [hL, hR]
  have : evaluates_to (T_p ω).e p
      = run_eqq AC c alpha q_challenge g0 g1 T_p ω * ((T_p ω).wc1 + p var_dwR)
          * ((T_p ω).wc0 + p var_dwL) := by
    rw [hclaim]; ring
  simp
  exact this


/--
**The degenerate-randomness event.**

The run's combination coefficient `alpha` collapses a non-zero output claim vector to zero
(`ArithmetizedCircuit.Degenerate`).  On such a run the sumcheck starts from a claim that is
*true*, so nothing can be concluded — this is the price of the `claim[0] + alpha * claim[1]`
combination at `verifier_layers.h:L147`.

This used to be the hypothesis `hgood : ¬ AC.degenerate ...` on the theorem's parameters.
Now that `alpha` is a function of the run it is an event, and `alpha_bad_card` bounds it by
a `1/|F|` fraction.
-/
noncomputable def Event_Degenerate {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (alpha : Ω → F)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    AC.Degenerate c w (alpha ω) q_challenge g0 g1) Finset.univ

/--
**The input-binding error event.**

`Event_B` — the verifier accepted and the extractor succeeded, yet `checkV` fails — is
contained in the event that the layer's random combination coefficient `alpha` is the one
unlucky value that lets a mismatch through.

This used to be `event_b_empty`, proved from an `alpha_good` field asserting that the
unlucky value never occurs.  It is now a *counted* term: `alpha_bad_card` (`ligero.lean`)
shows that when `alpha` is a fresh challenge at most a `1/|F|` fraction of runs land here.
-/
noncomputable def Event_AlphaBad {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (alpha : Ω → F) (var_dwR var_dwL : Fin M)
    (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    InputBindingBad (true_evals AC w (T_p ω).challenges).1
      (true_evals AC w (T_p ω).challenges).2
      ((T_p ω).wc0 + pad var_dwL) ((T_p ω).wc1 + pad var_dwR) (alpha ω)) Finset.univ

lemma event_b_subset {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} {npub : ℕ} {pub_binding : Ω → F}
    {alpha : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (lig : IsLigeroKnowledgeSound AC accepts T_p c npub pub_binding alpha q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK) :
    Event_B AC accepts c alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L
      ⊆ Event_AlphaBad AC accepts alpha var_dwR var_dwL T_p E_L := by
  intro ω hω
  dsimp [Event_B, Event_AlphaBad] at hω ⊢
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
  obtain ⟨h_acc, w, pad, h_lig, h_check⟩ := hω
  refine ⟨h_acc, w, pad, h_lig, ?_⟩
  by_contra hab
  have h_corr := extractor_soundness_bridge lig ω w pad h_acc h_lig hab
  rw [h_check] at h_corr
  contradiction

/--
`event_fail_subset` proves that the overall extractor failure event `Event_Fail` is a subset of
the union of the three atomic failure events: `Event_A ∪ Event_B ∪ Event_C`.

Case analysis:
- If `E_L ω = none`: Belongs to `Event_A` (Ligero extraction failure).
- If `E_L ω = some (w, pad)` and `Transcript.checkV = false`: Belongs to `Event_B`.
- If `E_L ω = some (w, pad)` and `Transcript.checkV = true` with `eval = false`: `Event_C`.
-/
lemma event_fail_subset {nc nv ninp logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} (inp : Input) {npub : ℕ} {pub_binding : Ω → F}
    {alpha : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (_lig : IsLigeroKnowledgeSound AC accepts T_p c npub pub_binding alpha q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK) :
    Event_Fail AC accepts c inp alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L
      ⊆ Event_A accepts E_L
        ∪ Event_B AC accepts c alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L
        ∪ Event_Degenerate AC accepts c alpha q_challenge g0 g1 E_L
        ∪ Event_C AC accepts c inp alpha q_challenge g0 g1 var_dwR var_dwL T_p E_L := by
  intro ω h
  dsimp [Event_Fail, Event_A, Event_B, Event_Degenerate, Event_C] at h ⊢
  simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at h ⊢
  obtain ⟨h_acc, h⟩ := h
  cases h with
  | inl h1 =>
    dsimp [E_prime] at h1
    cases h_lig : E_L ω with
    | none =>
      left; left; left
      exact ⟨h_acc, rfl⟩
    | some w_prime =>
      rcases w_prime with ⟨w, pad⟩
      rw [h_lig] at h1
      cases h_check : (run_transcript AC T_p var_dwR var_dwL ω w pad).checkV
          (run_eqq AC c alpha q_challenge g0 g1 T_p ω)
      · left; left; right
        exact ⟨h_acc, w, pad, rfl, h_check⟩
      · simp only [h_check] at h1
        contradiction
  | inr h2 =>
    rcases h2 with ⟨w, hw1, hw2⟩
    dsimp [E_prime] at hw1
    cases h_lig : E_L ω with
    | none =>
      rw [h_lig] at hw1
      contradiction
    | some w_prime =>
      rcases w_prime with ⟨w', pad⟩
      rw [h_lig] at hw1
      cases h_check : (run_transcript AC T_p var_dwR var_dwL ω w' pad).checkV
          (run_eqq AC c alpha q_challenge g0 g1 T_p ω)
      · simp only [h_check] at hw1
        contradiction
      · simp only [h_check] at hw1
        injection hw1 with heq
        subst heq
        by_cases hdeg : AC.Degenerate c w' (alpha ω) q_challenge g0 g1
        · left; right
          exact ⟨h_acc, w', pad, rfl, hdeg⟩
        · right
          exact ⟨h_acc, w', pad, rfl, hdeg, h_check, hw2⟩


/--
**Core Soundness Theorem for Longfellow Zero-Knowledge (LFZK)**

This is the main theorem of the formalization.  Read precisely, it says:

> for **one sumcheck layer**, on the runs where the ZK verifier **accepts**, the number
> of runs on which the combined extractor `E_prime` fails to output a satisfying witness
> is at most `eps_FSK + eps_bind + eps_deg + eps_sumcheck`.

It is a *reduction*, not a self-contained knowledge-soundness proof: the four error terms
are supplied by the caller.  `core_soundness_derived_eps` fills in the last of them.

Rather than reasoning about real-valued probabilities, this formalization counts "bad"
outcomes in a finite sample space `Ω`; all bounds are set cardinalities (`event_card`),
not probability measures.  The counts are **absolute** and never normalised by
`Fintype.card Ω`, so the sum is only meaningful relative to `|Ω|`.  (The counting bounds in
`sumcheck_soundness.lean` *are* normalised: `n * d * |F|^(n-1)` out of `|F|^n`.)

### High-Level Proof Structure

1. **Event Partitioning (`event_fail_subset`)**:
   `Event_Fail` — the verifier accepted, yet `E_prime` returned nothing or returned a
   witness with `eval = false` — is a subset of
   `Event_A ∪ Event_B ∪ Event_Degenerate ∪ Event_C`.  Every one of these carries the
   `accepts ω` conjunct; conditioning on acceptance is what makes this the right statement,
   since a rejected run carries no soundness obligation.

2. **Union Bound (`union_bound_4`)**.

3. **Bounding Individual Error Terms**:
   - `|Event_A| ≤ eps_FSK`: assumed, via `IsLigeroKnowledgeSound.extraction_bound`.
     Ligero is treated as an ideal primitive; its Reed–Solomon internals are not modelled.
     This is the one irreducibly cryptographic assumption.
   - `|Event_B| ≤ eps_bind`: **reduced** (`event_b_subset`).  `extractor_soundness_bridge`
     shows that a pad satisfying the `builder_finalize` row plus the quadratic pad relation,
     and witness columns satisfying the input row of `ZkCommon::input_constraint`, force
     `Transcript.checkV = true` — *unless* the run hits the single `alpha` that lets the
     combined row hide a mismatch.  So `Event_B` sits inside `Event_AlphaBad`, which
     `alpha_bad_card` bounds by a `1/|F|` fraction.
   - `|Event_Degenerate| ≤ eps_deg`: the `alpha` of `claim[0] + alpha * claim[1]`
     (`verifier_layers.h:L147`) collapsing a non-zero output claim vector.  `layer_claim_affine`
     shows the honest claim is affine in `alpha`, so again at most one value is bad.
   - `|Event_C| ≤ eps_sumcheck`: `lemma_sumcheck_soundness` reduces `Event_C` to
     `multi_round_bad_event` via `sumcheck_multi_reduction` (proved), and then takes the
     count from `IsSumcheckCorrelationIntractable.ci_bound` — which
     `sumcheck_ci_of_nonadaptive` derives as `K * (n * d * |F|^(n-1))`.

4. **Final Bound**: `|Event_Fail| ≤ eps_FSK + eps_bind + eps_deg + eps_sumcheck`.

### What is assumed

`IsLigeroKnowledgeSound` (Ligero as an ideal primitive, plus what its extractor returns and
public-input consistency), `ArithmetizedCircuit.arith` (an unsatisfied circuit has a
non-zero output claim vector — note this no longer mentions the layer randomness),
`ArithmetizedCircuit.W_mle_is_mle` (definitional), `IsWellFormedTranscript.round_count`, and
the four error bounds.  There is **no** non-degeneracy hypothesis: both randomness
conditions are events, not side conditions.

### Non-vacuity

`example.lean` constructs a concrete instance over `ZMod 5` — one round, `eval` identically
`false` — discharging every hypothesis, and shows there that `Event_Fail` is in fact
non-empty and the bound is doing work.  Without such a witness this theorem would say
nothing; an earlier version was vacuous on exactly this point.

### What this theorem does *not* establish

* **A single layer.**  `verifier_layers.h::layers` runs `nl` layers.  `layers.lean` proves
  the layer-to-layer reduction and the induction over all of them, but this theorem still
  joins the Ligero pad machinery to *one* layer's sumcheck.
* **Instantiated error terms.**  `eps_FSK`, `eps_bind` and `eps_deg` are parameters; nothing
  here exhibits an `Ω` for which `alpha_bad_card` discharges the last two.
* **Zero-knowledge.**  Only soundness is addressed; the pad is a vector the extractor
  produces, not a distribution.
* **Copy rounds.**  `RoundPoly` matches `WPoly = Poly<3, Field>` (degree 2), which is what
  the ZK path uses.  The non-ZK `VerifierLayers::layer_c` uses `CPoly = Poly<4, Field>`.
* **Challenge ordering.**  `extract_vars` treats the two hands as contiguous blocks, while
  the implementation interleaves them (`for (round) for (hand)`).
-/
theorem core_soundness_theorem {nc nv ninp logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq (Fin M)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (accepts : Ω → Prop) (C : Circuit) (x : Input) (npub : ℕ) (pub_binding : Ω → F)
    (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_prime : Ω → EncTranscript M F) (E_Ligero : Ω → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw)
    (lig : IsLigeroKnowledgeSound AC accepts T_prime C npub pub_binding alpha q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_Ligero eps_FSK)
    (eps_bind eps_deg : ℕ)
    (h_bind : event_card (Event_AlphaBad AC accepts alpha var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind)
    (h_deg : event_card (Event_Degenerate AC accepts C alpha q_challenge g0 g1 E_Ligero) ≤ eps_deg)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_prime)
    (ci : IsSumcheckCorrelationIntractable AC accepts T_prime var_dwR var_dwL C E_Ligero alpha q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_Fail AC accepts C x alpha q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
      ≤ eps_FSK + eps_bind + eps_deg + eps_sumcheck := by
  have h_sub := Finset.card_le_card (event_fail_subset x lig)
  have h_ub := union_bound_4 (Event_A accepts E_Ligero)
    (Event_B AC accepts C alpha q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
    (Event_Degenerate AC accepts C alpha q_challenge g0 g1 E_Ligero)
    (Event_C AC accepts C x alpha q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
  have h_a := lig.extraction_bound
  have h_b : event_card (Event_B AC accepts C alpha q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind :=
    le_trans (Finset.card_le_card (event_b_subset lig)) h_bind
  have h_c := lemma_sumcheck_soundness eps_sumcheck AC accepts var_dwR var_dwL C x T_prime
    E_Ligero alpha q_challenge g0 g1 hpos wf ci
  have h_d := h_deg
  dsimp [event_card] at *
  linarith


/--
**Core soundness with `eps_sumcheck` derived.**

Same statement as `core_soundness_theorem`, except the sumcheck error term is no longer a
hypothesis: it is `K * (n * d * |F|^(n-1))`, produced by `sumcheck_ci_of_nonadaptive` from

* `combinatorial_fiat_shamir` — a root count, no random oracle and no probability space;
* `IsNonAdaptiveRun` — the structural Fiat–Shamir property that round `i`'s polynomial is
  fixed before challenge `i` is drawn from it;
* `K` — how many runs the hash can send to a single challenge sequence.

Out of the `|F|^n` challenge sequences, `n * d * |F|^(n-1)` is a `n * d / |F|` fraction:
the textbook sumcheck soundness error, here as an exact count.
-/
theorem core_soundness_derived_eps {nc nv ninp logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq (Fin M)] [DecidableEq F] [SumcheckInterp F]
    {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp logv logw logc F)
    (fs : IsFiatShamirTranscript F n d)
    (accepts : Ω → Prop) (C : Circuit) (x : Input) (npub : ℕ) (pub_binding : Ω → F)
    (alpha : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_prime : Ω → EncTranscript M F) (E_Ligero : Ω → Option (AugmentedWitness M F Witness))
    (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ cs : Fin n → F, (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC fs accepts T_prime var_dwR var_dwL C E_Ligero alpha q_challenge g0 g1 challenge_map)
    (hpos : 0 < logc + 2 * logw)
    (lig : IsLigeroKnowledgeSound AC accepts T_prime C npub pub_binding alpha q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_Ligero eps_FSK)
    (eps_bind eps_deg : ℕ)
    (h_bind : event_card (Event_AlphaBad AC accepts alpha var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind)
    (h_deg : event_card (Event_Degenerate AC accepts C alpha q_challenge g0 g1 E_Ligero) ≤ eps_deg)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_prime) :
    event_card (Event_Fail AC accepts C x alpha q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
      ≤ eps_FSK + eps_bind + eps_deg + K * (n * d * (Fintype.card F) ^ (n - 1)) :=
  core_soundness_theorem (eps_FSK := eps_FSK)
    (eps_sumcheck := K * (n * d * (Fintype.card F) ^ (n - 1)))
    AC accepts C x npub pub_binding alpha q_challenge g0 g1
    var_dwR var_dwL var_dwL_dwR T_prime E_Ligero hpos lig eps_bind eps_deg h_bind h_deg wf
    (sumcheck_ci_of_nonadaptive AC fs accepts T_prime var_dwR var_dwL C E_Ligero
      alpha q_challenge g0 g1 challenge_map K h_unif na)
