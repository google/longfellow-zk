import Mathlib
import sumcheck_soundness
import types
import fiat_shamir
import circuit
import ligero

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

variable {F : Type} [Field F] [Fintype F]
variable {Circuit Input Witness : Type}
variable {Ω : Type} [Fintype Ω]
variable (eps_FSK eps_sumcheck : ℕ)

/-!
# The core soundness theorem

Theorem 6 / Protocol 2.5 of "Anonymous credentials from ECDSA", for one sumcheck layer.
`core_soundness_theorem` at the bottom is the statement; everything above it is the event
decomposition it rests on.  `zk_soundness.lean` carries the same events through a
multi-layer run.
-/


/-!
## The decrypted transcript of a run

`decrypt` needs the *honest* hand evaluations of the extracted witness; `true_evals`
supplies them, and `layer_eqq` supplies the `EQQ` scalar the verifier recomputes.  Both are
functions of the transcript's own challenges, so both are named once here.
-/

/-- The plaintext transcript of run `ω` under extracted witness `w` and pad `pad`. -/
noncomputable def run_transcript {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (ω : Ω) (inp : Input) (w : Witness) (pad : Pad M F) : Transcript F :=
  (T_p ω).decrypt pad var_dwR var_dwL
    (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2

/-- The `EQQ` scalar of run `ω`. -/
noncomputable def run_eqq {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (_inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (T_p : Ω → EncTranscript M F) (ω : Ω) : F :=
  layer_eqq AC c (alpha ω) (beta ω) q_challenge g0 g1 (T_p ω).challenges


/--
`Event_B` describes the event where the verifier accepted, the extractor `E_L`
successfully extracts a witness and pad, but the decrypted transcript fails the
validity check `checkV`.
-/
noncomputable def Event_B {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    (run_transcript AC T_p var_dwR var_dwL ω inp w pad).checkV
      (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω) = false) Finset.univ


/--
`Event_C` is the sumcheck failure: the verifier accepted, the extractor produced a witness
and pad, the decrypted transcript passes `checkV`, the layer randomness is *not* degenerate,
and yet the extracted witness fails the circuit.  With the randomness good and the final
identity pinned, the only way out is a lucky sumcheck round — which is what
`lemma_sumcheck_soundness` shows.

There is no "the sumcheck rounds verify" conjunct: that is automatic
(`EncTranscript.rounds_verify`), because the ZK path *substitutes* `p(1) = claim − p(0)`
rather than checking it.
-/
noncomputable def Event_C {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    ¬ AC.Degenerate c inp w (alpha ω) (beta ω) q_challenge g0 g1 ∧
    (run_transcript AC T_p var_dwR var_dwL ω inp w pad).checkV
      (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω) = true ∧ AC.eval c inp w = false) Finset.univ


/--
**What `accepts` means: the shape of an accepted transcript.**

`accepts` is an abstract predicate standing for "the ZK verifier accepted", so any property
of the verifier the proof uses has to be stated about it.  There is one: an accepted run's
transcript has exactly `logc + 2 * logw` rounds.

This is a *description of the verifier*, not a hypothesis about the adversary.  The loop
bound is `clr->logw`, read from `Circuit<Field>` (`verifier_layers.h:L102` and `L119`) — a
public circuit parameter, so a prover cannot vary it, and a proof carrying a different
number of rounds does not parse.
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

This is only about the *honest* evaluations.  That the prover's **claimed** evaluations
equal them is the separate and harder `input_row_binds_hands` (`ligero.lean`), which is what
makes the extracted witness enter the argument at all.
-/
lemma final_binding {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (ω : Ω) (w : Witness) (pad : Pad M F) :
    run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω
        * (run_transcript AC T_p var_dwR var_dwL ω inp w pad).w_r_true
        * (run_transcript AC T_p var_dwR var_dwL ω inp w pad).w_l_true
      = layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c (beta ω)) (AC.W_mle inp w)
          (alpha ω) q_challenge g0 g1
          (Vector.ofFn (n := logc + 2 * logw) fun i =>
            (run_transcript AC T_p var_dwR var_dwL ω inp w pad).challenges.getD i.val 0) := by
  have hch : (run_transcript AC T_p var_dwR var_dwL ω inp w pad).challenges = (T_p ω).challenges := rfl
  rw [hch, layer_poly_factors, run_eqq]
  show layer_eqq AC c (alpha ω) (beta ω) q_challenge g0 g1 (T_p ω).challenges
        * (true_evals AC inp w (T_p ω).challenges).2 * (true_evals AC inp w (T_p ω).challenges).1 = _
  ring


/--
**Sumcheck soundness for one layer.**

`event_card (Event_C …) ≤ eps_sumcheck`, by showing `Event_C` sits inside
`multi_round_bad_event` — the event that some round's transmitted polynomial differs from
the honest one yet agrees at the challenge.

This is the bridge between the abstract sumcheck counting bound and the protocol: the
generic `multi_round_bad_event` is instantiated at Longfellow's own honest round polynomials
(`circuit_true_polys`), and the reduction is `sumcheck_multi_reduction`.  Counts, not
probabilities.
-/
lemma lemma_sumcheck_soundness (eps_sumcheck : ℕ) {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (hpos : 0 < logc + 2 * logw)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_p)
    (ci : IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c inp E_L alpha beta q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_C AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L) ≤ eps_sumcheck := by
  have h_subset : Event_C AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L ⊆
    Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
      multi_round_bad_event (circuit_true_polys AC c inp w (run_transcript AC T_p var_dwR var_dwL ω inp w pad) (alpha ω) (beta ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ := by
    intro ω h_omega
    dsimp [Event_C] at h_omega ⊢
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at h_omega ⊢
    rcases h_omega with ⟨h_acc, w, pad, h_EL, hgood, h_check, h_ev⟩
    have h_ver := (T_p ω).rounds_verify pad
    refine ⟨h_acc, w, pad, h_EL, ?_⟩
    set eqq := run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω with h_eqq_def
    set t := run_transcript AC T_p var_dwR var_dwL ω inp w pad with h_t_def
    have h_shape1 : t.polys.length = logc + 2 * logw := by
      simpa [t, run_transcript, EncTranscript.decrypt] using wf.round_count ω h_acc
    have h_shape2 : t.challenges.length = logc + 2 * logw := by
      simpa [t, run_transcript, EncTranscript.decrypt] using wf.round_count ω h_acc
    have h_target : eqq * t.w_r_true * t.w_l_true =
        layer_sumcheck_poly_concat (nc := nc) (nv := nv) (AC.Quad_mle c (beta ω)) (AC.W_mle inp w)
          (alpha ω) q_challenge g0 g1
          (Vector.ofFn (n := logc + 2 * logw) fun i => t.challenges.getD i.val 0) :=
      final_binding AC c inp alpha beta q_challenge g0 g1 T_p var_dwR var_dwL ω w pad
    have h_circ := AC.soundness c inp w t (alpha ω) (beta ω) q_challenge g0 g1
      (eqq * t.w_r_true * t.w_l_true) hgood hpos h_shape1 h_shape2 h_target
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

  have h_mono : event_card (Event_C AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L) ≤ event_card (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧ multi_round_bad_event (circuit_true_polys AC c inp w (run_transcript AC T_p var_dwR var_dwL ω inp w pad) (alpha ω) (beta ω) q_challenge g0 g1) ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ) := by
    apply Finset.card_le_card
    exact h_subset
  have h_prob := ci.ci_bound
  exact le_trans h_mono h_prob

noncomputable def E_prime {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (c : Circuit) (inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) : Option Witness :=
  match E_L ω with
  | none => none
  | some (w, pad) =>
    if (run_transcript AC T_p var_dwR var_dwL ω inp w pad).checkV
        (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω) then some w else none


/--
`Event_Fail` is the knowledge-soundness failure event: the ZK verifier **accepted**
and yet the combined extractor `E_prime` either produced nothing or produced a
witness that does not satisfy the circuit.

The `accepts ω` conjunct is what makes this the right event to bound.  Runs the
verifier rejects carry no soundness obligation.
-/
noncomputable def Event_Fail {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧
    (E_prime AC c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L ω = none ∨
     ∃ w, E_prime AC c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L ω = some w ∧ AC.eval c inp w = false)) Finset.univ


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
lemma extractor_soundness_bridge {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
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
    (run_transcript AC T_p var_dwR var_dwL ω inp w p).checkV
      (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω) = true := by
  obtain ⟨hL, hR⟩ := input_row_binds_hands lig ω w p hacc hE hab
  have hclaim := layer_checks_imply_sumcheck (T_p ω).e p
      (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω) (T_p ω).wc0 (T_p ω).wc1
      var_dwL var_dwR var_dwL_dwR (lig.layer_constraint ω w p hacc hE)
  dsimp [run_transcript, Transcript.checkV, EncTranscript.decrypt]
  rw [hL, hR]
  have : evaluates_to (T_p ω).e p
      = run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω * ((T_p ω).wc1 + p var_dwR)
          * ((T_p ω).wc0 + p var_dwL) := by
    rw [hclaim]; ring
  simp
  exact this


/--
**The degenerate-randomness event.**

`begin_layer` draws two challenges (`transcript_sumcheck.h:L54`): `alpha`, which combines the
two inherited claims (`verifier_layers.h:L147`), and `beta`, which replaces the coefficient
of every assert-zero gate (`prep_v`, `quad.h:L213`).  On an unlucky pair the honest claim
`S(alpha, beta)` is *zero* even though the circuit is unsatisfied, so the sumcheck starts
from a true claim and nothing can be concluded.

This is a counted event, not a side condition.  `S` is a bilinear form in `(alpha, beta)`
(`layer_claim_affine` and `layer_claim_affine_quad`), so `bilinear_zero_card`
(`instantiate.lean`) bounds its zero set by `2·|F|` out of `|F|²` — a `2/|F|` fraction.
-/
noncomputable def Event_Degenerate {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (c : Circuit) (inp : Input) (alpha beta : Ω → F)
    (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    AC.Degenerate c inp w (alpha ω) (beta ω) q_challenge g0 g1
      ∧ AC.eval c inp w = false) Finset.univ

/--
**The input-binding error event.**

`Event_B` — the verifier accepted and the extractor succeeded, yet `checkV` fails — is
contained in the event that the input-binding coefficient `alpha_in` is the one unlucky value
that lets a mismatch through the single combined input row.

The challenge here is `alpha_in`, drawn *after every layer has closed*
(`symbolic_sumcheck_verifier.rs:L247`), not the layer's own `alpha`.  That ordering is what
makes the count work: by the time `alpha_in` is sampled, the transcript's `wc0`/`wc1` and the
committed witness are already fixed, so the pair of quantities the row has to separate is a
constant and `input_binding_bad_card` gives at most one bad draw.

A counted term, not an assumption: `event_alpha_bad_card` (`instantiate.lean`) turns that into
a `1/|F|` fraction of the sample space.
-/
noncomputable def Event_AlphaBad {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (inp : Input) (alpha_in : Ω → F) (var_dwR var_dwL : Fin M)
    (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
    InputBindingBad (true_evals AC inp w (T_p ω).challenges).1
      (true_evals AC inp w (T_p ω).challenges).2
      ((T_p ω).wc0 + pad var_dwL) ((T_p ω).wc1 + pad var_dwR) (alpha_in ω)) Finset.univ

lemma event_b_subset {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} {inp : Input} {w_ref : Witness}
    {alpha beta alpha_in : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (lig : IsLigeroKnowledgeSound AC accepts T_p c inp w_ref alpha beta alpha_in q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK) :
    Event_B AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L
      ⊆ Event_AlphaBad AC accepts inp alpha_in var_dwR var_dwL T_p E_L := by
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
`Event_Fail` is contained in the union of the four atomic failure events,
`Event_A ∪ Event_B ∪ Event_Degenerate ∪ Event_C`, by case analysis on what the extractor
returned and what the decrypted transcript does:

- `E_L ω = none` — Ligero extraction failed: `Event_A`.
- `E_L ω = some (w, pad)` and `checkV = false`: `Event_B`.
- `checkV = true` and the layer randomness is degenerate: `Event_Degenerate`.
- `checkV = true`, randomness good, and the witness fails the circuit: `Event_C`.
-/
lemma event_fail_subset {nc nv ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [DecidableEq (Fin M)] [SumcheckInterp F]
    {AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F}
    {accepts : Ω → Prop} {T_p : Ω → EncTranscript M F}
    {c : Circuit} (inp : Input) {w_ref : Witness}
    {alpha beta alpha_in : Ω → F} {q_challenge : Vector F logc} {g0 g1 : Vector F logv}
    {var_dwR var_dwL var_dwL_dwR : Fin M}
    {E_L : Ω → Option (AugmentedWitness M F Witness)} {eps_FSK : ℕ}
    (_lig : IsLigeroKnowledgeSound AC accepts T_p c inp w_ref alpha beta alpha_in q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_L eps_FSK) :
    Event_Fail AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L
      ⊆ Event_A accepts E_L
        ∪ Event_B AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L
        ∪ Event_Degenerate AC accepts c inp alpha beta q_challenge g0 g1 E_L
        ∪ Event_C AC accepts c inp alpha beta q_challenge g0 g1 var_dwR var_dwL T_p E_L := by
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
      cases h_check : (run_transcript AC T_p var_dwR var_dwL ω inp w pad).checkV
          (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω)
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
      cases h_check : (run_transcript AC T_p var_dwR var_dwL ω inp w' pad).checkV
          (run_eqq AC c inp alpha beta q_challenge g0 g1 T_p ω)
      · simp only [h_check] at hw1
        contradiction
      · simp only [h_check] at hw1
        injection hw1 with heq
        subst heq
        by_cases hdeg : AC.Degenerate c inp w' (alpha ω) (beta ω) q_challenge g0 g1
        · left; right
          exact ⟨h_acc, w', pad, rfl, hdeg, hw2⟩
        · right
          exact ⟨h_acc, w', pad, rfl, hdeg, h_check, hw2⟩


/--
**Core Soundness Theorem for Longfellow Zero-Knowledge (LFZK)**

This is the main theorem of the formalization.  Read precisely, it says:

> for **one sumcheck layer**, on the runs where the ZK verifier **accepts**, the number
> of runs on which the combined extractor `E_prime` fails to output a satisfying witness
> is at most `eps_FSK + eps_bind + eps_deg + eps_sumcheck`.

It is a *reduction*, not a self-contained knowledge-soundness proof: the four error terms
are supplied by the caller.  `core_soundness_derived_eps` fills in the sumcheck one, and
`core_soundness_probability_ideal_fs` (`instantiate.lean`) discharges all but `eps_FSK`
against a concrete sample space.

Rather than reasoning about real-valued probabilities, this formalization counts "bad"
outcomes in a finite sample space `Ω`; all bounds are set cardinalities (`event_card`),
not probability measures.  The counts are **absolute** and never normalised by
`Fintype.card Ω`, so the sum is only meaningful relative to `|Ω|`.  (The counting bounds in
`sumcheck_soundness.lean` *are* normalised: `n * d * |F|^(n-1)` out of `|F|^n`.)
`core_soundness_probability_ideal_fs` (`instantiate.lean`) is the normalised form.

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
     `Transcript.checkV = true` — *unless* the run hits the single `alpha_in` that lets the
     combined row hide a mismatch.  So `Event_B` sits inside `Event_AlphaBad`, which
     `event_alpha_bad_card` bounds by a `1/|F|` fraction.
   - `|Event_Degenerate| ≤ eps_deg`: the two challenges `begin_layer` draws collapsing a
     non-zero claim.  The honest claim is a bilinear form `S(alpha, beta)`
     (`layer_claim_affine`, `layer_claim_affine_quad`), so `bilinear_zero_card` bounds its
     zero set by `2·|F|` out of `|F|²`.

### The three challenges

A one-layer run draws three field elements, and the theorem keeps them apart:

| | drawn | used by |
|---|---|---|
| `alpha` | `begin_layer`, before the layer's messages | combines the two inherited claims |
| `beta` | `begin_layer`, alongside `alpha` | replaces the assert-zero coefficient (`prep_v`) |
| `alpha_in` | `elt_field`, after every layer has closed | the single combined input-binding row |

`alpha`/`beta` are the pair `Event_Degenerate` counts; `alpha_in` is the one `Event_AlphaBad`
counts.  Reusing the layer's `alpha` for the input row would make the model
strictly stronger than the protocol.  `instantiate.lean` samples them in that order, with the
transcript a function of `(alpha, beta)` and the extractor's output a function of neither —
matching `ZkProver::commit` running before the transcript exists.
   - `|Event_C| ≤ eps_sumcheck`: `lemma_sumcheck_soundness` reduces `Event_C` to
     `multi_round_bad_event` via `sumcheck_multi_reduction` (proved), and then takes the
     count from `IsSumcheckCorrelationIntractable.ci_bound` — which
     `sumcheck_ci_of_nonadaptive` derives as `K * (n * d * |F|^(n-1))`, with `d = 2` itself
     derived (`ArithmetizedCircuit.round_poly_natDegree_le_two`).

4. **Final Bound**: `|Event_Fail| ≤ eps_FSK + eps_bind + eps_deg + eps_sumcheck`.

### What is assumed

Three things, and nothing else:

* `IsLigeroKnowledgeSound` — Ligero as an ideal primitive (`extraction_bound`) plus what its
  extractor returns (`layer_constraint`, `input_row`).  This is the one irreducibly
  cryptographic assumption.
* `ArithmetizedCircuit.arith` — for an unsatisfied circuit the honest claim `S(alpha, beta)`
  is not identically zero on `F × F`.  This is the correctness of the circuit compiler.
* The three error bounds `h_bind`, `h_deg`, `ci`, which `instantiate.lean` discharges over a
  concrete sample space.

Everything else about the arithmetization is *data*: `Quad_mle` and `W_mle` are constructed
as multilinear extensions of a gate table and of `pub ++ priv`, so their multilinearity,
their affineness in `beta`, and public-input consistency are theorems.  `round_count` is a
description of the verifier rather than an assumption.  There is **no** non-degeneracy
hypothesis: both randomness conditions are counted events.

### Non-vacuity

`example.lean` builds a concrete instance over `ZMod 5` — one round, `eval` identically
`false`, verifier accepting — discharging every hypothesis.  There `Event_Fail` is the whole
sample space and the bound is tight, and `eps_sumcheck_forced` shows the sumcheck term
cannot be `0`.  Without such a witness this theorem would say nothing.

### What this theorem does *not* establish

* **A single layer.**  `verifier_layers.h::layers` runs `nl` layers; this theorem joins the
  Ligero pad machinery to *one* of them.  `multi_layer_core_soundness` (`zk_soundness.lean`)
  is the multi-layer statement, and `example.lean` witnesses it too.
* **Zero-knowledge.**  Only soundness; the pad is a vector the extractor produces, not a
  distribution.
* **Copy rounds.**  `RoundPoly` matches `WPoly = Poly<3, Field>` (degree 2), which is what
  the ZK path uses.  The non-ZK `VerifierLayers::layer_c` uses `CPoly = Poly<4, Field>`.
* **Challenge ordering.**  `extract_vars` treats the two hands as contiguous blocks, while
  the implementation interleaves them (`for (round) for (hand)`).
-/
theorem core_soundness_theorem {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq (Fin M)] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (accepts : Ω → Prop) (C : Circuit) (x : Input) (w_ref : Witness)
    (alpha beta alpha_in : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_prime : Ω → EncTranscript M F) (E_Ligero : Ω → Option (AugmentedWitness M F Witness))
    (hpos : 0 < logc + 2 * logw)
    (lig : IsLigeroKnowledgeSound AC accepts T_prime C x w_ref alpha beta alpha_in q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_Ligero eps_FSK)
    (eps_bind eps_deg : ℕ)
    (h_bind : event_card (Event_AlphaBad AC accepts x alpha_in var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind)
    (h_deg : event_card (Event_Degenerate AC accepts C x alpha beta q_challenge g0 g1 E_Ligero) ≤ eps_deg)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_prime)
    (ci : IsSumcheckCorrelationIntractable AC accepts T_prime var_dwR var_dwL C x E_Ligero alpha beta q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_Fail AC accepts C x alpha beta q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
      ≤ eps_FSK + eps_bind + eps_deg + eps_sumcheck := by
  have h_sub := Finset.card_le_card (event_fail_subset x lig)
  have h_ub := union_bound_4 (Event_A accepts E_Ligero)
    (Event_B AC accepts C x alpha beta q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
    (Event_Degenerate AC accepts C x alpha beta q_challenge g0 g1 E_Ligero)
    (Event_C AC accepts C x alpha beta q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
  have h_a := lig.extraction_bound
  have h_b : event_card (Event_B AC accepts C x alpha beta q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind :=
    le_trans (Finset.card_le_card (event_b_subset lig)) h_bind
  have h_c := lemma_sumcheck_soundness eps_sumcheck AC accepts var_dwR var_dwL C x T_prime
    E_Ligero alpha beta q_challenge g0 g1 hpos wf ci
  have h_d := h_deg
  dsimp [event_card] at *
  linarith


/--
**Core soundness with `eps_sumcheck` derived.**

Same statement as `core_soundness_theorem`, except the sumcheck error term is no longer a
hypothesis: it is `K * (|S| * n * d * |F|^(n-1))`, produced by `sumcheck_ci_of_nonadaptive`
from

* `combinatorial_fiat_shamir` — a root count, no random oracle and no probability space;
* `IsNonAdaptiveRun` — the structural Fiat–Shamir property that round `i`'s polynomial is
  fixed before challenge `i` is drawn from it;
* `K` — how many runs the hash can send to a single (pre-state, challenge sequence) pair;
* `|S|` — the number of pre-challenge states, which cancels against `|Ω|` exactly as `K` does.

Out of the `|F|^n` challenge sequences, `n * d * |F|^(n-1)` is a `n * d / |F|` fraction:
the textbook sumcheck soundness error, here as an exact count.  `d` need not be supplied
either — `fsOfArithmetized` builds the bundle at the derived `d = 2` — and `K` cancels
against `|Ω|` once the challenge sequence is a coordinate of the sample space
(`instantiate.lean`).
-/
theorem core_soundness_derived_eps {nc nv ninp npub logv logw logc : ℕ} {M : ℕ} {S F : Type}
    [Fintype S] [DecidableEq S] [Field F] [Fintype F] [DecidableEq (Fin M)] [DecidableEq F]
    [SumcheckInterp F] {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (fam : IsFiatShamirFamily S F n d)
    (accepts : Ω → Prop) (C : Circuit) (x : Input) (w_ref : Witness)
    (alpha beta alpha_in : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_prime : Ω → EncTranscript M F) (E_Ligero : Ω → Option (AugmentedWitness M F Witness))
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ (s : S) (cs : Fin n → F),
      (Finset.filter (fun ω => state ω = s ∧ challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC fam accepts T_prime var_dwR var_dwL C x E_Ligero alpha beta
      q_challenge g0 g1 state challenge_map)
    (hpos : 0 < logc + 2 * logw)
    (lig : IsLigeroKnowledgeSound AC accepts T_prime C x w_ref alpha beta alpha_in q_challenge g0 g1
             var_dwR var_dwL var_dwL_dwR E_Ligero eps_FSK)
    (eps_bind eps_deg : ℕ)
    (h_bind : event_card (Event_AlphaBad AC accepts x alpha_in var_dwR var_dwL T_prime E_Ligero) ≤ eps_bind)
    (h_deg : event_card (Event_Degenerate AC accepts C x alpha beta q_challenge g0 g1 E_Ligero) ≤ eps_deg)
    (wf : IsWellFormedTranscript (logw := logw) (logc := logc) accepts T_prime) :
    event_card (Event_Fail AC accepts C x alpha beta q_challenge g0 g1 var_dwR var_dwL T_prime E_Ligero)
      ≤ eps_FSK + eps_bind + eps_deg
          + K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1))) :=
  core_soundness_theorem (eps_FSK := eps_FSK)
    (eps_sumcheck := K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1))))
    AC accepts C x w_ref alpha beta alpha_in q_challenge g0 g1
    var_dwR var_dwL var_dwL_dwR T_prime E_Ligero hpos lig eps_bind eps_deg h_bind h_deg wf
    (sumcheck_ci_of_nonadaptive AC fam accepts T_prime var_dwR var_dwL C x E_Ligero
      alpha beta q_challenge g0 g1 state challenge_map K h_unif na)
