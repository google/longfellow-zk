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
variable (C : Circuit) (x : Input)
variable (eval : Circuit → Input → Witness → Bool)
variable {nc nv : ℕ}
variable (eps_FSK eps_sumcheck : ℕ)

/-!
This file contains the main Longfellow ZK soundness theorem corresponding
to Theorem 6, Protocol 2.5 in the "Anonymous credentials from ECDSA" paper.
The main argument follows the paper proof.
-/


/--
`Event_B` describes the event where the extractor `E_L` successfully extracts a witness and pad,
but the decrypted transcript fails the validity check `checkV`.
-/
noncomputable def Event_B {M : ℕ} {F : Type} [Field F] [DecidableEq F] (eqq : F) (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => ∃ w pad, E_L ω = some (w, pad) ∧ ((T_p ω).decrypt pad var_dwR var_dwL).checkV eqq = false) Finset.univ


/--
`Event_C` describes the event where the extractor `E_L` extracts a witness and pad, the sumcheck
multi-round verification succeeds, the decrypted transcript passes the validity check `checkV`, 
but the circuit evaluation for the extracted witness evaluates to false.
-/
noncomputable def Event_C {M : ℕ} {F : Type} [Field F] [DecidableEq F] (eqq : F) (var_dwR var_dwL : Fin M) (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input) (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => ∃ w pad, E_L ω = some (w, pad) ∧
    (verify_multi_round 0 (T_p ω).polys (T_p ω).challenges == some (evaluates_to (T_p ω).e pad)) ∧
    ((T_p ω).decrypt pad var_dwR var_dwL).checkV eqq = true ∧ ev c inp w = false) Finset.univ


/--
**Lemma: Sumcheck Protocol Soundness**
Proves that `P(Event_C) ≤ eps_sumcheck` by reducing `Event_C` to `multi_round_bad_event`
using `sumcheck_multi_reduction`.

This lemma serves as the bridge between abstract sumcheck bounds and the specific 
Longfellow protocol. It bounds the protocol-specific `Event_C` by instantiating the 
generic `multi_round_bad_event` with Longfellow's specific arithmetized quadratic 
form polynomials (`circuit_true_polys`).
-/
lemma lemma_sumcheck_soundness (eps_sumcheck : ℕ) {nc nv logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv logv logw logc F)
    (eqq : F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (ci : IsSumcheckCorrelationIntractable AC T_p var_dwR var_dwL eqq c inp E_L alpha q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_C eqq var_dwR var_dwL AC.eval c inp T_p E_L) ≤ eps_sumcheck := by
  have h_subset : Event_C eqq var_dwR var_dwL AC.eval c inp T_p E_L ⊆
    Finset.filter (fun ω => ∃ w pad, E_L ω = some (w, pad) ∧
      multi_round_bad_event (circuit_true_polys AC c w ((T_p ω).decrypt pad var_dwR var_dwL) alpha q_challenge g0 g1) (T_p ω).polys (T_p ω).challenges) Finset.univ := by
    intro ω h_omega
    dsimp [Event_C] at h_omega ⊢
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at h_omega ⊢
    rcases h_omega with ⟨w, pad, h_EL, h_ver, h_check, h_ev⟩
    use w, pad
    refine ⟨h_EL, ?_⟩
    let t := (T_p ω).decrypt pad var_dwR var_dwL
    have h_circ := AC.soundness c inp w eqq t alpha q_challenge g0 g1 h_ev
    rcases h_circ with ⟨P_first, P_rest, h_eq, h_len1, h_len2, h_cons, h_neq, h_last⟩
    have h_polys_nnil : (T_p ω).polys ≠ [] := by
      intro h_nil
      have h_len_zero : (T_p ω).polys.length = 0 := by rw [h_nil, List.length_nil]
      dsimp [t, EncTranscript.decrypt] at h_len1
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

    have h_reduce := sumcheck_multi_reduction (P_first :: P_rest) (T_p ω).polys (T_p ω).challenges 0 (evaluates_to (T_p ω).e pad)

    have h_ver_eq : verify_multi_round 0 (T_p ω).polys (T_p ω).challenges = some (evaluates_to (T_p ω).e pad) := by
      exact beq_iff_eq.mp h_ver

    have h_reduce_apply := h_reduce h_ver_eq h_len1 h_len2 h_cons h_polys_nnil
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

  have h_mono : event_card (Event_C eqq var_dwR var_dwL AC.eval c inp T_p E_L) ≤ event_card (Finset.filter (fun ω => ∃ w pad, E_L ω = some (w, pad) ∧ multi_round_bad_event (circuit_true_polys AC c w ((T_p ω).decrypt pad var_dwR var_dwL) alpha q_challenge g0 g1) (T_p ω).polys (T_p ω).challenges) Finset.univ) := by
    apply Finset.card_le_card
    exact h_subset
  have h_prob := ci.ci_bound
  exact le_trans h_mono h_prob

noncomputable def E_prime {M : ℕ} {F : Type} [Field F] [DecidableEq F] (eqq : F) (var_dwR var_dwL : Fin M) (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) : Option Witness :=
  match E_L ω with
  | none => none
  | some (w, pad) =>
    if ((T_p ω).decrypt pad var_dwR var_dwL).checkV eqq then some w else none


noncomputable def Event_Fail {M : ℕ} {F : Type} [Field F] [DecidableEq F] (eqq : F) (var_dwR var_dwL : Fin M) (ev : Circuit → Input → Witness → Bool) (c : Circuit) (inp : Input) (T_p : Ω → EncTranscript M F) (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => E_prime eqq var_dwR var_dwL T_p E_L ω = none ∨ ∃ w, E_prime eqq var_dwR var_dwL T_p E_L ω = some w ∧ ev c inp w = false) Finset.univ


omit [Fintype Ω] in
lemma union_bound_3 (A B C : Finset Ω) :
    event_card (A ∪ B ∪ C) ≤ event_card A + event_card B + event_card C := by
  dsimp [event_card]
  linarith [Finset.card_union_le (A ∪ B) C, Finset.card_union_le A B]

/--
`event_fail_subset` proves that the overall extractor failure event `Event_Fail` is a subset of
the union of the three atomic failure events: `Event_A ∪ Event_B ∪ Event_C`.

`Event_Fail` occurs when the combined extractor `E_prime` either fails to return a witness (`none`)
or returns an invalid witness (`ev c inp w = false`).

Case analysis:
- If `E_L ω = none`: Belongs to `Event_A` (Ligero extraction failure).
- If `E_L ω = some (w, pad)` and `Transcript.checkV = false`: Belongs to `Event_B` (verification check failure).
- If `E_L ω = some (w, pad)` and `Transcript.checkV = true` with `ev c inp w = false`: Belongs to `Event_C` (sumcheck soundness failure).

This partitioning allows bounding `P(Event_Fail)` via a union bound in `core_soundness_theorem`.
-/
lemma event_fail_subset {M : ℕ} {F : Type} [Field F] [DecidableEq F] [DecidableEq (Fin M)]
    (ev : Circuit → Input → Witness → Bool)
    (c : Circuit) (inp : Input) (eqq : F)
    (var_dwR var_dwL : Fin M)
    (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) :
    Event_Fail eqq var_dwR var_dwL ev c inp T_p E_L ⊆ Event_A E_L ∪ Event_B eqq var_dwR var_dwL T_p E_L ∪ Event_C eqq var_dwR var_dwL ev c inp T_p E_L := by
  intro ω h
  dsimp [Event_Fail, Event_A, Event_B, Event_C] at h ⊢
  simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_union] at h ⊢
  cases h with
  | inl h1 =>
    dsimp [E_prime] at h1
    cases h_lig : E_L ω with
    | none =>
      left; left
      rfl
    | some w_prime =>
      rcases w_prime with ⟨w, pad⟩
      rw [h_lig] at h1
      cases h_check : ((T_p ω).decrypt pad var_dwR var_dwL).checkV eqq
      · left; right
        exact ⟨w, pad, rfl, h_check⟩
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
      cases h_check : ((T_p ω).decrypt pad var_dwR var_dwL).checkV eqq
      · simp only [h_check] at hw1
        contradiction
      · simp only [h_check] at hw1
        injection hw1 with heq
        subst heq
        right
        have h_sumcheck := axiom_extractor_implies_sumcheck T_p E_L ω w' pad h_lig
        exact ⟨w', pad, rfl, h_sumcheck, h_check, hw2⟩


omit [Fintype Ω] in
/--
**Lemma: Constraint to Sumcheck Bridge**
This lemma proves that if the extracted pad passes the `ligero_layer_checks` and `ligero_input_checks`,
the decoded transcript is algebraically equivalent to the honest sumcheck transcript,
and therefore passes `ligero_checks`.
-/
lemma extractor_soundness_bridge {M : ℕ} {F : Type} [Field F] [DecidableEq F] [DecidableEq (Fin M)]
    (eqq : F) (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness))
    (ω : Ω) (w : Witness) (p : Pad M F) :
    E_L ω = some (w, p) →
    (∀ e eqq wc0 wc1 vL vR vLR, ligero_layer_checks e p eqq wc0 wc1 vL vR vLR) →
    (∀ g pb beta alpha wb vL vR, ligero_input_checks p g pb beta alpha wb vL vR) →
    ligero_checks eqq var_dwR var_dwL (T_p ω) w p = true := by
  intros _ h_layer h_input
  dsimp [ligero_checks, Transcript.checkV, EncTranscript.decrypt]
  have h_layer_spec := h_layer (T_p ω).e eqq (T_p ω).wc0 (T_p ω).wc1 var_dwL var_dwR var_dwL_dwR
  have h_input_w_r := h_input (T_p ω).wc1 (T_p ω).pub_r 0 1 (T_p ω).w_r_bind var_dwL var_dwR
  have h_input_w_l := h_input (T_p ω).wc0 (T_p ω).pub_l 1 0 (T_p ω).w_l_bind var_dwL var_dwR

  have hl := layer_checks_imply_sumcheck (T_p ω).e p eqq (T_p ω).wc0 (T_p ω).wc1 var_dwL var_dwR var_dwL_dwR h_layer_spec
  have hr := input_checks_imply_binding p (T_p ω).wc1 (T_p ω).pub_r 0 1 (T_p ω).w_r_bind var_dwL var_dwR h_input_w_r
  have hl_in := input_checks_imply_binding p (T_p ω).wc0 (T_p ω).pub_l 1 0 (T_p ω).w_l_bind var_dwL var_dwR h_input_w_l

  have hr_simp : (∑ i : Fin M, (T_p ω).w_r_bind i * p i) + (T_p ω).pub_r = (T_p ω).wc1 + p var_dwR := by
    calc (∑ i : Fin M, (T_p ω).w_r_bind i * p i) + (T_p ω).pub_r
      _ = (T_p ω).wc1 + 0 * p var_dwL + 1 * p var_dwR := hr
      _ = (T_p ω).wc1 + p var_dwR := by ring

  have hl_in_simp : (∑ i : Fin M, (T_p ω).w_l_bind i * p i) + (T_p ω).pub_l = (T_p ω).wc0 + p var_dwL := by
    calc (∑ i : Fin M, (T_p ω).w_l_bind i * p i) + (T_p ω).pub_l
      _ = (T_p ω).wc0 + 1 * p var_dwL + 0 * p var_dwR := hl_in
      _ = (T_p ω).wc0 + p var_dwL := by ring

  have hl_symm : evaluates_to (T_p ω).e p = eqq * ((T_p ω).wc1 + p var_dwR) * ((T_p ω).wc0 + p var_dwL) := by
    calc evaluates_to (T_p ω).e p
      _ = eqq * ((T_p ω).wc0 + p var_dwL) * ((T_p ω).wc1 + p var_dwR) := hl
      _ = eqq * ((T_p ω).wc1 + p var_dwR) * ((T_p ω).wc0 + p var_dwL) := by ring

  simp [hl_symm, hr_simp.symm, hl_in_simp.symm]


lemma event_b_empty {M : ℕ} {F : Type} [Field F] [DecidableEq F] [DecidableEq (Fin M)]
    (eqq : F)
    (var_dwR var_dwL var_dwL_dwR : Fin M)
    (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) :
    Event_B eqq var_dwR var_dwL T_p E_L = ∅ := by
  ext ω
  dsimp [Event_B]
  simp only [Finset.mem_filter, Finset.mem_univ, true_and]
  constructor
  · rintro ⟨w, pad, h_lig, h_check⟩
    have h_valid := axiom_ligero_extractor_valid_pad E_L ω w pad h_lig
    have h_corr := extractor_soundness_bridge eqq var_dwR var_dwL var_dwL_dwR T_p E_L ω w pad h_lig h_valid.1 h_valid.2
    dsimp [ligero_checks] at h_corr
    rw [h_check] at h_corr
    contradiction
  · intro h
    contradiction


/--
**Core Soundness Theorem for Longfellow Zero-Knowledge (LFZK)**

This is the main theorem of the formalization. It proves that the
combined Longfellow ZK interactive proof system is **Knowledge Sound** with total
soundness error bounded by `eps_FSK + eps_sumcheck`.

Rather than reasoning about real-valued probabilities directly, this formalization
operates by counting the number of "bad" random coin outcomes in a finite sample
space `Ω`. All bounds are expressed in terms of set cardinalities (via `event_card`)
instead of probability measures `P(...)`.

### High-Level Proof Structure:
1. **Event Partitioning (`event_fail_subset`)**:
   The failure event `Event_Fail` (where the prover causes the combined extractor `E_prime`
   to fail or output an invalid witness) is shown to be a subset of three atomic error events:
   `Event_Fail ⊆ Event_A ∪ Event_B ∪ Event_C`.

2. **Measure Monotonicity & Union Bound (`union_bound_3`)**:
   By subset monotonicity and the union bound over set cardinalities:
   `|Event_Fail| ≤ |Event_A| + |Event_B| + |Event_C|`.

3. **Bounding Individual Error Terms**:
   - `|Event_A| ≤ eps_FSK`: Bounded by Ligero Knowledge Soundness (`axiom_ligero_soundness`).
   - `|Event_B| = 0`: Proven to be empty (`event_b_empty`) via `extractor_soundness_bridge`,
     showing that any extracted pad satisfying Ligero constraints strictly forces `Transcript.checkV = true`.
   - `|Event_C| ≤ eps_sumcheck`: Bounded by Sumcheck Soundness (`lemma_sumcheck_soundness`).

4. **Final Bound**:
   `|Event_Fail| ≤ eps_FSK + 0 + eps_sumcheck = eps_FSK + eps_sumcheck`.
-/
theorem core_soundness_theorem {nc nv logv logw logc : ℕ} {M : ℕ} {F : Type} [Field F] [Fintype F] [Fintype (Vector F logv)] [DecidableEq (Fin M)] [DecidableEq F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv logv logw logc F)
    (eqq : F) (var_dwR var_dwL var_dwL_dwR : Fin M)
    (C : Circuit) (x : Input) (T_prime : Ω → EncTranscript M F) (E_Ligero : Ω → Option (AugmentedWitness M F Witness))
    (alpha : F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (ci : IsSumcheckCorrelationIntractable AC T_prime var_dwR var_dwL eqq C x E_Ligero alpha q_challenge g0 g1 eps_sumcheck) :
    event_card (Event_Fail eqq var_dwR var_dwL AC.eval C x T_prime E_Ligero) ≤ eps_FSK + eps_sumcheck := by
  have h_sub : event_card (Event_Fail eqq var_dwR var_dwL AC.eval C x T_prime E_Ligero) ≤ event_card (Event_A E_Ligero ∪ Event_B eqq var_dwR var_dwL T_prime E_Ligero ∪ Event_C eqq var_dwR var_dwL AC.eval C x T_prime E_Ligero) := Finset.card_le_card (event_fail_subset AC.eval C x eqq var_dwR var_dwL T_prime E_Ligero)
  have h_ub := union_bound_3 (Event_A E_Ligero) (Event_B eqq var_dwR var_dwL T_prime E_Ligero) (Event_C eqq var_dwR var_dwL AC.eval C x T_prime E_Ligero)
  have h_a := axiom_ligero_soundness eps_FSK E_Ligero
  have h_b : event_card (Event_B eqq var_dwR var_dwL T_prime E_Ligero) = 0 := by
    rw [event_b_empty eqq var_dwR var_dwL var_dwL_dwR T_prime E_Ligero]
    exact Finset.card_empty
  have h_c := lemma_sumcheck_soundness eps_sumcheck AC eqq var_dwR var_dwL C x T_prime E_Ligero alpha q_challenge g0 g1 ci
  linarith
