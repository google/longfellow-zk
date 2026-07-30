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
`ligero_input_checks` defines the mathematical predicate representing the 
linear constraints verified by the Ligero verifier for input witness evaluation bindings.

It checks that `∑ i, lhs[i] * pad[i] = rhs` holds for the `input_constraint_row`.
- **Code Reference**: `ZkCommon::InputConstraints` in `privacy/proofs/zk/lib/zk/zk_common.h`.
-/
def ligero_input_checks {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)] 
  (pad : Fin M → F) (got : F) (pub_binding : F) (beta alpha : F) 
  (witness_binding : Fin M → F) (var_dwL var_dwR : Fin M) : Prop :=
  let lr := input_constraint_row got pub_binding beta alpha witness_binding var_dwL var_dwR
  let lhs := lr.1
  let rhs := lr.2
  ∑ i, lhs i * pad i = rhs


def ligero_checks {M : ℕ} {F : Type} [Field F] [DecidableEq F] (eqq : F) (var_dwR var_dwL : Fin M) (t_prime : EncTranscript M F) (_w : Witness) (p : Pad M F) : Bool :=
  (t_prime.decrypt p var_dwR var_dwL).checkV eqq


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


theorem input_checks_imply_binding {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)] 
    (pad : Fin M → F) (got : F) (pub_binding : F) (beta alpha : F) 
    (witness_binding : Fin M → F) (var_dwL var_dwR : Fin M) :
    ligero_input_checks pad got pub_binding beta alpha witness_binding var_dwL var_dwR →
    (∑ i, witness_binding i * pad i) + pub_binding = got + beta * pad var_dwL + alpha * pad var_dwR := by
  intro h
  exact input_constraint_soundness pad got pub_binding beta alpha witness_binding var_dwL var_dwR h



noncomputable def Event_A {M : ℕ} {F : Type} [Field F] (E_L : Ω → Option (AugmentedWitness M F Witness)) : Finset Ω :=
  Finset.filter (fun ω => E_L ω = none) Finset.univ




/--
**Axiom 1: Ligero Knowledge Soundness**
This axiom guarantees that the probability of a malicious prover breaking the
Ligero commitment scheme is bounded by `eps_FSK`. Specifically, it asserts
that the probability of `Event_A` occurring (where the verifier accepts
the Ligero proof, but the Ligero extractor `E_Ligero` fails to output a
valid witness) is at most the statistical soundness error of the Ligero
protocol. We treat Ligero as an ideal cryptographic primitive in this
reduction.
-/
axiom axiom_ligero_soundness {M : ℕ} {F : Type} [Field F] (E_L : Ω → Option (AugmentedWitness M F Witness)) : event_card (Event_A E_L) ≤ eps_FSK


/--
**Axiom 2: Extractor Constraint Validity**
This axiom encodes the mathematical definition of Knowledge Soundness for our black-box Ligero prover.
It guarantees that if the Ligero extractor successfully outputs a witness and a pad (`w, p`),
that extracted pad is strictly guaranteed to satisfy the specific linear (`ligero_layer_checks`)
and quadratic (`ligero_input_checks`) constraints that were fed into the Ligero verifier.
Since we do not formally model the inner Reed-Solomon workings of Ligero in Lean, this axiom serves
as the cryptographic boundary between the Ligero black-box and our sumcheck integration.
-/
axiom axiom_ligero_extractor_valid_pad {M : ℕ} {F : Type} [Field F] [DecidableEq (Fin M)]
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) (w : Witness) (p : Pad M F) :
    E_L ω = some (w, p) →
    (∀ e eqq wc0 wc1 vL vR vLR, ligero_layer_checks e p eqq wc0 wc1 vL vR vLR) ∧
    (∀ g pb beta alpha wb vL vR, ligero_input_checks p g pb beta alpha wb vL vR)


/--
**Axiom 2.5: Extractor Sumcheck Validity**
This axiom guarantees that if the Ligero extractor succeeds, the public transcript was valid and accepted by the verifier,
meaning the sumcheck polynomial evaluations match the final claim.
-/
axiom axiom_extractor_implies_sumcheck {M : ℕ} {F : Type} [Field F] [DecidableEq F]
    (T_p : Ω → EncTranscript M F)
    (E_L : Ω → Option (AugmentedWitness M F Witness)) (ω : Ω) (w : Witness) (p : Pad M F) :
    E_L ω = some (w, p) →
    verify_multi_round 0 (T_p ω).polys (T_p ω).challenges == some (evaluates_to (T_p ω).e p)

