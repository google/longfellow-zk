import lfzk
import layers
import zk_layers
import zk_soundness

open Classical Polynomial Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false
set_option maxHeartbeats 1000000

/-!
# Non-vacuity witnesses

The soundness theorems bound the size of a *bad* event.  Such a bound is worthless if the
hypotheses are unsatisfiable (the theorem is then `False → anything`) or if they secretly
force the bad event to be empty (the bound then reads `0 ≤ eps`).  Neither failure is caught
by type-checking, so each theorem gets an explicit instance here.

Every instance is built in the regime the theorems are *about*: an **unsatisfiable** circuit
— `eval` identically `false`, so no witness exists — that the verifier nevertheless
**accepts**.  That is a real soundness break; the theorems say such breaks are rare, and the
job of these witnesses is to show the hypotheses do not assume them away.

The first instance:

* field `ZMod 5`, sample space `Unit`, pad width `M = 1`;
* `logc = 1`, `logw = 0`, `logv = 0`, `nc = nv = 1`, so exactly one sumcheck round;
* `eval` is identically `false` — every witness fails the circuit;
* the prover's round polynomial is a *lie* the verifier accepts, so `Event_Fail` is all of
  the sample space and the bound is tight at `1 ≤ 1`;
* `eps_sumcheck_forced` then shows any valid `eps_sumcheck` here is `≥ 1` — the sumcheck
  term is load-bearing, not padding.

The layer polynomial of this instance is `f(c) = (1 - q₀)(1 - c)(1 + alpha)`.  Its
hypercube sum `f(0) + f(1) = (1 - q₀)(1 + alpha)` is non-zero exactly when the layer
randomness is non-degenerate; that is what "the circuit is not satisfied" amounts to
here, and it is why `ArithmetizedCircuit.degenerate` has to exist.

Instantiating `alpha = 0`, `q = [0]` gives `f(c) = 1 - c`.  An honest prover would
have to send `p(0) = 1, p(1) = 0`, failing the round check `p(0) + p(1) = 0`.  The
cheating prover sends the zero polynomial instead, which passes the round check, and
gets away with it exactly when the challenge is the single root `r = 1` of `p - f`.
That is the `BadRoundEvent`, and it is why `eps_sumcheck` cannot be `0` here.
-/

namespace LfzkExample

instance : Fact (Nat.Prime 5) := ⟨by norm_num⟩

abbrev F5 := ZMod 5

/-- The third interpolation point for a prime field is `2`
(`Field::poly_evaluation_point(2)`), matching `WPoly = Poly<3, Field>`. -/
instance : SumcheckInterp F5 where
  pt2 := 2
  pt2_ne_zero := by decide
  pt2_ne_one := by decide

/-- The unique element of `Vector F5 0`. -/
def v0 : Vector F5 0 := Vector.ofFn (fun i => i.elim0)

/-- The one-element vector `[c]`. -/
def vec1 (c : F5) : Vector F5 1 := Vector.ofFn (fun _ => c)

@[simp] lemma vec1_get (c : F5) (i : Fin 1) : (vec1 c).get i = c := by
  simp [vec1]

lemma eq_matrix_10 (x y : Vector F5 0) : eq_matrix_mle 1 0 x y = 1 := by
  simp [eq_matrix_mle, eq_mle_basis]

lemma eq_matrix_11 (x y : Vector F5 1) :
    eq_matrix_mle 1 1 x y = (1 - x.get 0) * (1 - y.get 0) := by
  simp [eq_matrix_mle, eq_mle_basis, bit_value]

/-- With both copies present, `EQ` sums to `1` over the hypercube — which is what makes the
output claim non-zero for *every* `q`, as the alpha-free `arith` now demands. -/
lemma eq_matrix_21 (x y : Vector F5 1) :
    eq_matrix_mle 2 1 x y = (1 - x.get 0) * (1 - y.get 0) + x.get 0 * y.get 0 := by
  simp [eq_matrix_mle, eq_mle_basis, bit_value, Finset.sum_range_succ]

/-! ## The arithmetized circuit -/

@[simp] lemma eq_mle_basis_vec0 (i : ℕ) (x : Vector F5 0) : eq_mle_basis i x = 1 := by
  simp [eq_mle_basis]

/-- `QUAD` is identically one. -/
def myQuad : Unit → Vector F5 0 → Vector F5 0 → Vector F5 0 → F5 := fun _ _ _ _ => 1

/-- `W` is identically one. -/
def myW : Unit → Vector F5 0 → Vector F5 1 → F5 := fun _ _ _ => 1

/-- The single Ligero-committed input column, also identically one. -/
def myWcol : Unit → Vector F5 1 → Fin 1 → F5 := fun _ _ _ => 1

/-- The layer polynomial of this instance, as a function of the layer randomness. -/
noncomputable def myf (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) :
    Vector F5 (1 + 2 * 0) → F5 :=
  layer_sumcheck_poly_concat (nc := 2) (nv := 1) (myQuad ()) (myW ()) alpha q g0 g1

lemma myf_eval (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) (c : F5) :
    myf alpha q g0 g1 (vec1 c) = ((1 - q.get 0) * (1 - c) + q.get 0 * c) * (1 + alpha) := by
  simp [myf, layer_sumcheck_poly_concat, extract_vars, layer_sumcheck_poly,
        myQuad, myW, eq_matrix_21]

/-- The layer claim of this instance is `1 + alpha`: `EQ` sums to `1` over the two copies,
and the `QUAD` factor contributes `1 + alpha`. -/
lemma my_layer_claim (a : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) :
    layer_claim (nc := 2) (nv := 1) (myQuad ()) (myW ()) a q g0 g1 = 1 + a := by
  have h0 : (boolean_vector 0 : Vector F5 (1 + 2 * 0)) = vec1 0 := by
    ext i hi; simp [boolean_vector, vec1, bit_value]
  have h1 : (boolean_vector 1 : Vector F5 (1 + 2 * 0)) = vec1 1 := by
    ext i hi
    have him : i = 0 := by omega
    subst him
    simp [boolean_vector, vec1, bit_value]
  have hr : Finset.range (2 ^ (1 + 2 * 0)) = Finset.range 2 := by norm_num
  rw [layer_claim, hr, Finset.sum_range_succ, Finset.sum_range_one, h0, h1]
  show myf a q g0 g1 (vec1 0) + myf a q g0 g1 (vec1 1) = 1 + a
  rw [myf_eval, myf_eval]
  ring

/-- The honest round-0 polynomial.  Its prefix is empty, so it does not depend on
the challenges at all — which is what makes this one-round instance tractable. -/
noncomputable def myP (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) : Polynomial F5 :=
  sumcheck_round_poly (myf alpha q g0 g1) 0 (by omega)
    (Vector.ofFn (fun i : Fin 0 => i.elim0))

lemma myP_eval (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) (r : F5) :
    (myP alpha q g0 g1).eval r = ((1 - q.get 0) * (1 - r) + q.get 0 * r) * (1 + alpha) := by
  rw [myP, sumcheck_round_poly_eval]
  have h : sumcheck_eval_round (myf alpha q g0 g1) 0 (by omega)
      (Vector.ofFn (fun i : Fin 0 => i.elim0)) r = myf alpha q g0 g1 (vec1 r) := by
    simp [sumcheck_eval_round, construct_assignment, vec1]
  rw [h, myf_eval]

/-- `generate_true_polys` for this instance is the one-element list `[myP]`,
whatever the challenge vector is. -/
lemma generate_eq (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0)
    (ch : Vector F5 (1 + 2 * 0)) :
    generate_true_polys (myf alpha q g0 g1) ch = [myP alpha q g0 g1] := by
  simp only [generate_true_polys, myP, List.ofFn_succ, List.ofFn_zero]
  congr 1

/-- The gate table's multilinear extension is the constant `1`, for every `beta`: the single
gate has coefficient `1`, so `prep_v` never substitutes. -/
lemma myAC_quad_aux (b : F5) :
    (quadMle (logv := 0) (logw := 0) 1 1 (fun _ _ _ => (1 : F5)) b) = myQuad () := by
  funext g l r
  simp [quadMle, prepV, myQuad]

/-- The wire vector's multilinear extension is the constant `1`. -/
lemma myAC_w_aux :
    (fun (g : Vector F5 0) (_cp : Vector F5 1) =>
      wMle (ninp := 1) (logw := 0) 0 (fun _ => (0 : F5)) (fun _ => (1 : F5)) g) = myW () := by
  funext g cp
  simp [wMle, wCol, myW]

/--
The arithmetized circuit.  `eval` is identically `false`: **every** witness fails,
which is precisely the regime the old formulation could not express.
-/
noncomputable def myAC : ArithmetizedCircuit Unit Unit Unit 2 1 1 1 0 0 0 1 F5 where
  eval := fun _ _ _ => false
  -- one gate, with coefficient `1`: not an assert-zero gate, so `beta` never appears
  gate_v := fun _ _ _ _ => 1
  -- `npub = 0`: no public wires here
  pub_col := fun _ _ _ => 0
  priv_col := fun _ _ _ => 1
  arith := by
    intro c inp w q g0 g1 _
    cases c; cases inp; cases w
    rintro ⟨h0, -, -, -⟩
    rw [show (quadMle (logv := 0) (logw := 0) 1 1 (fun _ _ _ => (1 : F5)) 0) = myQuad () from
          myAC_quad_aux 0,
        show (fun (g : Vector F5 0) (_cp : Vector F5 1) =>
            wMle (ninp := 1) (logw := 0) 0 (fun _ => (0 : F5)) (fun _ => (1 : F5)) g)
          = myW () from myAC_w_aux] at h0
    rw [my_layer_claim] at h0
    norm_num at h0

@[simp] lemma myAC_quad_eq (b : F5) : myAC.Quad_mle () b = myQuad () :=
  myAC_quad_aux b

@[simp] lemma myAC_w_eq : myAC.W_mle () () = myW () :=
  myAC_w_aux

/-! ## The protocol run

One sample point.  The verifier accepts, the Ligero extractor succeeds, every
Ligero constraint holds (the extracted pad is zero and the committed column is `1`), and
yet the extracted witness does not satisfy the circuit — a genuine soundness failure,
correctly accounted for by `eps_sumcheck = 1`.
-/

/-- The cheating prover's round: it transmits `tr[0] = tr[2] = 0`.  With a zero pad the
unpadded round polynomial is `⟨0, 0, 0⟩`, which passes the round check `p(0) + p(1) = 0`
even though the honest polynomial has `P(0) + P(1) = 1`. -/
noncomputable def cheatRound : RoundData 1 F5 :=
  { tr0 := 0, tr2 := 0, pp0 := 0, pp2 := 0, chal := 1 }

/-- The encrypted transcript: one `ConstraintBuilder` round.  The masked hand evaluations
`wc0`, `wc1` are `1`, matching the honest evaluations of the committed column; the single
challenge is `r = 1`, the root of the cheating polynomial minus `myP`. -/
noncomputable def myT : Unit → EncTranscript 1 F5 := fun _ =>
  { rounds := [cheatRound], wc0 := 1, wc1 := 1 }

@[simp] lemma my_chal (ω : Unit) : (myT ω).challenges = [1] := rfl

/-- The `known` part of the builder's expression is zero: every term it accumulates is a
multiple of a transmitted value, and this prover transmits zeros. -/
@[simp] lemma my_e_known (ω : Unit) : ((myT ω).e).1 = 0 := by
  simp [myT, EncTranscript.e, builder_run, builder_next, cheatRound,
        Expression.axpy, Expression.axmy, Expression.scale, Expression.zero]

/-- The Ligero extractor: always succeeds, returning the zero pad. -/
noncomputable def myE : Unit → Option (AugmentedWitness 1 F5 Unit) :=
  fun _ => some ((), fun _ => 0)

/-- The verifier accepts. -/
def myAccepts : Unit → Prop := fun _ => True

/-- The extractor pins down the pad. -/
lemma myE_pad (ω : Unit) (w : Unit) (p : Pad 1 F5) (h : myE ω = some (w, p)) :
    p = fun _ => 0 := by
  simp only [myE] at h
  injection h with h1
  exact (congrArg (Prod.snd : Unit × Pad 1 F5 → Pad 1 F5) h1).symm

/-- `EQ[Q,C]` vanishes at this transcript's copy challenge, so the layer's `EQQ` is `0`. -/
lemma my_eqq_zero : layer_eqq myAC () 0 0 (vec1 0) v0 v0 [1] = 0 := by
  have h : eq_matrix_mle 2 1 (vec1 0)
      (challenge_split (logw := 0) (logc := 1) ([1] : List F5)).1 = 0 := by
    rw [eq_matrix_21]
    simp [challenge_split, extract_vars, vec1]
  simp only [layer_eqq]
  rw [h, zero_mul]

/-- Every Ligero constraint holds for the extracted (zero) pad and committed column. -/
theorem my_ligero :
    IsLigeroKnowledgeSound (Ω := Unit) (Input := Unit) myAC myAccepts myT () () ()
      0 0 (vec1 0) v0 v0 0 0 0 myE 0 where
  extraction_bound := by
    have : Event_A (Witness := Unit) myAccepts myE = ∅ := by
      ext ω; simp [Event_A, myE]
    simp [event_card, this]
  layer_constraint := by
    rintro ω w p _ h
    have hp := myE_pad ω w p h
    subst hp
    refine ⟨?_, by simp⟩
    show (∑ i, _ * (0:F5)) = _
    simp [builder_finalize, my_chal, my_eqq_zero, my_e_known]
  input_row := by
    rintro ω w p _ h
    have hp := myE_pad ω w p h
    subst hp
    cases w
    simp [ligero_input_row, pubBinding, privIdx, input_row_coeffs,
      ArithmetizedCircuit.W_col, wCol, myAC, myT]

theorem my_wf : IsWellFormedTranscript (Ω := Unit) (logw := 0) (logc := 1) myAccepts myT where
  round_count := by intro ω _; simp [myT]

/-- The bad event has exactly one point, so `eps_sumcheck = 1` (and no smaller). -/
theorem my_ci :
    IsSumcheckCorrelationIntractable (Input := Unit) myAC myAccepts myT 0 0 () () myE 0 0 (vec1 0) v0 v0 1 where
  ci_bound := by
    dsimp [event_card]
    refine le_trans (Finset.card_le_univ _) ?_
    simp

/-!
## The payoff

Every hypothesis of `core_soundness_theorem` is discharged, for a circuit that
rejects every witness.  The theorem is therefore not vacuous.
-/
/-- The alpha-bad event is empty on this instance: the honest and claimed evaluations agree,
so the first disjunct of `InputBindingBad` is false. -/
theorem my_alpha_ok :
    event_card (Event_AlphaBad myAC myAccepts () 0 0 0 myT myE) ≤ 0 := by
  have h : Event_AlphaBad myAC myAccepts () 0 0 0 myT myE = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, p, hE, hbad⟩ := hω
      have hp := myE_pad ω w p hE
      subst hp
      cases w
      simp [InputBindingBad, true_evals, myAC_w_eq, myW, myT] at hbad
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

/-- The degenerate-randomness event is empty here: the layer claim is `1 + alpha = 1 ≠ 0`. -/
theorem my_deg_ok :
    event_card (Event_Degenerate myAC myAccepts () () 0 0 (vec1 0) v0 v0 myE) ≤ 0 := by
  have h : Event_Degenerate myAC myAccepts () () 0 0 (vec1 0) v0 v0 myE = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, p, -, hdeg⟩ := hω
      cases w
      rw [ArithmetizedCircuit.Degenerate] at hdeg
      simp only [myAC_quad_eq, myAC_w_eq] at hdeg
      rw [my_layer_claim] at hdeg
      norm_num at hdeg
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

theorem soundness_applies :
    event_card (Event_Fail myAC myAccepts () () 0 0 (vec1 0) v0 v0 0 0 myT myE) ≤ 0 + 0 + 0 + 1 :=
  core_soundness_theorem (eps_FSK := 0) (eps_sumcheck := 1) myAC myAccepts () () ()
    0 0 (vec1 0) v0 v0 0 0 0 myT myE (by omega) my_ligero 0 0 my_alpha_ok my_deg_ok
    my_wf my_ci

/-- And the bound is not trivially satisfied by an empty failure event: this
prover really does break soundness on this instance. -/
theorem failure_event_nonempty :
    Event_Fail myAC myAccepts () () 0 0 (vec1 0) v0 v0 0 0 myT myE = Finset.univ := by
  ext ω
  simp only [Event_Fail, Finset.mem_filter, Finset.mem_univ, true_and, iff_true]
  refine ⟨trivial, Or.inr ⟨(), ?_, rfl⟩⟩
  have hcheck := extractor_soundness_bridge my_ligero ω () (fun _ => 0) trivial rfl
    (by
      cases ω
      simp [InputBindingBad, true_evals, myAC_w_eq, myW, myT])
  simp [E_prime, myE, hcheck]

/-!
## The layered circuit for the multi-layer runs

`layers.lean` and `zk_layers.lean` are only worth anything if `LayeredCircuit` has
inhabitants for which the claims can actually be *wrong*.  Here is one, over the same field:
`logc = 1`, `logw = 0` (one sumcheck round per layer), all wire values and `QUAD` zero.

Degenerate as an arithmetization, but enough to show the layer machinery applies.
-/

/-- With `QUAD ≡ 0` the layer polynomial is identically zero. -/
lemma zero_layer_poly (alpha : F5) (st : LayerState 0 1 F5) (v : Vector F5 (1 + 2 * 0)) :
    layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => (0 : F5)) (fun _ _ => (0 : F5)) alpha st v = 0 := by
  simp [layer_poly_of, layer_sumcheck_poly_concat, layer_sumcheck_poly]

/-- Everything zero: `V ≡ 0`, `QUAD ≡ 0`. -/
noncomputable def myLC : LayeredCircuit Unit 1 1 0 1 F5 where
  V := fun _ _ _ _ => 0
  Quad := fun _ _ _ _ => 0
  layer_rel := by
    intro ly w alpha st
    simp [zero_layer_poly]

/-!
## A ZK proof driving the layer loop

`zk_layers.lean` is only worth anything if `ZkLayerRow` is satisfiable at every layer of a
run whose claims are wrong.  Here is a two-layer instance over the same degenerate
`LayeredCircuit`: the pad is zero, `EQQ` is zero (because `QUAD` is), and the incoming claim
of `1` is carried by the builder's starting expression.

The round challenge is `0`, which is a root of the middle Lagrange coefficient
`lag1(r) = r(r − pt2)/(1 − pt2)` — so the builder's known part stays `0` and the
`finalize` row is satisfied.
-/

/-- One `ConstraintBuilder` round transmitting zeros, with challenge `0`. -/
noncomputable def zkRound : RoundData 1 F5 :=
  { tr0 := 0, tr2 := 0, pp0 := 0, pp2 := 0, chal := 0 }

/-- One ZK layer: masked evaluations `(1, 0)`, no combination (`alpha = 0`). -/
noncomputable def zkL : ZkLayer 1 F5 :=
  { rounds := [zkRound], wc0 := 1, wc1 := 0, alpha := 0, dwL := 0, dwR := 0, dwLR := 0 }

/-- The sumcheck state the run sits at: a claim of `1` where the honest wire value is `0`. -/
noncomputable def zkST : LayerState 0 1 F5 :=
  { claim0 := 1, claim1 := 0, q := vec1 0, g0 := v0, g1 := v0 }

lemma zk_next_state (cl : F5) :
    next_state (zkL.toLayerData (logw := 0) (logc := 1) (fun _ => 0) cl) = zkST := by
  rw [next_state, zkST]
  congr 1

/-- The builder's starting expression carries the incoming claim, and the `finalize` row
holds because `EQQ = 0` and the builder's known part is `0`. -/
lemma zk_row (ly : ℕ) : ZkLayerRow myLC (fun _ => (0 : F5)) ly zkST zkL := by
  refine ⟨((1 : F5), fun _ => 0), ?_, ?_, ?_⟩
  · simp [evaluates_to, zkST, zkL]
  · show (∑ i, _ * (0 : F5)) = _
    simp [builder_finalize, zkL, builder_run, builder_next, zkRound,
          Expression.axpy, Expression.axmy, Expression.scale,
          lag_coeffs, LayeredCircuit.eqq, myLC]
  · simp

lemma zk_rows_hold : ZkRowsHold myLC (fun _ => (0 : F5)) 0 zkST [zkL, zkL] := by
  refine ⟨zk_row 0, ?_, trivial⟩
  rw [zk_next_state]
  exact zk_row 1

/-- The whole two-layer ZK proof drives `VerifierLayers::layers` to accept. -/
theorem zk_layers_verify_applies :
    verify_layers myLC 0 zkST (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL])
      = some (zkFinalState (fun _ => (0 : F5)) zkST [zkL, zkL]) :=
  zk_layers_verify myLC (fun _ => 0) [zkL, zkL] 0 zkST zk_rows_hold

/-- Both layers of the run carry the same data. -/
lemma zk_datas_two :
    zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL]
      = [zkL.toLayerData (logw := 0) (logc := 1) (fun _ => 0)
            (zkST.claim0 + zkL.alpha * zkST.claim1),
         zkL.toLayerData (logw := 0) (logc := 1) (fun _ => 0)
            (zkST.claim0 + zkL.alpha * zkST.claim1)] := by
  rw [zkLayerDatas, zk_next_state, zkLayerDatas, zk_next_state, zkLayerDatas]

/-- The two-layer run has the shape the verifier reads: one round polynomial and one
challenge per sumcheck variable. -/
lemma zk_shape_ok : LayersShapeOK (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL]) := by
  rw [zk_datas_two]
  intro ld hld
  have hform : ld = zkL.toLayerData (logw := 0) (logc := 1) (fun _ => 0)
      (zkST.claim0 + zkL.alpha * zkST.claim1) := by
    rcases List.mem_cons.mp hld with h | h
    · exact h
    · rcases List.mem_cons.mp h with h2 | h2
      · exact h2
      · cases h2
  subst hform
  exact ⟨by simp [ZkLayer.toLayerData, zkL, run_polys, zkRound],
         by simp [ZkLayer.toLayerData, zkL, run_challenges, zkRound]⟩

/-- No layer's combination coefficient is unlucky. -/
lemma zk_good_randomness :
    GoodRandomness myLC () 0 zkST (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL]) := by
  rw [zk_datas_two]
  refine ⟨?_, ?_, trivial⟩
  · rintro ⟨-, hEq⟩
    simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq
  · rw [zk_next_state]
    rintro ⟨-, hEq⟩
    simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq

/-- The claims the run starts from are wrong: the honest wire value is `0`, not `1`. -/
lemma zk_claims_wrong (w : Unit) : ¬ ClaimsCorrect myLC 0 w zkST := by
  rintro ⟨h0, -⟩
  simp [zkST, myLC] at h0

/-- And the multi-layer soundness reduction applies to it: the run's claims are wrong, so
the prover was lucky somewhere or the input-layer claims are wrong. -/
theorem zk_multi_layer_soundness_applies :
    AnyLayerRoundBad myLC () 0 zkST (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL])
      ∨ ¬ ClaimsCorrect myLC [zkL, zkL].length ()
          (zkFinalState (fun _ => (0 : F5)) zkST [zkL, zkL]) :=
  zk_multi_layer_soundness myLC (fun _ => 0) () (by omega) [zkL, zkL] zkST
    zk_rows_hold zk_shape_ok zk_good_randomness (zk_claims_wrong ())

/--
**The sumcheck term is necessary, not padding.**

The other three error terms are provably `0` on this instance (`my_ligero.extraction_bound`,
`my_alpha_ok`, `my_deg_ok`), and the failure event has a point.  So *any* `eps_sumcheck` for
which the correlation-intractability bound holds must be at least `1`: this cheating prover
really does get away with it, and no sharper analysis of the other three terms could hide
that.
-/
theorem eps_sumcheck_forced (e : ℕ)
    (ci : IsSumcheckCorrelationIntractable (Input := Unit) myAC myAccepts myT 0 0 () () myE
            0 0 (vec1 0) v0 v0 e) :
    1 ≤ e := by
  have h := core_soundness_theorem (eps_FSK := 0) (eps_sumcheck := e) myAC myAccepts () () ()
    0 0 (vec1 0) v0 v0 0 0 0 myT myE (by omega) my_ligero 0 0 my_alpha_ok my_deg_ok my_wf ci
  rw [failure_event_nonempty] at h
  simpa [event_card] using h

/-!
## A `logv ≥ 1` layer polynomial

Every other instance in this file has `logv = 0`, where `Vector F 0` is a singleton.  That
makes the *gate corner* sum and a sum over all of `F^logv` coincide — and hides the
difference between them.  They are not the same for `logv ≥ 1`: summing over `F^logv` would
make the layer polynomial *identically zero* over any prime field with `|F| > 3`, because
`∑_{x ∈ F} x = ∑_{x ∈ F} x² = 0` there, so every `eq`-orthogonality sum collapses.  That
would silently force `eval ≡ true` and make the whole development vacuous.

`layer_sumcheck_poly` therefore sums over the `nv` gate corners, matching `bind_g`
(`quad.h:L153`).  This instance is the guard: at `logv = 1` the layer polynomial is *not*
zero.
-/

/-- Two gates at `logv = 1`, one hand wire, all coefficients `1`. -/
noncomputable def gQ : Vector F5 1 → Vector F5 1 → Vector F5 1 → F5 :=
  quadMle 2 2 (fun _ _ _ => (1 : F5)) 1

/-- **Regression guard.**  With the corner sum this is non-zero; with a sum over all of
`F^logv` it would be `0`, and `arith` would be unsatisfiable for every `logv ≥ 1` circuit. -/
theorem logv_one_poly_ne_zero :
    layer_sumcheck_poly (nc := 2) (nv := 2) (logc := 1) gQ (fun _ _ => (1 : F5)) 1
      (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0))
      (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0))
      ≠ 0 := by decide

/-!
## The merged multi-layer statement

`multi_layer_core_soundness` (`zk_soundness.lean`) is the join: the Ligero extractor, the
per-layer randomness, the per-layer sumcheck rounds and the input binding, all carried
through a multi-layer run.  This instantiates it on the two-layer ZK run above, with a
circuit that rejects every witness.

Two of the four error terms come out at `0` here — the extractor never fails, and no layer's
coefficient is unlucky — so the bound is `2·eps_round + eps_bind`.
-/

/-- The extractor never fails, so `Event_A` is empty. -/
lemma zk_extract_ok : event_card (Event_A (Witness := Unit) myAccepts myE) ≤ 0 := by
  have h : Event_A (Witness := Unit) myAccepts myE = ∅ := by ext ω; simp [Event_A, myE]
  simp [event_card, h]

/-- No layer's coefficient is unlucky, at any index. -/
lemma zk_rand_ok (i : ℕ) :
    event_card (MEvent_RandAt myLC myAccepts zkST (fun _ => [zkL, zkL]) myE i) ≤ 0 := by
  have h : MEvent_RandAt myLC myAccepts zkST (fun _ => [zkL, zkL]) myE i = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, pad, hE, hbad⟩ := hω
      have hp := myE_pad ω w pad hE
      subst hp
      cases w
      exact absurd hbad (goodRandomness_not_badAt myLC () _ 0 zkST zk_good_randomness i)
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

/-- **The merged bound applies.**  Every hypothesis of `multi_layer_core_soundness` is
discharged for a two-layer run whose extracted witness fails the circuit. -/
theorem multi_layer_soundness_applies :
    event_card (MEvent_Fail (Ω := Unit) (M := 1) (F := F5) myAccepts
        (fun _ _ _ => false) () () myE)
      ≤ 0 + 2 * 0 + 2 * 1 + 1 :=
  multi_layer_core_soundness myLC myAccepts zkST (fun _ => [zkL, zkL]) myE
    (fun _ _ _ => false) () () 2 0 0 1 1 (by omega) (fun _ => by simp)
    (fun ω w pad _ hE => by
      have hp := myE_pad ω w pad hE
      subst hp
      exact zk_shape_ok)
    (fun w _ => zk_claims_wrong w) zk_extract_ok
    (fun ω w pad _ hE => by
      have hp := myE_pad ω w pad hE
      subst hp
      cases w
      exact zk_rows_hold)
    (fun i _ => zk_rand_ok i)
    (fun _ _ => le_trans (Finset.card_le_univ _) (by simp))
    (le_trans (Finset.card_le_univ _) (by simp))

/-- And the failure event is everything: this run really does break soundness. -/
theorem multi_layer_failure_nonempty :
    MEvent_Fail (Ω := Unit) (M := 1) (F := F5) myAccepts (fun _ _ _ => false) () () myE
      = Finset.univ := by
  ext ω
  simp only [MEvent_Fail, Finset.mem_filter, Finset.mem_univ, true_and, iff_true]
  exact ⟨trivial, Or.inr ⟨(), fun _ => 0, rfl, by simp⟩⟩

end LfzkExample
