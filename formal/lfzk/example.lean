import lfzk
import layers
import zk_layers

open Classical Polynomial Finset

set_option autoImplicit false
set_option relaxedAutoImplicit false

/-!
# Non-vacuity witness for `core_soundness_theorem`

`core_soundness_theorem` is an implication.  It says nothing unless its hypotheses
are jointly satisfiable *in the regime it is about*, namely with an
`ArithmetizedCircuit` whose `eval` can return `false`.

This file builds such an instance explicitly and applies the theorem to it:

* field `ZMod 5`, sample space `Unit`, pad width `M = 1`;
* `logc = 1`, `logw = 0`, `logv = 0`, `nc = nv = 1`, so exactly one sumcheck round;
* `eval` is identically `false` — every witness fails the circuit;
* the prover's round polynomial is a *lie* that the verifier nevertheless accepts,
  so `Event_Fail` is genuinely non-empty and the bound `eps_FSK + eps_sumcheck`
  is actually doing work.

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

/-! ## `Vector` plumbing

Mathlib has no `Fintype` instance for core `Vector`, but `ArithmetizedCircuit`
requires one, so we supply it via the obvious equivalence with `Fin n → F`. -/

def vecEquiv (F : Type) (n : ℕ) : Vector F n ≃ (Fin n → F) where
  toFun v := v.get
  invFun f := Vector.ofFn f
  left_inv v := by ext i hi; simp [Vector.get]
  right_inv f := by funext i; simp

noncomputable instance vecFintype (F : Type) [Fintype F] (n : ℕ) : Fintype (Vector F n) :=
  Fintype.ofEquiv _ (vecEquiv F n).symm

instance vecUnique0 (F : Type) : Unique (Vector F 0) where
  default := Vector.ofFn (fun i => i.elim0)
  uniq v := by ext i hi; omega

lemma sum_vec0 {F : Type} [Fintype F] {M : Type} [AddCommMonoid M]
    (g : Vector F 0 → M) (v0 : Vector F 0) : ∑ v : Vector F 0, g v = g v0 := by
  rw [Fintype.sum_unique]
  congr 1
  ext i hi
  omega

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
        myQuad, myW, eq_matrix_10, eq_matrix_21]

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

/--
The arithmetized circuit.  `eval` is identically `false`: **every** witness fails,
which is precisely the regime the old formulation could not express.
-/
noncomputable def myAC : ArithmetizedCircuit Unit Unit Unit 2 1 1 0 0 1 F5 where
  eval := fun _ _ _ => false
  Quad_mle := myQuad
  W_mle := myW
  W_col := myWcol
  W_mle_is_mle := by intro w g copy; simp [myW, myWcol]
  arith := by
    intro c inp w q g0 g1 _
    cases c; cases inp; cases w
    left
    rw [my_layer_claim]
    norm_num

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
lemma my_eqq_zero : layer_eqq myAC () 0 (vec1 0) v0 v0 [1] = 0 := by
  have h : eq_matrix_mle 2 1 (vec1 0)
      (challenge_split (logw := 0) (logc := 1) ([1] : List F5)).1 = 0 := by
    rw [eq_matrix_21]
    simp [challenge_split, extract_vars, vec1]
  simp only [layer_eqq]
  rw [h, zero_mul]

/-- Every Ligero constraint holds for the extracted (zero) pad and committed column. -/
theorem my_ligero :
    IsLigeroKnowledgeSound (Ω := Unit) (Input := Unit) myAC myAccepts myT () 0 (fun _ => 0)
      0 (vec1 0) v0 v0 0 0 0 myE 0 where
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
    simp [ligero_input_row, privIdx, input_row_coeffs, myAC, myWcol, myT]
  pub_consistent := by
    rintro ω w p _ h
    simp [privIdx]
theorem my_wf : IsWellFormedTranscript (Ω := Unit) (logw := 0) (logc := 1) myAccepts myT where
  round_count := by intro ω _; simp [myT]

/-- The bad event has exactly one point, so `eps_sumcheck = 1` (and no smaller). -/
theorem my_ci :
    IsSumcheckCorrelationIntractable (Input := Unit) myAC myAccepts myT 0 0 () myE 0 (vec1 0) v0 v0 1 where
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
    event_card (Event_AlphaBad myAC myAccepts 0 0 0 myT myE) ≤ 0 := by
  have h : Event_AlphaBad myAC myAccepts 0 0 0 myT myE = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [Event_AlphaBad, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, p, hE, hbad⟩ := hω
      have hp := myE_pad ω w p hE
      subst hp
      cases w
      simp [InputBindingBad, true_evals, myAC, myW, myT] at hbad
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

/-- The degenerate-randomness event is empty here: the layer claim is `1 + alpha = 1 ≠ 0`. -/
theorem my_deg_ok :
    event_card (Event_Degenerate myAC myAccepts () 0 (vec1 0) v0 v0 myE) ≤ 0 := by
  have h : Event_Degenerate myAC myAccepts () 0 (vec1 0) v0 v0 myE = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [Event_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, p, -, hdeg⟩ := hω
      cases w
      have hA : layer_claim (nc := 2) (nv := 1) (myAC.Quad_mle ()) (myAC.W_mle ()) 0
          (vec1 0) v0 v0 = 1 := my_layer_claim 0 (vec1 0) v0 v0
      have h2 := hdeg.2
      rw [hA] at h2
      exact absurd h2 (by simp)
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

theorem soundness_applies :
    event_card (Event_Fail myAC myAccepts () () 0 (vec1 0) v0 v0 0 0 myT myE) ≤ 0 + 0 + 0 + 1 :=
  core_soundness_theorem (eps_FSK := 0) (eps_sumcheck := 1) myAC myAccepts () () 0 (fun _ => 0)
    0 (vec1 0) v0 v0 0 0 0 myT myE (by omega) my_ligero 0 0 my_alpha_ok my_deg_ok my_wf my_ci

/-- And the bound is not trivially satisfied by an empty failure event: this
prover really does break soundness on this instance. -/
theorem failure_event_nonempty :
    Event_Fail myAC myAccepts () () 0 (vec1 0) v0 v0 0 0 myT myE = Finset.univ := by
  ext ω
  simp only [Event_Fail, Finset.mem_filter, Finset.mem_univ, true_and, iff_true]
  refine ⟨trivial, Or.inr ⟨(), ?_, rfl⟩⟩
  have hcheck := extractor_soundness_bridge my_ligero ω () (fun _ => 0) trivial rfl
    (by
      cases ω
      simp [InputBindingBad, true_evals, myAC, myW, myT])
  simp [E_prime, myE, hcheck]

/-!
## A multi-layer run

`layers.lean` is only worth anything if `LayeredCircuit` has inhabitants for which the
claims can actually be *wrong*.  Here is one, over the same field: `logc = 1`, `logw = 0`
(one sumcheck round per layer), all wire values and `QUAD` zero.

Degenerate as an arithmetization, but it is enough to show the layer machinery applies:
the state entering layer 0 carries a claim of `1` where the honest value is `0`, and
`layers_reduction` fires on a two-layer run.
-/

/-- With `QUAD ≡ 0` the layer polynomial is identically zero. -/
lemma zero_layer_poly (alpha : F5) (st : LayerState 0 1 F5) (v : Vector F5 (1 + 2 * 0)) :
    layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => (0 : F5)) (fun _ _ => (0 : F5)) alpha st v = 0 := by
  simp [layer_poly_of, layer_sumcheck_poly_concat, layer_sumcheck_poly]

/-- ... so the honest round polynomials are the single zero polynomial. -/
lemma zero_true_polys (alpha : F5) (st : LayerState 0 1 F5) (chal : List F5) :
    layer_true_polys_of (nc := 1) (nv := 1) (fun _ _ _ => (0 : F5)) (fun _ _ => (0 : F5)) alpha st chal
      = [(0 : Polynomial F5)] := by
  simp only [layer_true_polys_of, generate_true_polys, List.ofFn_succ, List.ofFn_zero,
             sumcheck_round_poly, sumcheck_eval_round, zero_layer_poly]
  simp

/-- Everything zero: `V ≡ 0`, `QUAD ≡ 0`. -/
noncomputable def myLC : LayeredCircuit Unit 1 1 0 1 F5 where
  V := fun _ _ _ _ => 0
  Quad := fun _ _ _ _ => 0
  layer_rel := by
    intro ly w alpha st
    simp [zero_layer_poly]

/-- The prover's round polynomial for a layer: claims `1`, which the round check accepts
because `1 + 0 = 1` is the incoming combined claim, and which the challenge `r = 1` lets
through because `p(1) = 0 = V(1)`. -/
def layerPoly : RoundPoly F5 := ⟨1, 0, 0⟩

noncomputable def myLD : LayerData 0 1 F5 :=
  { polys := [layerPoly], challenges := [1], wc0 := 1, wc1 := 0, alpha := 0 }

/-- The state entering layer 0: a claim of `1` where the honest wire value is `0`.
It is also the state the run returns to, so the same data works for every layer. -/
noncomputable def myST : LayerState 0 1 F5 :=
  { claim0 := 1, claim1 := 0, q := vec1 1, g0 := v0, g1 := v0 }

lemma vec0_eq (a b : Vector F5 0) : a = b := by ext i hi; omega

lemma myLD_next : next_state myLD = myST := by
  rw [next_state, myST]
  congr 1

lemma my_verify_layer (ly : ℕ) : verify_layer myLC ly myST myLD = some myST := by
  rw [verify_layer_some_iff]
  refine ⟨myLD_next.symm, ?_⟩
  simp [myLD, myST, verify_multi_round, check_round_c, layerPoly,
        LayeredCircuit.eqq, myLC]

/-- A two-layer run the verifier accepts. -/
lemma my_verify_layers : verify_layers myLC 0 myST [myLD, myLD] = some myST := by
  simp [verify_layers, my_verify_layer]

/-- The claims are wrong on the way in — the honest wire value is `0`, not `1`. -/
lemma my_claims_wrong (ly : ℕ) : ¬ ClaimsCorrect myLC ly () myST := by
  rintro ⟨h0, -⟩
  simp [myST, myLC] at h0

/-- `layers_reduction` applies: the run is accepted, the shape is right, no unlucky
`alpha`, and the starting claims are wrong. -/
theorem layers_reduction_applies :
    AnyLayerRoundBad myLC () 0 myST [myLD, myLD] ∨
      ¬ ClaimsCorrect myLC (0 + [myLD, myLD].length) () myST := by
  refine layers_reduction myLC () (by omega) [myLD, myLD] 0 myST myST
    my_verify_layers ?_ ?_ (my_claims_wrong 0)
  · intro ld hld
    rcases List.mem_cons.mp hld with rfl | hld
    · exact ⟨by simp [myLD], by simp [myLD]⟩
    · rcases List.mem_cons.mp hld with rfl | hld
      · exact ⟨by simp [myLD], by simp [myLD]⟩
      · cases hld
  · refine ⟨?_, ?_, trivial⟩
    · rintro ⟨-, hEq⟩
      simp [myLC, myST, myLD] at hEq
    · rw [myLD_next]
      rintro ⟨-, hEq⟩
      simp [myLC, myST, myLD] at hEq

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

/-- And the multi-layer soundness reduction applies to it: the run's claims are wrong, so
the prover was lucky somewhere or the input-layer claims are wrong. -/
theorem zk_multi_layer_soundness_applies :
    AnyLayerRoundBad myLC () 0 zkST (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL])
      ∨ ¬ ClaimsCorrect myLC [zkL, zkL].length ()
          (zkFinalState (fun _ => (0 : F5)) zkST [zkL, zkL]) := by
  refine zk_multi_layer_soundness myLC (fun _ => 0) () (by omega) [zkL, zkL] zkST
    zk_rows_hold ?_ ?_ ?_
  · rw [zk_datas_two]
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
  · rw [zk_datas_two]
    refine ⟨?_, ?_, trivial⟩
    · rintro ⟨-, hEq⟩
      simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq
    · rw [zk_next_state]
      rintro ⟨-, hEq⟩
      simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq
  · rintro ⟨h0, -⟩
    simp [zkST, myLC] at h0

end LfzkExample
