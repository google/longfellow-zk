import lfzk
import instantiate
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

/-- The gate list of this circuit: a single ordinary gate with coefficient `1`. -/
def myGates : List (GateTerm F5) := [⟨0, 0, 0, 1⟩]

/-- Its multilinear extension is the constant `1`, for every `beta`: the one stored gate has
coefficient `1`, so `prep_v` never substitutes. -/
lemma myAC_quad_aux (b : F5) :
    (quadMle (logv := 0) (logw := 0) myGates b) = myQuad () := by
  funext g l r
  simp [quadMle, prepV, myQuad, myGates]

/-- The wire vector's multilinear extension is the constant `1`. -/
lemma myAC_w_aux :
    (fun (g : Vector F5 0) (_cp : Vector F5 1) =>
      wMle (ninp := 1) (logw := 0) 0 (fun _ => (0 : F5)) (fun _ => (1 : F5)) g) = myW () := by
  funext g cp
  simp [wMle, wCol, myW]

/--
The arithmetized circuit.  `eval` is identically `false`: **every** witness fails,
which is precisely the regime the sparse gate list has to express.
-/
noncomputable def myAC : ArithmetizedCircuit Unit Unit Unit 2 1 1 0 0 0 1 F5 where
  eval := fun _ _ _ => false
  -- one gate, with coefficient `1`: not an assert-zero gate, so `beta` never appears
  gates := fun _ => myGates
  -- `npub = 0`: no public wires here
  pub_col := fun _ _ _ => 0
  priv_col := fun _ _ _ => 1
  arith := by
    intro c inp w q g0 g1 _
    cases c; cases inp; cases w
    rintro ⟨h0, -, -, -⟩
    rw [show (quadMle (logv := 0) (logw := 0) myGates 0) = myQuad () from myAC_quad_aux 0,
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

/-- `EQ[Q,C]` vanishes at this transcript's copy challenge, so the layer's `EQQ` is `0` —
*whatever* the layer randomness is.  The copy factor sits outside the `alpha`/`beta` sum in
`layer_eqq`, so the vanishing is uniform in both. -/
lemma my_eqq_zero (a b : F5) : layer_eqq myAC () a b (vec1 0) v0 v0 [1] = 0 := by
  have h : eq_matrix_mle 2 1 (vec1 0)
      (challenge_split (logw := 0) (logc := 1) ([1] : List F5)).1 = 0 := by
    rw [eq_matrix_21]
    simp [challenge_split, extract_vars, vec1]
  simp only [layer_eqq]
  rw [h, zero_mul]

/-- Every Ligero constraint holds for the extracted (zero) pad and committed column.

All three challenges — the layer's `alpha` and `beta`, and the fresh input-binding `alpha_in`
— are `0` here, since `Ω = Unit`.  They are still supplied separately, so this instance also
witnesses that the three-challenge shape of the bundle is inhabited. -/
theorem my_ligero :
    IsLigeroKnowledgeSound (Ω := Unit) (Input := Unit) myAC myAccepts myT () () ()
      0 0 0 (vec1 0) v0 v0 0 0 0 myE 0 where
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
    0 0 0 (vec1 0) v0 v0 0 0 0 myT myE (by omega) my_ligero 0 0 my_alpha_ok my_deg_ok
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

/-- The layer polynomial of this instance, at a concrete point.  `QUAD ≡ 1` and
`V ly w g q = 1 − q₀`, which is what makes `layer_rel` hold with the claims the verifier
actually starts from. -/
lemma one_layer_poly (alpha : F5) (st : LayerState 0 1 F5) (v : Vector F5 (1 + 2 * 0)) :
    layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => (1 : F5))
        (fun _ q => 1 - q.get 0) alpha st v
      = (1 - st.q.get 0) * (1 + alpha) * (1 - v.get ⟨0, by omega⟩) ^ 3 := by
  simp [layer_poly_of, layer_sumcheck_poly_concat, extract_vars, layer_sumcheck_poly,
        eq_matrix_11]
  ring

/-- The layer polynomial for a *constant* `QUAD ≡ k`.  `one_layer_poly` is the `k = 1` case;
the general one is what lets `myLCb` below put `beta` itself in the `QUAD` slot. -/
lemma one_layer_poly_k (k alpha : F5) (st : LayerState 0 1 F5) (v : Vector F5 (1 + 2 * 0)) :
    layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => k) (fun _ q => 1 - q.get 0) alpha st v
      = k * ((1 - st.q.get 0) * (1 + alpha) * (1 - v.get ⟨0, by omega⟩) ^ 3) := by
  simp [layer_poly_of, layer_sumcheck_poly_concat, extract_vars, layer_sumcheck_poly,
        eq_matrix_11]
  ring

/-- Its hypercube sum, which is what `layer_rel` has to match. -/
lemma const_quad_claim (k alpha : F5) (st : LayerState 0 1 F5) :
    ∑ j ∈ Finset.range (2 ^ (1 + 2 * 0)),
        layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => k) (fun _ q => 1 - q.get 0) alpha st
          (boolean_vector j)
      = k * (1 - st.q.get 0) + alpha * (k * (1 - st.q.get 0)) := by
  have h0 : (boolean_vector 0 : Vector F5 (1 + 2 * 0)) = vec1 0 := by
    ext i hi; simp [boolean_vector, vec1, bit_value]
  have h1 : (boolean_vector 1 : Vector F5 (1 + 2 * 0)) = vec1 1 := by
    ext i hi
    have him : i = 0 := by omega
    subst him
    simp [boolean_vector, vec1, bit_value]
  have hr : Finset.range (2 ^ (1 + 2 * 0)) = Finset.range 2 := by norm_num
  rw [hr, Finset.sum_range_succ, Finset.sum_range_one, h0, h1,
      one_layer_poly_k, one_layer_poly_k]
  simp [vec1]
  ring

/-- `QUAD ≡ 1`, `V ly w g q = 1 − q₀`.  Unlike an all-zero instance this has a *non-zero*
output claim, so a run that starts from the verifier's initial claims of zero really does
start from wrong claims. -/
noncomputable def myLC : LayeredCircuit Unit 1 1 0 1 F5 where
  -- the wire values ignore the schedule: `QUAD` has no assert-zero gate here, so there is
  -- nothing for `prep_v` to substitute into
  V := fun _ _ _ _ q => 1 - q.get 0
  Quad := fun _ _ _ _ _ => 1
  Quad_affine_beta := by intro ly b g l r; ring
  V_local := by intro ly w betas betas' _; rfl
  layer_rel := by
    intro ly w alpha betas st
    rw [const_quad_claim 1 alpha st]
    ring

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
  { rounds := [zkRound], wc0 := 0, wc1 := 0, alpha := 0, dwL := 0, dwR := 0, dwLR := 0 }

/-- The run's beta schedule: `begin_layer` draws `0` at every layer.  For this `QUAD` the
choice is immaterial — there is no assert-zero gate — but it must be *supplied*, and the
wire values, the layer relation and the degeneracy count are all stated at it. -/
def zkBetas : ℕ → F5 := fun _ => 0

/-- The sumcheck state the run sits at: a claim of `1` where the honest wire value is `0`. -/
noncomputable def zkST : LayerState 0 1 F5 :=
  { claim0 := 0, claim1 := 0, q := vec1 0, g0 := v0, g1 := v0 }

lemma zk_next_state (cl : F5) :
    next_state (zkL.toLayerData (logw := 0) (logc := 1) (fun _ => 0) cl) = zkST := by
  rw [next_state, zkST]
  congr 1

/-- The rows hold at **the expression the verifier builds**, not at some convenient one.  At
layer 0 that is `Expression.zero`, so the first conjunct says the run starts from a zero
output claim — which is exactly how `claims_state.claim = [zero, zero]` initialises.  At an
interior layer it is `builder_first` on the previous layer's data, and the conjunct is then
`ZkLayer.first_matches_next_state`. -/
lemma zk_row (ly : ℕ) (prev : Option (ZkLayer 1 F5))
    (hprev : ∀ p, prev = some p → p = zkL) :
    ZkLayerRow myLC zkBetas (fun _ => (0 : F5)) ly zkST zkL (zkExpr prev zkL.alpha) := by
  -- both starting expressions have a zero *known* part: `Expression.zero` at layer 0, and
  -- `builder_first` on `wc = (0, 0)` at an interior layer
  have hknown : (zkExpr prev zkL.alpha).1 = 0 := by
    cases hp : prev with
    | none => simp [zkExpr, Expression.zero]
    | some p =>
      rw [hprev p hp]
      simp [zkExpr, builder_first, zkL, Expression.axpy, Expression.zero]
  refine ⟨?_, ?_, ?_⟩
  · show (zkExpr prev zkL.alpha).1 + _ = _
    rw [hknown]; simp [zkST, zkL]
  · show (∑ i, _ * (0 : F5)) = _
    simp [builder_finalize, zkL, builder_run, builder_next, zkRound,
      Expression.axpy, Expression.axmy, Expression.scale,
      lag_coeffs, LayeredCircuit.eqq, myLC]
  · simp

lemma zk_rows_hold : ZkRowsHold myLC zkBetas (fun _ => (0 : F5)) 0 zkST none [zkL, zkL] := by
  refine ⟨zk_row 0 none (by simp), ?_, trivial⟩
  rw [zk_next_state]
  exact zk_row 1 (some zkL) (by rintro p ⟨rfl⟩; rfl)

/-- The whole two-layer ZK proof drives `VerifierLayers::layers` to accept. -/
theorem zk_layers_verify_applies :
    verify_layers myLC zkBetas 0 zkST (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL])
      = some (zkFinalState (fun _ => (0 : F5)) zkST [zkL, zkL]) :=
  zk_layers_verify myLC zkBetas (fun _ => 0) [zkL, zkL] 0 zkST none zk_rows_hold

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
    GoodRandomness myLC () zkBetas 0 zkST
      (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL]) := by
  rw [zk_datas_two]
  refine ⟨?_, ?_, trivial⟩
  · rintro ⟨-, hEq⟩
    simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq
  · rw [zk_next_state]
    rintro ⟨-, hEq⟩
    simp [myLC, zkST, ZkLayer.toLayerData, zkL] at hEq

/-- The claims the run starts from are wrong: the honest wire value is `0`, not `1`. -/
lemma zk_claims_wrong (w : Unit) : ¬ ClaimsCorrect myLC 0 w zkBetas zkST := by
  rintro ⟨h0, -⟩
  simp [zkST, myLC] at h0

/-- And the multi-layer soundness reduction applies to it: the run's claims are wrong, so
the prover was lucky somewhere or the input-layer claims are wrong. -/
theorem zk_multi_layer_soundness_applies :
    AnyLayerRoundBad myLC () zkBetas 0 zkST
        (zkLayerDatas (fun _ => (0 : F5)) zkST [zkL, zkL])
      ∨ ¬ ClaimsCorrect myLC [zkL, zkL].length () zkBetas
          (zkFinalState (fun _ => (0 : F5)) zkST [zkL, zkL]) :=
  zk_multi_layer_soundness myLC zkBetas (fun _ => 0) () (by omega) [zkL, zkL] zkST
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
    0 0 0 (vec1 0) v0 v0 0 0 0 myT myE (by omega) my_ligero 0 0 my_alpha_ok my_deg_ok my_wf ci
  rw [failure_event_nonempty] at h
  simpa [event_card] using h

/-!
## The randomness schedule, instantiated

Everything above lives at `Ω = Unit`, where the three challenges are forced to be `0` and the
schedule is invisible.  `core_soundness_probability` is stated over the protocol's own sample
space instead —

```
(D × (F × F)) × F   =   commitment  ×  begin_layer's (beta, alpha)  ×  the fresh alpha_in
```

— and a witness at *that* shape is a genuinely separate obligation: the hypotheses now have to
hold for **every** value of all three challenges, and the transcript is allowed to depend on
the layer pair.

This instance discharges it at `D = Unit`, so `|Ω| = 125`.  The cheating prover of this file
gets away with it at every one of those points, for two structural reasons:

* `EQQ` vanishes at this transcript's copy challenge (`my_eqq_zero`), and the copy factor sits
  *outside* the `alpha`/`beta` sum in `layer_eqq` — so no choice of the layer pair repairs it;
* the input row balances identically in `alpha_in`, at `1 + alpha_in` on both sides.

The payoff is `probability_eps_sumcheck_forced`: the failure event is all of `Ω`, and the two
challenge-collision terms cost only `3/5`, so any admissible `eps_sumcheck` here is at least
`50` out of `125`.  The sumcheck term carries at least `2/5` of the bound on this instance and
cannot be absorbed into the randomness terms.
-/

/-- The sample space of `core_soundness_probability` at `D = Unit`: `125` points. -/
abbrev ProbΩ := (Unit × (F5 × F5)) × F5

/-- The verifier accepts, at every setting of the three challenges. -/
def probAccepts : ProbΩ → Prop := fun _ => True

/-- The prover's transcript.  Its type says it *may* depend on the layer pair — which is the
point of the restructuring — even though this particular prover ignores it. -/
noncomputable def probT : Unit × (F5 × F5) → EncTranscript 1 F5 := fun _ => myT ()

@[simp] lemma prob_chal (p : Unit × (F5 × F5)) : (probT p).challenges = [1] := rfl

@[simp] lemma prob_e_known (p : Unit × (F5 × F5)) : ((probT p).e).1 = 0 := my_e_known ()

/-- The Ligero bundle holds at every point of the three-challenge sample space. -/
theorem prob_ligero :
    IsLigeroKnowledgeSound (Ω := ProbΩ) (Input := Unit) myAC probAccepts
      (fun ω => probT ω.1) () () ()
      (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
      (vec1 0) v0 v0 0 0 0 (fun ω => myE ω.1.1) 0 where
  extraction_bound := by
    have h : Event_A (Witness := Unit) probAccepts (fun ω : ProbΩ => myE ω.1.1) = ∅ := by
      ext ω; simp [Event_A, myE]
    simp [event_card, h]
  layer_constraint := by
    rintro ω w p _ h
    have hp := myE_pad ω.1.1 w p h
    subst hp
    refine ⟨?_, by simp⟩
    show (∑ i, _ * (0:F5)) = _
    simp [builder_finalize, my_eqq_zero, probT]
  input_row := by
    rintro ω w p _ h
    have hp := myE_pad ω.1.1 w p h
    subst hp
    cases w
    simp [ligero_input_row, pubBinding, privIdx, input_row_coeffs,
      ArithmetizedCircuit.W_col, wCol, myAC, probT, myT]

theorem prob_wf :
    IsWellFormedTranscript (Ω := ProbΩ) (logw := 0) (logc := 1) probAccepts
      (fun ω => probT ω.1) where
  round_count := by intro ω _; simp [probT, myT]

/-- The failure event is *everything*: at every setting of the three challenges the verifier
accepts, the extractor succeeds, and the extracted witness fails the circuit. -/
theorem prob_failure_event :
    Event_Fail myAC probAccepts () () (fun ω : ProbΩ => ω.1.2.2) (fun ω => ω.1.2.1)
      (vec1 0) v0 v0 0 0 (fun ω => probT ω.1) (fun ω => myE ω.1.1) = Finset.univ := by
  ext ω
  simp only [Event_Fail, Finset.mem_filter, Finset.mem_univ, true_and, iff_true]
  refine ⟨trivial, Or.inr ⟨(), ?_, rfl⟩⟩
  have hcheck := extractor_soundness_bridge prob_ligero ω () (fun _ => 0) trivial rfl
    (by simp [InputBindingBad, true_evals, myAC_w_eq, myW, probT, myT])
  simp [E_prime, myE, hcheck]

/--
**The sumcheck term is at least `2/5` on this instance.**

`core_soundness_probability` reads `1 ≤ 0 + 3/5 + e/125` here, because the failure event is
all `125` points and Ligero extraction never fails.  So `e ≥ 50`.

This is the counterpart of `eps_sumcheck_forced` over the protocol's real sample space, and it
says something the `Unit` version cannot: the `3/|F|` charged for the three challenge
collisions is genuinely *not* enough to cover a cheating prover, even though the collisions are
now counted over all `125` challenge settings rather than a single point.
-/
theorem probability_eps_sumcheck_forced (e : ℕ)
    (ci : IsSumcheckCorrelationIntractable (Input := Unit) myAC probAccepts
            (fun ω : ProbΩ => probT ω.1) 0 0 () () (fun ω => myE ω.1.1)
            (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (vec1 0) v0 v0 e) :
    50 ≤ e := by
  have h := core_soundness_probability (D := Unit) (F := F5) 0 e myAC probAccepts () () ()
    (vec1 0) v0 v0 0 0 0 probT myE (by omega) (by simp) (by simp) prob_ligero prob_wf ci
  rw [prob_failure_event] at h
  have hcard : Fintype.card (ZMod 5) = 5 := by simp
  rw [hcard] at h
  simp only [event_card, Finset.card_univ, Fintype.card_prod, Fintype.card_unit, hcard] at h
  norm_num at h
  by_contra hlt
  have : (e : ℚ) < 50 := by exact_mod_cast Nat.lt_of_not_le hlt
  linarith

/-- The hypothesis of `probability_eps_sumcheck_forced` is satisfiable: the trivial bound
`|Ω| = 125` holds.  Without this the theorem above would be `False → 50 ≤ e`. -/
theorem prob_ci :
    IsSumcheckCorrelationIntractable (Input := Unit) myAC probAccepts
      (fun ω : ProbΩ => probT ω.1) 0 0 () () (fun ω => myE ω.1.1)
      (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (vec1 0) v0 v0 125 where
  ci_bound := by
    dsimp [event_card]
    refine le_trans (Finset.card_le_univ _) ?_
    simp

/-- So the admissible range on this instance is exactly `50 ≤ eps_sumcheck ≤ 125`, and it is
non-empty: neither `probability_eps_sumcheck_forced` nor `prob_ci` is vacuous. -/
example : 50 ≤ 125 := probability_eps_sumcheck_forced 125 prob_ci

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
  quadMle [⟨0, 0, 0, 1⟩, ⟨1, 1, 1, 1⟩] 1

/-- **Regression guard.**  With the corner sum this is non-zero; with a sum over all of
`F^logv` it would be `0`, and `arith` would be unsatisfiable for every `logv ≥ 1` circuit. -/
theorem logv_one_poly_ne_zero :
    layer_sumcheck_poly (nc := 2) (nv := 2) (logc := 1) gQ (fun _ _ => (1 : F5)) 1
      (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0))
      (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0)) (Vector.ofFn (fun _ => 0))
      ≠ 0 := by decide

/-!
## Absent gates versus assert-zero gates

`Quad<Field>` is *sparse*: `bind_g` iterates the stored terms (`quad.h:L171`, and
`for_each_term` in the Rust `hquad.rs`), applying `prep_v` to each.  So a triple that is
**absent** contributes nothing, while a stored term with coefficient **zero** is an
assert-zero gate and contributes `beta`.

A dense coefficient table cannot tell those apart — both read as `0` — and would give every
absent triple a phantom `beta`.  These two circuits differ *only* by the presence of a
zero-coefficient term, and they compute different polynomials.
-/

/-- One ordinary gate; the triple `(1,1,1)` is absent. -/
def gAbsent : List (GateTerm F5) := [⟨0, 0, 0, 1⟩]

/-- The same, plus an explicit assert-zero gate at `(1,1,1)`. -/
def gAssertZero : List (GateTerm F5) := [⟨0, 0, 0, 1⟩, ⟨1, 1, 1, 0⟩]

/-- **The sparse structure is load-bearing.**  An absent gate contributes `0`; an explicit
assert-zero gate contributes `beta`.  A dense table would conflate them. -/
theorem absent_ne_assert_zero :
    quadMle (logv := 1) (logw := 1) gAbsent 1 (Vector.ofFn (fun _ => 1))
        (Vector.ofFn (fun _ => 1)) (Vector.ofFn (fun _ => 1))
      ≠ quadMle (logv := 1) (logw := 1) gAssertZero 1 (Vector.ofFn (fun _ => 1))
        (Vector.ofFn (fun _ => 1)) (Vector.ofFn (fun _ => 1)) := by
  decide

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
    event_card (MEvent_RandAt myLC myAccepts (fun _ => zkBetas) zkST
      (fun _ => [zkL, zkL]) myE i) ≤ 0 := by
  have h : MEvent_RandAt myLC myAccepts (fun _ => zkBetas) zkST
      (fun _ => [zkL, zkL]) myE i = ∅ := by
    ext ω
    constructor
    · intro hω
      simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, pad, hE, hbad⟩ := hω
      have hp := myE_pad ω w pad hE
      subst hp
      cases w
      exact absurd hbad (goodRandomness_not_badAt myLC () zkBetas _ 0 zkST zk_good_randomness i)
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

/--
Layer 0's randomness is never degenerate here: the output claim is `1`, whatever the
challenges are.  `beta` plays no part in that, and by `degenerate_beta_independent` it could
not have.
-/
lemma zk_layer0_claim :
    layer_claim (nc := 1) (nv := 1) (myLC.Quad 0 (zkBetas 0)) (myLC.V 1 () zkBetas) 0
        zkST.q zkST.g0 zkST.g1 = 1 := by
  have hrel := myLC.layer_rel 0 () 0 zkBetas zkST
  rw [show (∑ j ∈ Finset.range (2 ^ (1 + 2 * 0)),
        layer_poly_of (nc := 1) (nv := 1) (myLC.Quad 0 (zkBetas 0)) (myLC.V 1 () zkBetas) 0 zkST
          (boolean_vector j))
      = layer_claim (nc := 1) (nv := 1) (myLC.Quad 0 (zkBetas 0)) (myLC.V 1 () zkBetas) 0
          zkST.q zkST.g0 zkST.g1
      from rfl] at hrel
  rw [hrel]
  simp [myLC, zkST, vec1]

lemma zk_deg_not : ¬ myLC.Degenerate () zkBetas 0 (zkBetas 0) zkST := by
  rw [LayeredCircuit.Degenerate, zk_layer0_claim]
  decide

lemma zk_deg_ok :
    event_card (MEvent_Degenerate myLC myAccepts (fun _ => zkBetas) zkST (fun _ => (0 : F5))
        myE (fun _ _ _ => false) () ()) ≤ 0 := by
  have h : MEvent_Degenerate myLC myAccepts (fun _ => zkBetas) zkST (fun _ => (0 : F5))
      myE (fun _ _ _ => false) () () = ∅ := by
    ext ω
    constructor
    · intro hω
      -- `ev ≡ false` here, so `simp` collapses that conjunct: five components, not six
      simp only [MEvent_Degenerate, Finset.mem_filter, Finset.mem_univ, true_and] at hω
      obtain ⟨-, w, pad, -, hdeg⟩ := hω
      cases w
      exact absurd hdeg zk_deg_not
    · intro hc; exact absurd hc (by simp)
  simp [event_card, h]

/-- **The merged bound applies.**  Every hypothesis of `multi_layer_core_soundness` is
discharged for a two-layer run whose extracted witness fails the circuit. -/
theorem multi_layer_soundness_applies :
    event_card (MEvent_Fail (Ω := Unit) (M := 1) (F := F5) myAccepts
        (fun _ _ _ => false) () () myE)
      ≤ 0 + 2 * 0 + 2 * 1 + 1 + 0 :=
  multi_layer_core_soundness myLC myAccepts (fun _ => zkBetas) zkST (fun _ => 0)
    (fun _ => [zkL, zkL]) myE
    (fun _ _ _ => false) () () 2 0 0 1 1 0 (by omega) (fun _ => by simp) rfl rfl
    (fun ω w pad _ hE => by
      have hp := myE_pad ω w pad hE
      subst hp
      exact zk_shape_ok)
    zk_extract_ok
    (fun ω w pad _ hE => by
      have hp := myE_pad ω w pad hE
      subst hp
      cases w
      exact zk_rows_hold)
    (fun i _ => zk_rand_ok i)
    (fun _ _ => le_trans (Finset.card_le_univ _) (by simp))
    (le_trans (Finset.card_le_univ _) (by simp))
    zk_deg_ok

/-- And the failure event is everything: this run really does break soundness. -/
theorem multi_layer_failure_nonempty :
    MEvent_Fail (Ω := Unit) (M := 1) (F := F5) myAccepts (fun _ _ _ => false) () () myE
      = Finset.univ := by
  ext ω
  simp only [MEvent_Fail, Finset.mem_filter, Finset.mem_univ, true_and, iff_true]
  exact ⟨trivial, Or.inr ⟨(), fun _ => 0, rfl, by simp⟩⟩

/-!
## `beta` bites: an assert-zero gate that the witness violates

Everything above has `QUAD ≡ 1` — an ordinary gate, nothing for `prep_v` to substitute into —
so `beta` never shows up in the arithmetic.  That leaves open the question the whole
schedule-indexed design exists to answer: *can* `beta` change anything?

`myLCb` is the smallest instance where it does.  Its layer-0 `QUAD` is a single **assert-zero**
gate: `Quad 0 b ≡ b`, which is what `prep_v` produces from a stored coefficient of `0`
(`vcc = if k == 0 { beta * dot }`, `HQuad::bind_g`).  Its layer-1 wire values are non-zero, so
the constraint that gate asserts is **violated** — exactly the cheating witness `beta` exists
to catch.  The layer-0 values are then `betas 0 * (1 − q₀)`: the violation, scaled by the
challenge.

`myLCb_degenerate_iff` computes the degeneracy exactly, and `beta_bites` reads off that a
`beta` of `0` hides the violation while a `beta` of `1` exposes it.  So `Degenerate` really is
a function of `beta`, the two-variable Schwartz–Zippel count in `layer_claim_zero_card` is
about a genuinely two-variable form, and the schedule in `LayeredCircuit.V` is load-bearing
rather than decorative.
-/

/-- Layer 0 is one assert-zero gate; every layer below it is the ordinary `QUAD ≡ 1`. -/
noncomputable def myLCb : LayeredCircuit Unit 1 1 0 1 F5 where
  V := fun ly _ betas _ q =>
    match ly with
    | 0 => betas 0 * (1 - q.get 0)
    | _ + 1 => 1 - q.get 0
  Quad := fun ly b _ _ _ => match ly with | 0 => b | _ + 1 => 1
  Quad_affine_beta := by
    intro ly b g l r
    cases ly <;> simp
  V_local := by
    intro ly w betas betas' h
    cases ly with
    | zero => funext g q; simp only [h 0 (Nat.zero_le 0)]
    | succ n => rfl
  layer_rel := by
    intro ly w alpha betas st
    cases ly with
    | zero => rw [const_quad_claim (betas 0) alpha st]
    | succ n => rw [const_quad_claim 1 alpha st]; ring

/-- The degeneracy of `myLCb`, computed: `beta · (1 − q₀) · (1 + alpha) = 0`. -/
lemma myLCb_degenerate_iff (betas : ℕ → F5) (alpha beta : F5) (st : LayerState 0 1 F5) :
    myLCb.Degenerate () betas alpha beta st
      ↔ beta * (1 - st.q.get 0) + alpha * (beta * (1 - st.q.get 0)) = 0 := by
  show (∑ j ∈ Finset.range (2 ^ (1 + 2 * 0)),
      layer_poly_of (nc := 1) (nv := 1) (fun _ _ _ => beta) (fun _ q => 1 - q.get 0) alpha st
        (boolean_vector j)) = 0 ↔ _
  rw [const_quad_claim beta alpha st]

/--
**`beta` decides the outcome.**

At `beta = 0` the assert-zero gate contributes nothing and the run looks honest; at `beta = 1`
the violation surfaces and the claim is non-zero.  So `Degenerate` is not a function of
`alpha` alone — which is what the earlier, schedule-free formulation forced it to be.
-/
theorem beta_bites :
    myLCb.Degenerate () zkBetas 0 0 zkST ∧ ¬ myLCb.Degenerate () zkBetas 0 1 zkST := by
  constructor
  · rw [myLCb_degenerate_iff]
    simp [zkST, vec1]
  · rw [myLCb_degenerate_iff]
    simp [zkST, vec1]

/-- Consequently the multi-layer degeneracy is genuinely two-variable: no analogue of the old
`degenerate_beta_independent` can hold. -/
theorem no_beta_independence :
    ¬ (∀ (LC : LayeredCircuit Unit 1 1 0 1 F5) (w : Unit) (betas : ℕ → F5) (alpha b b' : F5)
         (st : LayerState 0 1 F5), LC.Degenerate w betas alpha b st
           ↔ LC.Degenerate w betas alpha b' st) := by
  intro h
  exact beta_bites.2 ((h myLCb () zkBetas 0 0 1 zkST).mp beta_bites.1)

/-!
## The pre-state is necessary, and the ideal-Fiat–Shamir bound has an instance

`IsNonAdaptiveRun` indexes the Fiat–Shamir strategy by a pre-challenge state, not by the
challenge *prefix* alone.
Round 0's prefix is empty, so that forced the honest round polynomial to be one fixed
polynomial across every accepted run.  `honest_polys_need_state` shows that is not merely
strong but **false** here: the honest round polynomial of this layer is `(1 − r)(1 + alpha)`,
which differs between `alpha = 0` and `alpha = 1`.  Since `alpha` is a coordinate of the
sample space `core_soundness_probability` uses, the old hypothesis was unsatisfiable there.

With the pre-state index the whole bound becomes inhabitable, and `ideal_fs_applies` inhabits
it: `Ω` has `625` points — `D₀ = Unit`, one challenge, the layer pair, and `alpha_in` — the
strategy family reads `alpha` out of the pre-state, and every hypothesis including
`IsNonAdaptiveRun` is discharged.  That closes the second half of the gap: before this, the
correlation-intractability bound was only ever supplied by `card_le_univ`.
-/

/-- The honest round polynomials of this layer, computed. -/
lemma my_true_polys (alpha beta : F5) (t : Transcript F5) :
    circuit_true_polys myAC () () () t alpha beta (vec1 0) v0 v0
      = [myP alpha (vec1 0) v0 v0] := by
  rw [circuit_true_polys, myAC_quad_eq, myAC_w_eq]
  exact generate_eq alpha (vec1 0) v0 v0 _

/-- They genuinely depend on `alpha`: at `r = 0` the value is `1 + alpha`. -/
lemma myP_alpha_ne : myP 0 (vec1 0) v0 v0 ≠ myP 1 (vec1 0) v0 v0 := by
  intro h
  have h0 : (myP 0 (vec1 0) v0 v0).eval 0 = (myP 1 (vec1 0) v0 v0).eval 0 := by rw [h]
  rw [myP_eval, myP_eval] at h0
  simp [vec1] at h0

/--
**A state-free Fiat–Shamir strategy cannot describe this run.**

The honest side of non-adaptivity asks for one list of round polynomials per challenge prefix.
Round 0's prefix is empty, so a state-free strategy would need the same list for `alpha = 0`
and `alpha = 1`.  It is not.
-/
theorem honest_polys_need_state (t : Transcript F5) :
    circuit_true_polys myAC () () () t 0 0 (vec1 0) v0 v0
      ≠ circuit_true_polys myAC () () () t 1 0 (vec1 0) v0 v0 := by
  rw [my_true_polys, my_true_polys]
  intro h
  exact myP_alpha_ne (by injection h)

/-- The layer polynomial of this instance is *affine* in its single (copy) coordinate, so the
round polynomial has degree `≤ 2` even though copy rounds are cubic in general. -/
lemma myf_quadratic (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) :
    QuadraticAt (myf alpha q g0 g1) 0 (by omega) := by
  intro v
  refine ⟨(1 - q.get 0) * (1 + alpha),
          (q.get 0 - (1 - q.get 0)) * (1 + alpha), 0, fun X => ?_⟩
  have hset : v.set 0 X (by omega) = vec1 X := by
    ext i hi
    have : i = 0 := by omega
    subst this
    simp [vec1]
  rw [hset, myf_eval]
  ring

lemma myP_deg (alpha : F5) (q : Vector F5 1) (g0 g1 : Vector F5 0) :
    (myP alpha q g0 g1).natDegree ≤ 2 :=
  sumcheck_round_poly_natDegree_le_two _ 0 (by omega) _ (myf_quadratic alpha q g0 g1) (by decide)

/-! ### The instance -/

/-- The pre-challenge state: everything the run decides apart from the challenge sequence. -/
abbrev FsS := (Unit × (F5 × F5)) × F5

/-- The sample space of `core_soundness_probability_ideal_fs` at `D₀ = Unit`, `n = 1`:
`625` points. -/
abbrev FsΩ := ((Unit × (Fin 1 → F5)) × (F5 × F5)) × F5

/-- The verifier accepts the runs whose challenge is `1` — the root at which this cheating
prover survives.  Conditioning is legitimate: every hypothesis of the theorem is already
conditioned on `accepts`, and `Event_Fail` carries it too. -/
def fsAccepts : FsΩ → Prop := fun ω => ω.1.1.2 0 = 1

noncomputable def fsT : (Unit × (Fin 1 → F5)) × (F5 × F5) → EncTranscript 1 F5 :=
  fun _ => myT ()

noncomputable def fsE : Unit × (Fin 1 → F5) → Option (AugmentedWitness 1 F5 Unit) :=
  fun _ => myE ()

/-- The prover's single round polynomial.  It is a constant: this transcript and the extracted
pad are both fixed, which is what `prover_eq` needs. -/
noncomputable def fsProverPoly : RoundPoly F5 := cheatRound.unpad (fun _ => 0) 0

/--
The Fiat–Shamir family.  `P_func` reads `alpha` out of the pre-state — precisely the
dependence `honest_polys_need_state` shows is unavoidable.
-/
noncomputable def fsFam : IsFiatShamirFamily FsS F5 1 2 where
  P_func := fun s _ _ => myP s.1.2.2 (vec1 0) v0 v0
  p_func := fun _ _ _ => fsProverPoly
  hd := fun s _ _ => myP_deg s.1.2.2 (vec1 0) v0 v0
  h2 := le_refl 2

theorem fs_ligero :
    IsLigeroKnowledgeSound (Ω := FsΩ) (Input := Unit) myAC fsAccepts
      (fun ω => fsT ω.1) () () ()
      (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (fun ω => ω.2)
      (vec1 0) v0 v0 0 0 0 (fun ω => fsE ω.1.1) 0 where
  extraction_bound := by
    have h : Event_A (Witness := Unit) fsAccepts (fun ω : FsΩ => fsE ω.1.1) = ∅ := by
      ext ω; simp [Event_A, fsE, myE]
    simp [event_card, h]
  layer_constraint := by
    rintro ω w p _ h
    have hp := myE_pad () w p h
    subst hp
    refine ⟨?_, by simp⟩
    show (∑ i, _ * (0:F5)) = _
    simp [builder_finalize, my_eqq_zero, fsT]
  input_row := by
    rintro ω w p _ h
    have hp := myE_pad () w p h
    subst hp
    cases w
    simp [ligero_input_row, pubBinding, privIdx, input_row_coeffs,
      ArithmetizedCircuit.W_col, wCol, myAC, fsT, myT]

theorem fs_wf :
    IsWellFormedTranscript (Ω := FsΩ) (logw := 0) (logc := 1) fsAccepts
      (fun ω => fsT ω.1) where
  round_count := by intro ω _; simp [fsT, myT]

/--
**Non-adaptivity, discharged.**

`challenges_eq` is where `fsAccepts` earns its keep: on an accepted run the challenge *is* `1`,
which is what this transcript carries.  `true_eq` is where the pre-state does: the honest
polynomial is `myP (alpha ω)`, and `state ω` reports exactly that `alpha`.
-/
theorem fs_nonadaptive :
    IsNonAdaptiveRun (Ω := FsΩ) myAC fsFam fsAccepts (fun ω => fsT ω.1) 0 0 () ()
      (fun ω => fsE ω.1.1) (fun ω => ω.1.2.2) (fun ω => ω.1.2.1) (vec1 0) v0 v0
      (fun ω => ((ω.1.1.1, ω.1.2), ω.2)) (fun ω => ω.1.1.2) where
  challenges_eq := by
    intro ω hacc
    show [(1 : F5)] = List.ofFn (ω.1.1.2)
    rw [List.ofFn_succ, List.ofFn_zero]
    exact congrArg (fun x => [x]) hacc.symm
  prover_eq := by
    rintro ω w p _ h
    have hp := myE_pad () w p h
    subst hp
    rfl
  true_eq := by
    rintro ω w p _ h
    cases w
    rw [my_true_polys]
    rfl

/--
**The ideal-Fiat–Shamir bound, instantiated.**

Every hypothesis is discharged — including `IsNonAdaptiveRun`, which no witness reached
before.  `K = 1` here because the pre-state and the challenge together *are* the sample point.
-/
theorem ideal_fs_applies :
    (event_card (Event_Fail myAC fsAccepts () () (fun ω : FsΩ => ω.1.2.2) (fun ω => ω.1.2.1)
        (vec1 0) v0 v0 0 0 (fun ω => fsT ω.1) (fun ω => fsE ω.1.1)) : ℚ)
        / (Fintype.card (Unit × (Fin 1 → F5)) * Fintype.card F5 * Fintype.card F5
            * Fintype.card F5)
      ≤ (0 : ℚ)
          / (Fintype.card (Unit × (Fin 1 → F5)) * Fintype.card F5 * Fintype.card F5
              * Fintype.card F5)
        + 3 / Fintype.card F5
        + (1 : ℚ) * 2 / Fintype.card F5 :=
  core_soundness_probability_ideal_fs (D₀ := Unit) (n := 1) (d := 2) 0 myAC fsFam fsAccepts
    () () () (vec1 0) v0 v0 0 0 0 fsT fsE (by omega) (by simp) (by simp) (by omega)
    fs_ligero fs_wf fs_nonadaptive

/--
**And the bound is not about the empty set.**

`Event_Fail` is exactly the accepted runs: on every one of them the extractor succeeds,
`checkV` passes, and the extracted witness fails the circuit.  So the left-hand side of
`ideal_fs_applies` is `125/625 = 1/5`, not `0`.
-/
theorem fs_failure_event :
    Event_Fail myAC fsAccepts () () (fun ω : FsΩ => ω.1.2.2) (fun ω => ω.1.2.1)
        (vec1 0) v0 v0 0 0 (fun ω => fsT ω.1) (fun ω => fsE ω.1.1)
      = Finset.filter fsAccepts Finset.univ := by
  ext ω
  simp only [Event_Fail, Finset.mem_filter, Finset.mem_univ, true_and]
  constructor
  · rintro ⟨hacc, -⟩; exact hacc
  · intro hacc
    refine ⟨hacc, Or.inr ⟨(), ?_, rfl⟩⟩
    have hcheck := extractor_soundness_bridge fs_ligero ω () (fun _ => 0) hacc rfl
      (by simp [InputBindingBad, true_evals, myAC_w_eq, myW, fsT, myT])
    simp [E_prime, fsE, myE, hcheck]

theorem fs_failure_nonempty :
    (Event_Fail myAC fsAccepts () () (fun ω : FsΩ => ω.1.2.2) (fun ω => ω.1.2.1)
      (vec1 0) v0 v0 0 0 (fun ω => fsT ω.1) (fun ω => fsE ω.1.1)).Nonempty := by
  refine ⟨((((), fun _ => 1), (0, 0)), 0), ?_⟩
  rw [fs_failure_event]
  simp [fsAccepts]

/-!
## The per-layer randomness terms are about a reachable situation

`mevent_randAt_card_split` bounds the runs on which layer `i`'s `alpha` lets wrong claims
survive the combination `claim[0] + alpha·claim[1]`.  Two things could make that bound empty
talk: the splitting hypotheses might be unsatisfiable, or they might force the event empty.
The existing two-layer instance cannot settle either — it sits at `Ω = Unit`, where the space
has no `alpha` coordinate to split at, and `zk_rand_ok` proves the event is *empty* there.

This instance has the coordinate.  `myLC.V` is `1 − q₀` and the run's copy point is `0`, so
both honest layer-0 values are `1` while the verifier starts from claims of `0`: the claims
really are wrong.  Then `1 + alpha·1 = 0` has exactly one solution in `F5`, namely `alpha = 4`,
and the bound `≤ |Unit| = 1` is met with equality.
-/

section PerLayerWitness

/-- Everything decided before layer `0`'s `alpha`, then that `alpha`. -/
abbrev PlΩ : Type := Unit × F5

/-- The run: layer `0` carries the sampled `alpha`, layer `1` is unchanged. -/
noncomputable def plT : PlΩ → List (ZkLayer 1 F5) :=
  fun ω => [{ zkL with alpha := ω.2 }, zkL]

/-- The extractor reads only the prefix — it cannot see the `alpha` its output is compared
against, which is what makes the one-bad-draw count legitimate. -/
noncomputable def plE : Unit → Option (AugmentedWitness 1 F5 Unit) :=
  fun _ => some ((), fun _ => 0)

/-- **The bound applies**: every hypothesis of `mevent_randAt_card_split` is discharged, the
causality ones (`hstate`, `halpha`) by computation on the run. -/
theorem pl_alpha_card :
    event_card (MEvent_RandAt myLC (fun _ => True) (fun _ : PlΩ => zkBetas) zkST plT
      (fun _ : PlΩ => plE ()) 0) ≤ Fintype.card Unit :=
  mevent_randAt_card_split (Ω := PlΩ) myLC (fun _ => True) (fun _ => zkBetas) zkST
    (fun _ => ()) (fun ω => ω.2)
    (by
      rintro ⟨⟨⟩, x⟩ ⟨⟨⟩, y⟩ h
      simp only [Prod.mk.injEq] at h
      rw [h.2])
    plT plE 0 (fun _ _ => zkST)
    (fun _ _ => rfl)
    (fun ω pad ld h => by
      simp only [plT, zkLayerDatas, List.getElem?_cons_zero, Option.some.injEq] at h
      rw [← h]
      rfl)
    (fun _ _ => by simp [plT, zkLayerDatas])

/-- **And it is not about the empty set.**  At `alpha = 4` the wrong claims survive: the honest
values are `1` and `1`, the verifier's claims are `0` and `0`, and `1 + 4·1 = 0` in `F5`. -/
theorem pl_alpha_nonempty :
    (MEvent_RandAt myLC (fun _ => True) (fun _ : PlΩ => zkBetas) zkST plT
      (fun _ : PlΩ => plE ()) 0).Nonempty := by
  refine ⟨((), 4), ?_⟩
  simp only [MEvent_RandAt, Finset.mem_filter, Finset.mem_univ, true_and]
  refine ⟨(), fun _ => 0, rfl, ?_⟩
  show LayerAlphaBad myLC 0 () zkBetas zkST _
  rw [LayerAlphaBad]
  refine ⟨Or.inl ?_, ?_⟩
  · show (1 : F5) - (vec1 (0 : F5)).get 0 ≠ zkST.claim0
    simp [zkST, vec1]
  · show (1 : F5) - (vec1 (0 : F5)).get 0
        + _ * ((1 : F5) - (vec1 (0 : F5)).get 0) = zkST.claim0 + _ * zkST.claim1
    simp [zkST, vec1]
    decide

/-- **The bound is tight.**  Exactly one of the five draws is bad, and `|Unit| = 1`. -/
theorem pl_alpha_exact :
    event_card (MEvent_RandAt myLC (fun _ => True) (fun _ : PlΩ => zkBetas) zkST plT
      (fun _ : PlΩ => plE ()) 0) = 1 :=
  le_antisymm (le_trans pl_alpha_card (by simp))
    (Finset.card_pos.mpr pl_alpha_nonempty)

end PerLayerWitness

end LfzkExample