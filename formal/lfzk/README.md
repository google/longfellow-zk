# Longfellow ZK Lean formalization

**WORK IN PROGRESS.** A partial formalization of the soundness argument for the Longfellow
protocol (Theorem 6 / Protocol 2.5 of "Anonymous credentials from ECDSA"), checked against
the implementation in `lib/sumcheck/` and `lib/zk/`. It has not been externally audited.
§"Security analysis" states exactly what the main theorem does and does not give you.

Comments and corrections are welcome.

```
lake build            # builds everything, including the non-vacuity example
```

Toolchain: Lean 4.31.0 with Mathlib pinned in `../lakefile.toml`.

---

## Files

| File | Contents |
|---|---|
| `sumcheck_soundness.lean` | `RoundPoly` (= `WPoly`), the round check, the multi-round reduction, Schwartz–Zippel, and a combinatorial Fiat–Shamir counting bound |
| `types.lean` | `Expression`, `Pad`, `Transcript`, `Transcript.checkV`, and the random-combination collision lemmas |
| `builder.lean` | `ZkCommon::Expression` / `ConstraintBuilder`, `EncTranscript`, and the proof that the rounds close on `e(pad)` |
| `circuit.lean` | Multilinear extensions, the layer polynomial, the hypercube-splitting lemmas, the degree bound, `ArithmetizedCircuit` |
| `ligero.lean` | The Ligero constraint rows, the witness binding, and the `IsLigeroKnowledgeSound` assumption bundle |
| `fiat_shamir.lean` | Non-adaptive strategies, the challenge-sequence counting bound, and its instantiation at the layer polynomial |
| `layers.lean` | The `for (ly)` loop, the layer-to-layer reduction, and the induction over all layers |
| `zk_layers.lean` | Joining the layer loop to the ZK/Ligero side: the pad overlap, and a whole ZK proof driving `VerifierLayers::layers` |
| `zk_soundness.lean` | Multi-layer knowledge soundness: all bad events carried through the layers |
| `lfzk.lean` | Event decomposition and `core_soundness_theorem` |
| `instantiate.lean` | The sample space, and the bound as a probability |
| `example.lean` | A concrete instance discharging every hypothesis the non-vacuity witness |

---

## Security analysis

### What the main theorem says

`core_soundness_theorem` (`lfzk.lean`):

> Fix a circuit `C`, a public input `x`, and a family of runs indexed by a finite sample
> space `Ω`. Among the runs on which the ZK verifier **accepts**, the number on which the
> extractor fails to output a witness satisfying `C(x, ·)` is at most
>
> ```
> eps_FSK  +  eps_bind  +  eps_deg  +  eps_sumcheck
> ```

This is knowledge soundness in counting form: `event_card` is a raw `Finset.card`, never
normalised by `|Ω|`.  As per the definition of knowledge soundness and the extractor,
we only consider verifier runs that are accepting. Every event in the decomposition
carries the `accepts ω` conjunct.

`core_soundness_probability_ideal_fs` (`instantiate.lean`) is the same result as a
probability, over the sample space `(D₀ × challenges) × F` everything decided before the
challenges, the challenge sequence, and the layer combination coefficient:

```
Pr[extraction fails | verifier accepts]  ≤  eps_FSK/|Ω|  +  3/|F|  +  n·d/|F|
```

where `n = logc + 2·logw` is the number of sumcheck rounds. Both `d = 2` and the
`3/|F|` are derived, not supplied, so on the ZK path (`logc = 0`) the last two
terms are `3/|F| + 4·logw/|F|`. `eps_FSK` remains the only free parameter.

The sample space carries *both* per-layer challenges that `begin_layer` draws
(`transcript_sumcheck.h:L54`): `alpha`, which combines the two inherited claims,
and `beta`, which replaces the coefficient of every assert-zero gate 
(`prep_v`, `quad.h:L213`). The `3/|F|` is `1/|F|` for the input binding plus
`2/|F|` for the pair `(alpha, beta)`. The actual claim is a *bilinear form* in
those variables, so its zero set is `2·|F|` out of `|F|²`.

`multi_layer_core_soundness` (`zk_soundness.lean`) is the multi-layer version,
for a circuit of `nl` layers:

```
|Event_Fail|  ≤  eps_FSK  +  nl · eps_alpha  +  nl · eps_round  +  eps_bind
```

Only the per-layer randomness terms scale with depth; `eps_FSK` and the witness
binding do not.

### Where each term comes from

`Event_Fail ⊆ Event_A ∪ Event_B ∪ Event_Degenerate ∪ Event_C`, and:

| Term | Event | Status |
|---|---|---|
| `eps_FSK` | `Event_A` verifier accepted, Ligero extractor returned nothing | **assumed** (`IsLigeroKnowledgeSound.extraction_bound`) |
| `eps_bind` | `Event_B` extraction succeeded but `checkV` failed | **derived**: reduced to a random-combination collision, worth `1/\|F\|` |
| `eps_deg` | `Event_Degenerate` the layer challenges `(alpha, beta)` collapsed a non-zero output claim | **derived**: two-variable Schwartz–Zippel, `2/\|F\|` |
| `eps_sumcheck` | `Event_C` the prover was lucky in some sumcheck round | **derived**: `n·d/\|F\|`, with `d = 2` also derived |

### How the verifier is modelled

`accepts : Ω → Prop` is an *abstract* predicate standing for "the ZK verifier accepted this
run". Nothing in the development executes the verifier, so every property of it that the
proof uses has to be stated as a property of `accepts`. Here is one:

* `IsWellFormedTranscript.round_count`: an accepted run's transcript has exactly
  `logc + 2·logw` rounds.

This is a *description of the verifier*, not a hypothesis about the adversary, and it is
enforced by construction in the implementation: the loop bound is `clr->logw` read from
`Circuit<Field>` (`verifier_layers.h:L119`), a public circuit parameter, so a prover cannot vary it, and a proof carrying a different number of rounds does not parse.

Everything else the verifier does *is* modelled concretely: the round checks
(`check_round_c`), the layer-to-layer state update, the final layer identity
`got = EQ[Q,C] · QUAD[G|R,L] · W[R,C] · W[L,C]`, and the `ConstraintBuilder`
recursion that turns the padded transcript into a Ligero constraint system.

### What you have to assume

The theorem is a reduction. A reader who accepts the following, and nothing else,
gets the bound above:

1. Ligero knowledge soundness: `extraction_bound` on accepted runs the extractor fails
   on at most `eps_FSK` of them. Ligero is treated as an ideal primitive; its Reed–Solomon
   internals are not modelled. *This is the one genuinely cryptographic assumption.*
2. What the Ligero extractor returns: `layer_constraint` and `input_row`: the extracted
   pad and witness columns satisfy the rows the verifier fed in
   (`ConstraintBuilder::finalize`, `zk_common.h:L373`, and `ZkCommon::input_constraint`,
   `zk_common.h:L406`). This is the definition of extraction, instantiated at the *actual*
   transcript rather than universally quantified.
3. Arithmetization is correct: `ArithmetizedCircuit.arith` models the correctness of
   the circuit compiler.  For an unsatisfied circuit, the honest layer claim 
   `S(alpha, beta)` is **not identically zero on `F × F`**. We must assume that the
   quad-form encoding is equivalent to `eval`. A separate directory in this project
   models the correctness of the compiler, and will eventually be tied into this proof.

   It is *written* as "non-zero at one of `(0,0)`, `(0,1)`, `(1,0)`, `(1,1)`", which is a
   finite certificate for that statement, not a restriction on the challenges: `alpha` and
   `beta` are drawn from the whole field. `S` is bilinear, hence determined by four
   coefficients, and those vanish exactly when `S` vanishes at those four points —
   `bilinear_corners_iff` proves the equivalence.
4. Fiat–Shamir: `IsNonAdaptiveRun.prover_eq` states round `i`'s polynomial is
   fixed before challenge `i` is drawn from it. This is structural and it holds because
   `ts.round(hp)` derives `r_i` from a transcript that already contains `p_i`.
   We also model the challenge sequence as a coordinate of `Ω` under the
   ideal-Fiat–Shamir idealisation, discussed under "The Fiat–Shamir term" below.

Everything else about the arithmetization is *data*, not assumption. `ArithmetizedCircuit`
carries a gate table `gate_v` and the two halves `pub_col` / `priv_col` of the input wire
vector, and `QUAD` and `W` are **constructed** from them as multilinear extensions. So:

* `Quad_mle` is multilinear in each hand `Quad_mle_ml_l` / `Quad_mle_ml_r`, theorems.
* `Quad_mle` is affine in `beta` `Quad_mle_affine_beta`, a theorem, because `prep_v` is.
* `W_mle` is a multilinear extension of the wire vector `W_mle_is_mle`, definitional.
* The public wires do not depend on the witness `W_col_pub`, since the wire
  vector *is* `pub ++ priv`.

### What it does *not* cover

* **Zero-knowledge is not addressed at all**: only soundness. The pad is modelled as a
  vector the extractor produces, not as a distribution, and no theorem uses the fact that
  the blinders are uniform.
* **Ligero is a black box.** `eps_FSK` is a parameter; nothing here bounds it.
* **Copy rounds.** The non-ZK verifier's `CPoly` rounds are not modelled; see gap 1.

### Non-vacuity

The main theorem is a reduction that bounds the size of a *bad* event.
Here we explain how we ensure the theorem is meaningful with concrete
"tests" of our abstractions.

First, it is important to ensure the hypothesis of the theorem can
be satisfied.  If the conditions are too strong to every be met, then
the theorem is essentially "False -> foo".  More subtly, if the hypothesis
forces the bad event set to be empty, the reduction may also be vacuous.

The file `example.lean` contains examples of unsatisfiable circuits, and
tests the result of applying our theorem.

1. In the first example, the prover sends the zero polynomial where the honest one has
`P(0) + P(1) = 1`; the round check passes because `0 + 0 = 0`, and the Fiat–Shamir
challenge `r = 1` happens to be the root of `p − P`, so the verifier accepts. Every
hypothesis of `core_soundness_theorem` holds anyway.  In this case, the test verifies:

* `Event_Fail` is *all* of the sample space, the bound is not bounding the empty set;
* `eps_FSK`, `eps_bind` and `eps_deg` are each provably `0` here, so the bound is `1 ≤ 1`,
  **tight**;
* therefore `eps_sumcheck_forced`: **any** `eps_sumcheck` satisfying the
  correlation-intractability bound on this instance is `≥ 1`. The sumcheck term is
  load-bearing, not padding.

1. The second example, `zk_multi_layer_soundness_applies`, is a two-layer ZK proof
over a degenerate `LayeredCircuit`, whose Ligero rows all hold and which drives
`VerifierLayers::layers` to accept, starting from claims that are wrong. 
We show `ZkRowsHold`, `LayersShapeOK` and `GoodRandomness` are jointly satisfiable
*with wrong claims*, so the layer reduction's conclusion is about a reachable situation
rather than an impossible one.

1. In the third example, `multi_layer_soundness_applies` / `multi_layer_failure_nonempty`,
the same is run against the merged five-event statement. Two of its four terms come
out provably `0` (the extractor never fails; no layer's coefficient is unlucky), so
the surviving bound is `2·eps_round + eps_bind` and the per-layer `nl ·` factors are
exercised rather than absorbed.

1. `deg_quadratic` / `deg_round_zero` tests the degree bound needs because
every witness above has `logw = 0`, where the multilinearity conditions hold
*vacuously* and would prove nothing. At `logw = 1` the round-0 polynomial is exactly
`X²`, so `d ≤ 2` is tight: `d = 1` would be false.

1. `logv_one_poly_ne_zero`: likewise a `logv = 0` instance is not enough to pin down
how the `G` variable is summed. `Vector F 0` is a singleton, so a sum over the gate
corners and a sum over all of `F^logv` coincide there. They differ sharply for 
`logv ≥ 1`: summing over `F^logv` makes the layer polynomial **identically zero** over
any prime field with `|F| > 3`, because `∑_{x∈F} x = ∑_{x∈F} x² = 0` collapses every
`eq`-orthogonality sum. That would force `eval ≡ true` and make the whole development
vacuous.

Finally, the only axioms used via  `#print axioms core_soundness_theorem` are 
`[propext, Classical.choice, Quot.sound]`.
There are no global `axiom` declarations and no `sorry` anywhere.

---

## What is proved

### The Ligero side

* **`builder_finalize_soundness`**: the linear row emitted by `ConstraintBuilder::finalize`
  (`zk_common.h:L373`), together with the quadratic pad relation, forces
  `CLAIM = EQQ · (W_hat[L] + dW[L]) · (W_hat[R] + dW[R])`.
* **`input_row_soundness`, `input_row_coeffs_give_mle`, `input_row_binds_hands`**: the
  single input row of `ZkCommon::input_constraint`, acting on the committed witness columns,
  forces the prover's claimed hand evaluations to equal the honest multilinear evaluations
  of the extracted witness. This is the witness binding; at most one `alpha` escapes it.
* **`pub_consistent_of_indep`**: public-input consistency is a theorem, not an extractor
  obligation: `pubBinding` computed from any witness is the same value.
* **`builder_next_eval`, `builder_run_verifies`, `EncTranscript.rounds_verify`**: the
  `ConstraintBuilder` recursion tracks the verifier's claim exactly, and the sumcheck rounds
  of a builder run always close on the decrypted expression `e(pad)`. The ZK path
  *substitutes* `p(1) = claim − p(0)` rather than checking it, so every round check passes by
  construction which is why this is a theorem rather than an assumption.
* **`ZkLayer.first_matches_next_state`**: the pad overlap. `ConstraintBuilder::first` reads
  `CLAIM_PAD[layer − 1]`, which is the previous layer's `CLAIM_PAD[layer]` (`PadLayout`,
  `zk_common.h:L207-L213`); its value *is* the claim the sumcheck verifier carries forward.
  This is what makes the two sides composable.

### The sumcheck side

* **`sumcheck_multi_reduction`**: if the verifier accepts a round sequence starting from a
  false claim, then either the final claim is wrong or some round was a lucky guess.
* **`layer_step`, `layers_reduction`**: the GKR induction. `layer_step` turns "the claims
  entering layer `ly` are wrong" into "a round of layer `ly` was lucky, or the claims
  entering layer `ly+1` are wrong", using the `got == claim` check and the state update at
  `verifier_layers.h:L182-L197`. `layers_reduction` iterates it to the input layer, where
  `input_row_binds_hands` pins the claims to the committed witness. This needs **no**
  `EQQ ≠ 0` condition.
* **`layer_sumcheck_poly`** sums the `G` variable over the `nv` **gate corners**, which is
  what `bind_g` does (`quad.h:L153`): it iterates over gates and looks each gate's corner up
  in `dot = raw_eq2(logv, nv, G0, G1, alpha)`. `logv_one_poly_ne_zero` (`example.lean`) is
  the regression guard see the note under non-vacuity.
* **`ca_split`, `consistent_generate`, `head_generate`, `get_last_eval_generate`**: the
  hypercube-splitting lemmas, from the bijection `j ↦ (j/2, j%2)`. These discharge the facts
  about honest round polynomials that the reduction needs, leaving `arith` as the only
  assumption in `ArithmetizedCircuit.soundness`.
* **`final_binding`**: `EQQ · W[R,C] · W[L,C]` equals the honest layer polynomial at the
  transcript's challenge point.
* **`zk_layer_verifies`, `zk_layers_verify`, `zk_multi_layer_soundness`**: a whole ZK proof
  drives `VerifierLayers::layers` to accept, and if the claims it starts from are wrong then
  some layer's sumcheck round was lucky or the input-layer claims are wrong.
* **`mevent_fail_subset`, `multi_layer_core_soundness`**: the merged multi-layer statement.
  The extractor's guarantee *is* that the Ligero rows hold, so that event contributes `0`;
  the two `nl ·` factors come from a union bound over layers.

### The randomness terms

`begin_layer` draws two challenges per layer, and both are counted.

* **`layer_claim_affine`, `layer_claim_affine_quad`**: the honest layer claim `S(alpha, beta)`
  is affine in `alpha` (the verifier combines the two inherited claims linearly) and affine in
  `beta` (`prep_v` substitutes `beta` for each assert-zero coefficient), i.e. a bilinear form.
  This is what turns degenerate randomness from an assumption into a countable event.
* **`event_b_subset`**: a pad and witness columns satisfying the Ligero rows force
  `Transcript.checkV = true` unless the run hits the one bad `alpha`.
* **`bilinear_corners_iff`**: a bilinear form vanishes identically on `F × F` iff it vanishes
  at the four corners `{0,1}²`. This is why `arith` can be a finite condition even though the
  challenges range over the whole field.
* **`affine_root_card`, `bilinear_zero_card`**: two-variable Schwartz–Zippel: a bilinear form
  that is not identically zero vanishes on at most `2·|F|` of the `|F|²` pairs.
* **`option_bad_pairs_card_mul`, `event_alpha_bad_card`, `event_degenerate_card`**: over a
  sample space split as `D × (F × F)` (everything decided before the layer, then
  `(beta, alpha)`), the extractor's output is fixed by the pre-challenge state. So the input
  binding costs `1/|F|` and the degenerate pair costs `2/|F|`.

### The Fiat–Shamir term

* **`univariate_roots_bound`, `bad_round_roots`, `combinatorial_fiat_shamir`**. At most
  `n · d · |F|^(n-1)` of the `|F|^n` challenge sequences let a non-adaptive prover cheat.
  This is a root count, with no random-oracle axiom.
* **`multi_round_bad_event_exists`, `sumcheck_ci_of_nonadaptive`** that count transfers to
  the sample space, giving `eps_sumcheck = K · n · d · |F|^(n-1)`, where `K` bounds the
  fibers of `challenge_map : Ω → (Fin n → F)` how many runs share a challenge sequence.

`K` appears because `event_card` counts over `Ω` while the root count is over challenge
sequences. Left as a parameter it says nothing, so it is pinned down and removed:

* **`card_le_K_mul`** `K ≥ |Ω| / |F|^n`, by pigeonhole. `K` is a **load factor, not a
  security parameter**: no hash drives it to `1`, and a bound claiming a smaller `K` is
  unachievable.
* **`IsRegularChallengeMap`, `regular_fiber_card`** for a *regular* map (all fibers equal,
  the defining property of an ideal hash) that lower bound is attained exactly.
* **`split_fiber_card`, `mid_fiber_card`** when the challenge sequence is a coordinate of
  the sample space, the fiber bound is a **theorem**, and `K` is the size of the rest of the
  space.
* **`sumcheck_prob_of_split`, `core_soundness_probability_ideal_fs`**: `K` then cancels
  against `|Ω|`, leaving `n·d/|F|`: the textbook sumcheck soundness error.

This does not remove the idealisation, it relocates it. In the real protocol
`r_i = H(transcript_i)` is *determined* by `ω`, not an independent coordinate of it; making
it a coordinate is the ideal-Fiat–Shamir model. What is gained is that the idealisation is
visible in the shape of the sample space and provably the best case, rather than hiding
inside an unexplained constant. It is also not wishful: the relation being dodged is "`cs i`
is a root of a degree-`d` polynomial determined by the prefix", which is efficiently
searchable, and correlation-intractable hash families for that class are known from
sub-exponential LWE. Formalizing that is out of scope.

### The degree `d`

`d` is not an independent parameter: the layer summand is
`EQ[Q,C] · QUAD[G|L,R] · W[L,C] · W[R,C]`, and binding a hand variable freezes the copy
block, so `EQ[Q,C]` and one of the two `W` factors are constants while `QUAD` and the other
`W` are affine. A product of two affine factors is quadratic, which is what
`WPoly = Poly<3, Field>` (three evaluation points) encodes.

* **`IsMultilinear`, `QuadraticAt`, `IsQuadratic`**: stated as "freezing every coordinate
  but one leaves a degree-≤1 / ≤2 function".
* **`ArithmetizedCircuit.W_mle_multilinear`, `Quad_mle_ml_l`, `Quad_mle_ml_r`**: both `W` and
  `QUAD` are multilinear *because they are constructed as multilinear extensions*, so the
  degree bound rests on no assumption at all.
* **`layer_quadratic_at_hand`**: every hand coordinate is quadratic, for any `logc`.
  `layer_quadratic` specialises to `logc = 0`, the ZK path, where every coordinate is a hand
  coordinate.
* **`sumcheck_round_poly_eq_of_agrees`**: interpolation below `|F|` is unique, so the degree
  comes from the arithmetization rather than from the field size.
* **`three_le_card`**: a field carrying a `SumcheckInterp` instance has `|F| ≥ 3`, which is
  the side condition the degree bound needs. It comes free.
* **`ArithmetizedCircuit.round_poly_natDegree_le_two`, `fsOfArithmetized`**: `natDegree ≤ 2`
  for every honest round polynomial of a ZK layer, packaged so a caller supplies only the
  prover's own strategy.
* **`circuit_true_polys_eq_fsOfArithmetized`**: the check that this bounds the *right*
  polynomials: the constructed honest strategy is exactly the family `circuit_true_polys`
  produces.

---

## Current gaps

### 1. Copy rounds (`CPoly`) are not covered

`RoundPoly` matches `WPoly = Poly<3, Field>`: `eval_lagrange` is the degree-≤2 Lagrange
interpolant through `0`, `1` and the field-specific third point `pt2` (`2` for prime fields,
the generator `X` for `GF(2)[X]/(Q(X))`, where `2 = 0`).

The *copy* rounds of the non-ZK verifier, `VerifierLayers::layer_c`, use
`CPoly = Poly<4, Field>` (degree 3) and are not modelled. The ZK path does not have them —
`zk_common.h:L72` asserts `logc == 0` so a four-point variant is needed only to model
`Verifier::verify` directly. This is also why the derived `d = 2` is stated at `logc = 0`.

### 2. Ligero is a black box

`eps_FSK` is the last free parameter. Bounding it means formalizing Reed–Solomon proximity
testing and the Ligero commitment argument, which is a separate project of comparable size.
It is also the one idealisation not relocated into the sample space: Ligero is still an
oracle here.

### 3. Zero-knowledge

Not addressed. Every theorem uses the pad for soundness only; no theorem uses the fact that
the blinders `dP(r, ·)` and `dWC[·]` are uniform, so "the padded transcript reveals nothing"
is unproved.

### 4. Modelling details

* All layers carry the same `logw`. This is scope, not a gap: `clr->logw` is a public
  circuit parameter read from `Circuit<Field>`, never from the proof, and
  `logw ≤ kMaxBindings = 40` (`sumcheck/circuit.h:L78`) means a common width always exists,
  so a prover gains nothing from varying it.
* `extract_vars` treats the two hands as contiguous blocks of the challenge vector, while
  the implementation interleaves them (`for (round) { for (hand) }`,
  `zk_common.h:L91-L101`). This is a permutation of the challenge indexing.
* `ArithmetizedCircuit.W_mle` is the multilinear extension of `W_col` in the *hand* variables
  only; the copy point is a parameter rather than being bound. The ZK path has `logc = 0`, so
  nothing is lost there.

---

## Remaining work

1. **Open the Ligero box**: formalize Reed–Solomon proximity testing and derive `eps_FSK`
   instead of assuming it (gap 2). This is the largest remaining item and the only one that
   changes what the result rests on.
2. **A `CPoly`-shaped four-point `RoundPoly`**, to cover the non-ZK verifier's copy rounds
   and lift the degree bound to `d = 3` there (gap 1).
3. **Standard-model Fiat–Shamir**: replace the ideal-challenge sample space with a
   correlation-intractable hash family for the root-finding relation.
