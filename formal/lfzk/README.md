# Longfellow ZK Lean formalization

**WORK IN PROGRESS.** A machine-checked *reduction* for the soundness and zero-knowledge
arguments of the Longfellow protocol (Theorem 6 / Protocol 2.5 of "Anonymous credentials from
ECDSA"), written against the implementations in `lib/sumcheck/`, `lib/zk/` and
`rust/runtime/zk/`. It has not been externally audited.

Comments and corrections are welcome.

```
lake build            # builds everything, including the non-vacuity example
```

Toolchain: Lean 4.31.0 with Mathlib pinned in `../lakefile.toml`.

---

## Files

| File | Contents |
|---|---|
| `sumcheck_soundness.lean` | `RoundPoly` (= `WPoly`), the round check, the multi-round reduction *and* its completeness converse, Schwartz–Zippel, and a combinatorial Fiat–Shamir counting bound |
| `types.lean` | `Expression`, `Pad`, `Transcript`, `Transcript.checkV`, and the random-combination collision lemmas |
| `builder.lean` | `ZkCommon::Expression` / `ConstraintBuilder`, `EncTranscript`, and the proof that the rounds close on `e(pad)` |
| `circuit.lean` | Multilinear extensions, the layer polynomial, the hypercube-splitting lemmas, the degree bound, `ArithmetizedCircuit` |
| `ligero.lean` | The Ligero constraint rows, the witness binding, and the `IsLigeroKnowledgeSound` assumption bundle |
| `ligero_rs.lean` | Reed–Solomon minimum distance and unique decoding, and the column-opening count |
| `mlin.lean` | Multilinear Schwartz–Zippel (`mlin_zero_card`), the count for the initial challenge point (`initial_point_bad_card`), and computed witnesses that both are tight |
| `ligero_sys.lean` | The row/system types, the **generic** Ligero interface `IsLigeroSound` over an arbitrary public constraint system, and the fibrewise lifting of a per-coin error to a global count |
| `ligero_bridge.lean` | Longfellow's row facts *derived* from `IsLigeroSound`: the one-layer bundle, a whole run's `ZkRowsHold`, the multi-layer input binding, and the composed multi-layer soundness bound over the protocol's own sample space |
| `fiat_shamir.lean` | Non-adaptive strategies, the challenge-sequence counting bound, and its instantiation at the layer polynomial |
| `layers.lean` | The `for (ly)` loop, the layer-to-layer reduction, and the induction over all layers |
| `zk_layers.lean` | Joining the layer loop to the ZK/Ligero side: the pad overlap, and a whole ZK proof driving `VerifierLayers::layers` |
| `zk_soundness.lean` | Multi-layer knowledge soundness: all bad events carried through the layers |
| `lfzk.lean` | Event decomposition and `core_soundness_theorem` |
| `instantiate.lean` | The sample space, and the bound as a probability |
| `zk_hiding.lean` | `PadLayout`, the blinding-slot injectivity — within a layer and across a whole run (`blindSlot_inj`, `quadSlot_ne_blindSlot`) — the one-time pad as a bijection and as a function (`padOfBlinders`), and statistical distance: `probOf`, `StatClose`, `statDist` and the coupling bridge |
| `zk_sim.lean` | The Ligero system separated from its assignment, the ZK black box, honest-verifier zero-knowledge, and `zkSetupOfLayer` / `zkSetupOfRun` — `ZkSetup`s built from the model's own pieces, for one layer and for a whole run at the computed layout `stdRunPad` and every challenge sequence |
| `example.lean` | A concrete instance discharging every hypothesis — the non-vacuity witness |
| `../merkle/` | A *separate* Lean library: Merkle-heap commitment, binding from collision resistance, and ROM binding/hiding bounds. Not imported by `lfzk` — see gap 2 |

---

## What the theorems say

Both theorems are reductions: each names exactly what it assumes, and
§"What is not covered" at the bottom collects the boundaries of both.

### Soundness

`multi_layer_soundness_probability` (`ligero_bridge.lean`) is the top-level statement, for a
circuit of `nl` layers over the sample space the protocol's own randomness schedule dictates:

```
Pr[verifier accepts  ∧  extraction fails]  ≤  eps_FSK/|Ω|  +  3/|F|  +  nl·(eps_alpha + eps_round)/|Ω|
```

This is a **joint** probability, not a conditional one. Every event carries the `accepts ω`
conjunct and the count is divided by `|Ω|`, so what is bounded is `Pr[accepts ∧ fail]`, the
usual soundness form; turning it into `Pr[fail | accepts]` would need a lower bound on the
acceptance probability, which nothing here provides.

`eps_FSK` is Ligero's knowledge error and is the only free parameter that a cryptographic
assumption feeds. The other terms are derived: `1/|F|` for the input-binding collision, `2/|F|`
for the layer pair collapsing the output claim, `1/|F|` per layer for the claim combination and
`n·d/|F|` per layer for the sumcheck rounds. `multi_layer_soundness_probability_all_derived`
derives all five, over an abstract sample space presented as one bijective splitting per
challenge, and concludes the probability directly.

### Zero-knowledge

`longfellow_hvzk` (`zk_sim.lean`):

> For every witness and **every challenge sequence**, no test distinguishes the real transcript
> from a simulation that never sees a witness with advantage more than `eps_hide`.

`longfellow_wi` is the witness-indistinguishability corollary: two witnesses' transcripts are
`2·eps_hide`-indistinguishable. `longfellow_hvzk_statDist` restates the bound as total
variation distance, which is the form to compare against a paper.

"Advantage" quantifies over *all* predicates on the transcript, unbounded and non-uniform, so
this is statistical, not computational. `eps_hide` is Ligero's own error, unchanged: the pad
stage is a bijection, so it contributes nothing and there is no factor for the blinder space.
At `eps_hide = 0` this is perfect HVZK.

The simulator uses its **own** randomness. `SimRand` and `LigRand` are unrelated types of
possibly different size, which is what a real simulator needs and what a coupling-based
statement could not have expressed.

`zkSetupOfRun` (`zk_sim.lean`) is the instance this applies to: a whole `nl`-layer run at the
computed standard pad layout, quantified over the runtime's full challenge schedule. So the
statement is about the object the protocol produces, not a stand-in.

---

## How much of Longfellow is verified

**In one sentence:** the sumcheck/GKR core is verified, as a *reduction* to a small and
explicitly named trust base, over an algebraic model of the protocol rather than over the
shipped code.

### By component

| Component | Status |
|---|---|
| Sumcheck round reduction, the GKR layer loop, the `ConstraintBuilder` recursion | **Verified.** The bulk of the ~12.5k lines |
| The error terms | **Derived, not supplied.** `multi_layer_soundness_probability_all_derived` concludes the probability from bijective splittings, with `K` and every cardinality derived rather than assumed |
| The randomness schedule and its counting | **Verified**, and matched coordinate-by-coordinate against the runtime's draw order |
| Ligero — `eps_FSK` and `eps_hide` | **Assumed.** Interleaved Reed–Solomon proximity, the mathematical core, is proved nowhere here |
| The circuit compiler — `arith`, `layer_rel`, … | **Assumed**, and `arith` in a form *stronger* than ordinary compiler correctness |
| Fiat–Shamir | **Idealised.** The root count needs no oracle; making the challenge sequence a coordinate of `Ω` is the random-oracle model |
| The implementation — `ZkVerifier::verify`, the Rust prover, the C++ library | **Not addressed.** `accepts` is an abstract predicate |
| Zero-knowledge | **Honest-verifier only.** The deployed protocol is a Fiat–Shamir NIZK |

### The trust base, in full

Nothing else is assumed anywhere in `lfzk/`; there are no `sorry`, no custom
`axiom`, and `#print axioms` on every top-level theorem returns
`[propext, Classical.choice, Quot.sound]`.

**Cryptographic — 2.**

* `IsLigeroSound` (`ligero_sys.lean`) — Ligero's knowledge error. Every Longfellow-shaped fact
  about Ligero is *derived* from it (`isLigeroKnowledgeSound_of_sound`, `zkRowsHold_of_sound`,
  `ligeroInputRow_of_sound`).
* `IsLigeroZeroKnowledge` (`zk_sim.lean`) — Ligero's hiding error, in distinguisher form so the
  simulator may use its own coins.

**Arithmetization — 6, all with one root cause.**

* `ArithmetizedCircuit.arith`;
* `LayeredCircuit.layer_rel`, `.V_local`, `.Quad_affine_beta`;
* `EqqAgree` and `LayeredInputMLE` (`ligero_bridge.lean`).

All six exist because `ArithmetizedCircuit` and `LayeredCircuit` are *abstract*. A construction
of a `LayeredCircuit` from a compiled circuit would discharge five of them at once, and the
counted term that weakens the sixth is already proved (`initial_point_bad_card`). This is the
largest single reduction in assumption count available.

**Fiat–Shamir — 2.**

* `IsNonAdaptiveRun.prover_eq` / `IsLayerNonAdaptive.prover_eq` — round `i`'s polynomial is
  fixed before challenge `i` is drawn from it. Structural, and true of the implementation.
* The challenge sequence being a *coordinate* of `Ω`. This is the idealisation, and it is at
  least visible in the shape of the sample space and provably the best case (`card_le_K_mul`,
  `regular_fiber_card`) rather than hidden in a constant.

**Verifier model — 1.**

* `IsWellFormedTranscript.round_count` — an accepted run has `logc + 2·logw` rounds. The *only*
  property of `accepts` any theorem uses.

### Main gaps

1. **This proof verifies the protocol, not the code.** No theorem here mentions 
  `ZkVerifier::verify`, the Rust or the C++ library. `accepts` is an abstract predicate. 
   The model was written *against* the sources and the documented
   correspondences are specific (see §"Modelling details" for the known divergences). A future
   aim is to build a solid correspondence using tools like verus.
2. **Ligero cryptographic content is a black box.** `eps_FSK` and `eps_hide` are
   free parameters. What is proved is "if Ligero is a knowledge-sound, hiding commitment with
   these errors, then Longfellow inherits these bounds". Ligero's own argument, interleaved
   Reed–Solomon proximity, is the part with real mathematical content, and it is not yet here.
   `ligero_rs.lean` proves the code geometry and the column test; `merkle/` proves binding and
   hiding from collision resistance; neither is connected to `eps_FSK`, because that needs a
   tableau model this development does not have.
3. **The ZK result is not the deployed property.** `longfellow_hvzk` is honest-verifier ZK:
   the challenge sequence is an *input*, given and identical on both sides. The deployed
   protocol is non-interactive via Fiat–Shamir, and a NIZK simulator has to program the random
   oracle.  Under Fiat–Shamir the blinders-to-transmissions map also stops being a translation
   and becomes triangular, so even the pad argument needs reproving by induction over rounds.

### What is nonetheless solid

* **The reduction is complete and the counting has no unexplained constants.** `3/|F|` is
  derived from three counted events and `d = 2` comes from the arithmetization. On the
  one-layer path `K` and `|S|` are pinned down and cancel (`card_le_K_mul`,
  `pair_fiber_le_one`), giving the textbook `n·d/|F|`, and
  `multi_layer_soundness_probability_all_derived` performs the same cancellation for a whole
  run. A reader who accepts
  the eleven items above gets the bounds with nothing further taken on faith.
* **Causality is structural, not narrative.** Which coordinate of the sample space each object
  may read *is* the faithfulness statement, and it is enforced by the types:
  `core_soundness_protocol_order` types the extractor at `D₀ → …` so it cannot see a challenge,
  and `buildSystem`/`buildSystemMulti` have no `Witness` argument so the system handed to
  Ligero is public by construction.
* **Unit tests for our theorems.** Every theorem gets a concrete witness, e.g., an unsatisfiable
  circuit the verifier accepts, and several are tight (`eps_sumcheck ≥ 50` at `|Ω| = 125`;
  the per-layer `alpha` count exact at `1`; the multilinear root count exact at `k = 1`).

---

## Soundness Details

### The sample space is the protocol's randomness schedule

A run draws its field elements at distinct moments, and the sample space is built to match. For
one layer:

```
Ω  =  ((D₀ × challenges) × (beta, alpha)) × alpha_in
```

| | drawn by | read by |
|---|---|---|
| `alpha`, `beta` | `begin_layer`, before the layer's messages (`symbolic_sumcheck_verifier.rs:L73`) | the layer relation |
| sumcheck challenges | `round`, one per message | the round reduction |
| `alpha_in` | `elt_field`, after every layer has closed (`symbolic_sumcheck_verifier.rs:L247`) | the input-binding row |

`alpha` combines the two inherited claims; `beta` replaces the coefficient of every assert-zero
gate (`prep_v`, `quad.h:L213`); `alpha_in` is used by the single combined input row, in all four
places it occurs — the coefficients `b_i = eq0_i + alpha_in·eq1_i`, the `pub_binding` constant,
the combined claim `got = wc0 + alpha_in·wc1`, and the second claim pad's coefficient. Sharing
one draw between the layer relation and the input binding would make the model *stronger* than
the protocol: it would let them fail together on a single unlucky draw, which no prover can
arrange.

Causality is expressed by *which coordinates each object may read*, and this is where the
model's faithfulness lives:

* the extractor is `E_pre : D → …` — it sees the commitment and nothing else, because
  `ZkProver::commit` (`rust/runtime/zk/src/prover.rs:L44`) fixes the witness and pad before the
  transcript exists;
* the transcript is `T_pre : D × (F × F) → EncTranscript` — the prover's messages *may* depend
  on the layer pair, since `begin_layer` runs first;
* `alpha_in` is read by nothing else, which is what makes its `1/|F|` collision bound sound.

The multi-layer composition uses the same shape, `Ω = (D × (beta₀, alpha₀)) × alpha_in` with
`|Ω| = |D|·|F|³` (`card_runSpace`), and the beta *schedule* `Function.update tail 0 beta₀` — so
layer 0's coefficient is the sampled coordinate while later layers keep a fixed tail, which is
what the degeneracy count needs.

**The causal order.** `core_soundness_protocol_order` states the one-layer result over

```
Ω  =  ((D₀ × (beta, alpha)) × round challenges) × alpha_in
```

with `E_pre : D₀ → …` — the extractor reads the **commitment only**, matching `ZkProver::commit`
fixing the witness and pad before the transcript exists. `eps_bind` and `eps_deg` are derived
there rather than supplied. The older `core_soundness_probability_ideal_fs` types the extractor
at `D := D₀ × (Fin n → F)`, so it formally may read the challenge sequence, and the sequence
sits before the layer pair; that is a safe over-approximation of the same count, since widening
what the extractor may see only weakens the hypotheses, but it is not the causal statement.

What made the causal order reachable is stating the counts as *splittings* rather than at a
fixed product: `event_card_le_split` bounds an event on any `Ω` by a count over a product it
factors through, at no cost when the two maps really are a splitting.
`event_alpha_bad_card_split` and `event_degenerate_card_split` are the two counts in that form.

One liberty remains, and it does not affect the count: the layer pair is carried as
`(beta, alpha)`, the reverse of the draw order, since they are drawn back to back with no
message between.

### Where each term comes from

`Event_Fail ⊆ Event_A ∪ Event_B ∪ Event_Degenerate ∪ Event_C`, and:

| Term | Event | Status |
|---|---|---|
| `eps_FSK` | `Event_A` verifier accepted, Ligero extractor returned nothing | **assumed** (`IsLigeroSound.extraction`) |
| `eps_bind` | `Event_B` extraction succeeded but `checkV` failed | **derived**: a random-combination collision, worth `1/\|F\|` |
| `eps_deg` | `Event_Degenerate` the layer challenges `(alpha, beta)` collapsed a non-zero output claim | **derived**: two-variable Schwartz–Zippel, `2/\|F\|` |
| `eps_sumcheck` | `Event_C` the prover was lucky in some sumcheck round | **derived**: `n·d/\|F\|`, with `d = 2` also derived |

### How the verifier is modelled

`accepts : Ω → Prop` is an *abstract* predicate standing for "the ZK verifier accepted this
run". Nothing in the development executes the verifier, so every property of it that the proof
uses has to be stated as a property of `accepts`. There is one:

* `IsWellFormedTranscript.round_count`: an accepted run's transcript has exactly
  `logc + 2·logw` rounds.

This is a *description of the verifier*, not a hypothesis about the adversary, and it is
enforced by construction in the implementation: the loop bound is `clr->logw` read from
`Circuit<Field>` (`verifier_layers.h:L119`), a public circuit parameter, so a prover cannot vary
it, and a proof carrying a different number of rounds does not parse.

Everything else the verifier does *is* modelled concretely: the round checks (`check_round_c`),
the layer-to-layer state update, the final layer identity
`got = EQ[Q,C] · QUAD[G|R,L] · W[R,C] · W[L,C]`, and the `ConstraintBuilder` recursion that
turns the padded transcript into a Ligero constraint system.

### What you have to assume

A reader who accepts the following, and nothing else, gets the bound.

**1. Ligero.** `IsLigeroSound` (`ligero_sys.lean`) is the whole of it, and it is stated the way
a Ligero paper would state it, over an arbitrary public system:

> if the verifier accepts, then — outside the knowledge error `eps_FSK` — the extractor returns
> an assignment satisfying that system.

Two fields, neither mentioning Longfellow: `extraction`, the knowledge error, and `sound`, that
what comes back satisfies the rows. Everything Longfellow-shaped is then a lemma —
`isLigeroKnowledgeSound_of_sound` reads the one-layer bundle off `buildSystem_Sat`,
`zkRowsHold_of_sound` reads a whole run's rows off `buildSystemMulti_Sat`, and
`ligeroInputRow_of_sound` the input row. `fiber_lift` turns a per-coin error, which is how a
Ligero theorem states it, into the global count `eps_FSK` is used at. Ligero's Reed–Solomon
internals are not modelled; *this is the one genuinely cryptographic assumption.*

**2. Arithmetization is correct.** `ArithmetizedCircuit.arith`: for an unsatisfied circuit the
honest layer claim `S(alpha, beta)` is **not identically zero on `F × F`**. This is the
correctness of the circuit compiler (`QuadCircuit::mkcircuit`), which is not modelled here; a
separate directory in this project works on it.

**3. Fiat–Shamir.** `IsNonAdaptiveRun.prover_eq`: round `i`'s polynomial is fixed before
challenge `i` is drawn from it. This is structural because `ts.round(hp)` derives `r_i` from a
transcript that already contains `p_i`. The challenge sequence being a *coordinate* of `Ω` is
the ideal-Fiat–Shamir idealisation, discussed under §"The Fiat–Shamir term".

**4. Two refinement conditions on the multi-layer track**, both of which a construction of a
`LayeredCircuit` from a compiled circuit would discharge, and which exist because
`LayeredCircuit` is abstract:

* `EqqAgree`: the verifier's public layer coefficients are the ones the model computes along
  the run. Kept as a separate condition rather than folded into the system precisely so it
  cannot smuggle secret data into what is supposed to be public.
* `LayeredInputMLE`: the input layer's value function is the multilinear extension of the
  committed columns. The layered twin of `W_mle_is_mle`, which on the one-layer path is
  definitional.

Everything else about the arithmetization is *data*, not assumption. `ArithmetizedCircuit`
carries a gate table and the two halves `pub_col` / `priv_col` of the input wire vector, and
`QUAD` and `W` are **constructed** from them as multilinear extensions. So `Quad_mle` is
multilinear in each hand (`Quad_mle_ml_l` / `Quad_mle_ml_r`) and affine in `beta`
(`Quad_mle_affine_beta`, because `prep_v` is), `W_mle` is a multilinear extension of the wire
vector (`W_mle_is_mle`, definitional), and the public wires do not depend on the witness
(`W_col_pub`), since the wire vector *is* `pub ++ priv`.
`quadMle` models `Quad<Field>`'s **sparse** gate list, not a dense coefficient table.

### What is proved

#### The Ligero side

* **`builder_finalize_soundness`**: the linear row emitted by `ConstraintBuilder::finalize`
  (`zk_common.h:L373`), together with the quadratic pad relation, forces
  `CLAIM = EQQ · (W_hat[L] + dW[L]) · (W_hat[R] + dW[R])`.
* **`input_row_soundness`, `input_row_coeffs_give_mle`, `input_row_binds_hands`**: the single
  input row of `ZkCommon::input_constraint`, acting on the committed witness columns, forces the
  prover's claimed hand evaluations to equal the honest multilinear evaluations of the extracted
  witness. This is the witness binding; at most one `alpha_in` escapes it.
* **`pub_consistent_of_indep`**: public-input consistency is a theorem, not an extractor
  obligation: `pubBinding` computed from any witness is the same value.
* **`builder_next_eval`, `builder_run_verifies`, `EncTranscript.rounds_verify`**: the
  `ConstraintBuilder` recursion tracks the verifier's claim exactly, and the sumcheck rounds of a
  builder run always close on the decrypted expression `e(pad)`. The ZK path *substitutes*
  `p(1) = claim − p(0)` rather than checking it, so every round check passes by construction.
* **`ZkLayer.first_matches_next_state`**: the pad overlap. `ConstraintBuilder::first` reads
  `CLAIM_PAD[layer − 1]`, which is the previous layer's `CLAIM_PAD[layer]` (`PadLayout`,
  `zk_common.h:L207-L213`); its value *is* the claim the sumcheck verifier carries forward. This
  is what makes the two sides composable.
* **`buildSystem` / `buildSystemMulti` and their `_Sat` characterisations**: the Ligero **rows**
  separated from the **assignment** that satisfies them, shown to be the same rows the soundness
  side already uses. The point is the *type*: neither has a `Witness` argument, so the system
  handed to Ligero is public by construction rather than by argument. That is what makes both
  the sequential ZK composition and the generic soundness interface valid.

#### The sumcheck side

* **`sumcheck_multi_reduction`**: if the verifier accepts a round sequence starting from a false
  claim, then either the final claim is wrong or some round was a lucky guess.
* **`layer_step`, `layers_reduction`**: `layer_step` turns "the claims
  entering layer `ly` are wrong" into "a round of layer `ly` was lucky, or the claims entering
  layer `ly+1` are wrong", using the `got == claim` check and the state update at
  `verifier_layers.h:L182-L197`. `layers_reduction` iterates it to the input layer, where
  `input_row_binds_hands` pins the claims to the committed witness. This needs **no** `EQQ ≠ 0`
  condition.  While almost all other aspects of GKR have been superceded in this protocol,
  this is its one idea that remains.
* **`layer_sumcheck_poly`** sums the `G` variable over the `nv` **gate corners**, which is what
  `bind_g` does (`quad.h:L153`): it iterates over gates and looks each gate's corner up in
  `dot = raw_eq2(logv, nv, G0, G1, alpha)`. `logv_one_poly_ne_zero` (`example.lean`) is the
  regression guard.
* **`ca_split`, `consistent_generate`, `head_generate`, `get_last_eval_generate`**: the
  hypercube-splitting lemmas, from the bijection `j ↦ (j/2, j%2)`. These discharge the facts
  about honest round polynomials that the reduction needs.
* **`final_binding`**: `EQQ · W[R,C] · W[L,C]` equals the honest layer polynomial at the
  transcript's challenge point.
* **`zk_layer_verifies`, `zk_layers_verify`, `zk_multi_layer_soundness`**: a whole ZK proof
  drives `VerifierLayers::layers` to accept, and if the claims it starts from are wrong then some
  layer's sumcheck round was lucky or the input-layer claims are wrong.

#### The multi-layer track

`LayeredCircuit.Quad` takes `beta`, exactly as `ArithmetizedCircuit.Quad_mle` does, with a
`Quad_affine_beta` field mirroring the single-layer theorem. `ZkLayer` carries `alpha`; `beta`
comes from the run's **beta schedule** `betas : ℕ → F`, with `betas ly` what `begin_layer` draws
at layer `ly` — a challenge indexed by layer, not data the prover supplies. `LayeredCircuit.V`
is therefore schedule-indexed and `layer_rel` is stated at the layer's own challenge:

```
layer_claim (Quad ly (betas ly)) (V (ly+1) w betas) alpha st = V ly w betas g0 q + alpha · V ly w betas g1 q
```

Indexing `V` by the schedule rather than quantifying `layer_rel` over `beta` is what makes the
two-variable Schwartz–Zippel count meaningful. On a *satisfying* assignment every assert-zero
product is zero, so `prep_v`'s substitution multiplies zero and is invisible; only for a
witness that **violates** an assert-zero gate do the layer's values pick up `beta ·` (the
violation). With a `beta`-free right-hand side `Degenerate` is provably independent of `beta`,
and the count would be bounding a one-variable form.

A `V_local` field records that `V ly` reads only `betas i` for `i ≥ ly`. That keeps the layer-0
count honest: when `betas 0` is the sampled coordinate, `V 1 w betas` must be constant on the
fiber. `betas_tail_eq` is the lemma that uses it, and `mevent_degenerate_card` samples the
schedule as `Function.update tail 0 b`.

* **`zero_claims_wrong`**: with the verifier's initial claims both zero, non-degenerate layer-0
  randomness *forces* the starting claims to be wrong. `degenerate_at_schedule` computes the
  degeneracy as "the honest combined output value vanishes", at the run's own `betas 0`.
* **`degenerate_agrees`, `arith_gives_layered_nonvanishing`**: the two tracks' degeneracy
  predicates coincide given `Quad 0 β = Quad_mle c β` and `V 1 w betas = W_mle inp w`, and
  `arith` discharges the multi-layer non-vanishing condition. So `LayeredCircuit`'s layer 0 and
  `ArithmetizedCircuit`'s only layer are the same layer, not two unrelated abstractions.
* **`ZkLayerRow`** takes the starting expression as a **parameter**, and `ZkRowsHold` supplies
  the one the verifier actually builds: `Expression.zero` at layer 0, matching
  `claims_state.claim = [Expression::zero, Expression::zero]`, and `builder_first` on the
  previous layer's `wc`s and claim pads at an interior layer, matching
  `claim.axpy(claim[0], 1); claim.axpy(claim[1], alpha)`. At layer 0 the first conjunct then
  *says* the run starts from a zero output claim; at interior layers it becomes a theorem
  (`zkExpr_some_eval`).
* **`zkRowsHold_of_sound`** derives the run's rows from `IsLigeroSound`. The system is built by
  `zkLayerRowDatas` from **public data only**, the transmitted layers and the verifier's own
  coefficients — with the tie back to `LayeredCircuit.eqq` left to `EqqAgree`.
* **`claimsCorrect_of_inputRow`, `mevent_input_card`**: the multi-layer twin of
  `input_row_binds_hands`, and its count. `zkFinalState_last` identifies the run's final claims
  with the last layer's `wc + pad dw`; the input row forces their `alpha_in`-combination to match
  the committed columns' MLEs at that layer's two hand points; a fresh `alpha_in` separates them,
  at `1/|F|`.
* **`multi_layer_soundness_all_derived`**: the assembly over an abstract sample space, with
  the protocol's causality supplied as splittings, for each challenge the verifier sends, a
  pair of maps saying "everything decided before it" and "it". The bound is
  `eps_FSK + nl·|Dα| + nl·K·|S|·n·d·|F|^(n−1) + |Dbind| + 2·|Ddeg|·|F|`.

* **`multi_layer_soundness_probability_all_derived`** is the same statement with the splittings
  strengthened to **bijections**, which is what the protocol's sample space actually is: at
  each challenge the run decomposes as "everything before it" times "it", nothing left over and
  nothing repeated. That buys the three things the count was missing. Every cardinality equality
  is *derived* (`card_of_split_bij`) rather than assumed; `K` disappears, since a bijective
  splitting at the round challenges makes `pair_fiber_le_one` give `K = 1`; and the conclusion
  is the probability itself,

  ```
  Pr[accepts ∧ extraction fails]  ≤  eps_FSK/|Ω|  +  3/|F|  +  nl·(1 + n·d)/|F|
  ```

  so a reader has no arithmetic left to perform. This is the statement to audit.

#### The randomness terms

Three challenges per layer-plus-input-binding, and all three are counted.

* **`layer_claim_affine`, `layer_claim_affine_quad`**: the honest layer claim `S(alpha, beta)` is
  affine in `alpha` (the verifier combines the two inherited claims linearly) and affine in
  `beta` (`prep_v` substitutes `beta` for each assert-zero coefficient), i.e. a bilinear form.
  This is what turns degenerate randomness from an assumption into a countable event.
* **`event_b_subset`**: a pad and witness columns satisfying the Ligero rows force
  `Transcript.checkV = true` unless the run hits the one bad `alpha_in`.
* **`bilinear_corners_iff`**: a bilinear form vanishes identically on `F × F` iff it vanishes at
  the four corners `{0,1}²`. This is why `arith` can be a finite condition even though the
  challenges range over the whole field.
* **`affine_root_card`, `bilinear_zero_card`**: two-variable Schwartz–Zippel, a bilinear form
  that is not identically zero vanishes on at most `2·|F|` of the `|F|²` pairs.
* **`option_bad_pairs_card`, `event_alpha_bad_card`**: `alpha_in` is the *last* coordinate, so
  fixing the prefix fixes both the extracted witness and the transcript's `wc0`/`wc1`. The two
  quantities the input row must separate are then constants and at most one draw is bad
  `1/|F|`.
* **`degenerate_pairs_card`, `card_filter_fst_le`, `event_degenerate_card`**: the degenerate
  event is decided by the prefix alone and never reads `alpha_in`, so the Schwartz–Zippel count
  `|D|·2|F|` is carried across that whole coordinate, `2/|F|`.

#### The Fiat–Shamir term

* **`univariate_roots_bound`, `bad_round_roots`, `combinatorial_fiat_shamir`**: at most
  `n · d · |F|^(n-1)` of the `|F|^n` challenge sequences let a non-adaptive prover cheat. This is
  a root count, with no random-oracle axiom.
* **`IsFiatShamirFamily`, `combinatorial_fiat_shamir_indexed`**: the strategy is indexed by the
  **pre-challenge state** `S`, everything the run decides before the challenges, and the root
  count applies fibrewise over it, giving `|S| · n·d·|F|^(n-1)` out of `|S|·|F|^n`, still
  `n·d/|F|`. The index is not a convenience: round 0's prefix is empty, so a state-free strategy
  would need one honest polynomial for every accepted run, and `honest_polys_need_state`
  (`example.lean`) shows the honest round polynomial `(1 − r)(1 + alpha)` differs between
  `alpha = 0` and `alpha = 1`. Since `alpha` is a coordinate of `Ω`, the state-free form was not
  merely strong but false there.
* **`multi_round_bad_event_exists`, `challenge_pullback_bound_indexed`,
  `sumcheck_ci_of_nonadaptive`**: that count transfers to the sample space, giving
  `eps_sumcheck = K · |S| · n · d · |F|^(n-1)`, where `K` bounds the fibers of the *pair*
  `(state, challenge_map)` — how many runs share both a pre-state and a challenge sequence.

`K` appears because `event_card` counts over `Ω` while the root count is over challenge
sequences, and is pinned down through `card_le_K_mul`, `IsRegularChallengeMap`, `split_fiber_card`,
`pair_fiber_le_one`, and  `sumcheck_prob_of_split` and `core_soundness_probability_ideal_fs`.

This does not remove the idealisation, it relocates it. In the real protocol
`r_i = H(transcript_i)` is *determined* by `ω`, not an independent coordinate of it; making it a
coordinate is the ideal-Fiat–Shamir model. What is gained is that the idealisation is visible in
the shape of the sample space and provably the best case, rather than hiding inside an
unexplained constant. It is also not wishful: the relation being dodged is "`cs i` is a root of
a degree-`d` polynomial determined by the prefix", which is efficiently searchable, and
correlation-intractable hash families for that class are known from sub-exponential LWE.
Formalizing that is out of scope.

### Non-vacuity

The theorems bound the size of a *bad* event. Such a bound is worthless if the hypotheses are
unsatisfiable (the theorem is then `False → anything`) or if they secretly force the bad event to
be empty (the bound then reads `0 ≤ eps`). Neither failure is caught by type-checking, so
`example.lean` carries an explicit instance for each, built in the regime the theorems are
*about*: an unsatisfiable circuit that the verifier nevertheless accepts.

1. The prover sends the zero polynomial where the honest one has `P(0) + P(1) = 1`; the round
   check passes because `0 + 0 = 0`, and the challenge `r = 1` happens to be the root of `p − P`,
   so the verifier accepts. Every hypothesis of `core_soundness_theorem` holds anyway.
   `Event_Fail` is *all* of the sample space, `eps_FSK`, `eps_bind` and `eps_deg` are each
   provably `0` here, so the bound is `1 ≤ 1` — **tight** — and `eps_sumcheck_forced` reads off
   that any admissible `eps_sumcheck` is `≥ 1`. The sumcheck term is load-bearing, not padding.
2. `probability_eps_sumcheck_forced` runs that same cheating prover over the protocol's real
   sample space, `(Unit × (F5 × F5)) × F5` — `125` points, one per setting of the layer pair and
   `alpha_in`. This tests something the `Ω = Unit` instance structurally cannot: there all three
   challenges are forced to `0`, so no hypothesis is ever evaluated at a second value. Here every
   hypothesis must hold at all `125`, and they do. `Event_Fail` is again everything, so the bound
   reads `1 ≤ 3/5 + eps_sumcheck/125` and forces `eps_sumcheck ≥ 50`: the `3/|F|` charged for the
   three challenge collisions provably cannot cover a cheating prover on its own. `prob_ci`
   supplies `eps_sumcheck = 125`, so the admissible range is non-empty.
3. `zk_multi_layer_soundness_applies` is a two-layer ZK proof over a degenerate `LayeredCircuit`
   whose Ligero rows all hold and which drives `VerifierLayers::layers` to accept, starting from
   claims that are wrong. `ZkRowsHold`, `LayersShapeOK` and `GoodRandomness` are jointly
   satisfiable *with wrong claims*, so the layer reduction's conclusion is about a reachable
   situation.
4. `multi_layer_soundness_applies` / `multi_layer_failure_nonempty` run the same against the
   merged multi-event statement. Two of its terms come out provably `0`, so the surviving bound
   is `2·eps_round + eps_bind` and the per-layer `nl ·` factors are exercised rather than
   absorbed.
5. `beta_bites` / `no_beta_independence` test that `beta` is not decoration. Every other instance
   has `QUAD ≡ 1` — an ordinary gate, nothing for `prep_v` to substitute into. `myLCb` is the
   smallest instance where it does: layer 0 is a single **assert-zero** gate, `Quad 0 b ≡ b`, and
   the layer-1 values are non-zero, so the constraint that gate asserts is violated. The
   degeneracy holds at `beta = 0` and fails at `beta = 1` — same run, same `alpha`.
6. `ideal_fs_applies` / `honest_polys_need_state` test the Fiat–Shamir half.
   `ideal_fs_applies` discharges every hypothesis of
   `core_soundness_probability_ideal_fs` over a `625`-point sample space, with the strategy family
   reading `alpha` out of the pre-state; `fs_failure_event` confirms the failure event is all
   `125` accepted runs rather than empty.
7. `LigeroSoundExample.sound1` inhabits `IsLigeroSound` at a system with a real row and a real
   quadratic triple, at knowledge error `0`, so the bridges are not implications from an
   unsatisfiable premise.
8. `MlinExample` (`mlin.lean`) tests the multilinear root count, by computation rather than by
   argument. At `k = 1` the identity has exactly one zero out of five and the bound is `1` —
   **tight**. At `k = 2` the product `v₀·v₁` vanishes on `9` of the `25` points against a bound
   of `10`, so the count is neither vacuous nor far off. And `hne_needed` shows the hypothesis
   is load-bearing: the zero function has all `25` points as zeros, exceeding the bound, so
   `mlin_zero_card` cannot drop it.
9. `myf_quadratic` / `myP_deg` instantiate the degree bound: `QuadraticAt` holds for this
   instance's layer polynomial and `sumcheck_round_poly_natDegree_le_two` then gives
   `natDegree ≤ 2` for its round polynomial. Note the instance has `logc = 1`, `logw = 0`, so
   what is exercised is a *copy* coordinate — affine here even though copy rounds are cubic in
   general. No witness in the file has `logw ≥ 1`, so the hand-variable multilinearity that the
   general degree bound rests on is not exercised by an instance; it is a theorem
   (`Quad_mle_ml_l` / `Quad_mle_ml_r`, `W_mle_multilinear`) rather than an assumption, but the
   non-vacuity discipline does not reach it.
10. `logv_one_poly_ne_zero`: likewise a `logv = 0` instance cannot pin down how the `G` variable is
   summed, since `Vector F 0` is a singleton and a sum over gate corners coincides with a sum over
   `F^logv` there. They differ sharply for `logv ≥ 1`: summing over `F^logv` makes the layer
   polynomial **identically zero** over any prime field with `|F| > 3`, because
   `∑_{x∈F} x = ∑_{x∈F} x² = 0` collapses every `eq`-orthogonality sum. That would force
   `eval ≡ true` and make the whole development vacuous.

11. `pl_alpha_card` / `pl_alpha_nonempty` / `pl_alpha_exact` test the **per-layer** claim
    combination, which the earlier multi-layer instance structurally could not: it sits at
    `Ω = Unit`, where the space has no `alpha` coordinate to split at, and `zk_rand_ok` proves
    the event is *empty* there. This instance has the coordinate — `Ω = Unit × F5`, layer `0`
    carrying the sampled `alpha`. `myLC.V` is `1 − q₀` at copy point `0`, so both honest layer-0
    values are `1` while the verifier starts from claims of `0`: the claims really are wrong.
    Then `1 + alpha·1 = 0` has exactly one solution in `F5`, and the event has exactly one
    point against a bound of `|Unit| = 1` — **tight**. Both causality hypotheses of
    `mevent_randAt_card_split` are discharged by computation on the run, not assumed.

**What this does not reach.** `mevent_roundAt_card` and `IsLayerNonAdaptive` still have no
instance. The run above makes the round event non-empty for the right reason, layer `0`'s
honest polynomial is `(1+alpha)(1−X)³` and the transmitted one is zero, so at challenge `1` the
prover is lucky — but exhibiting it needs `generate_true_polys` and `sumcheck_round_poly`
evaluated concretely, which no lemma here does yet; the existing instances bound the round
events by `card_le_univ` instead. And no witness has `logw ≥ 1`, so the hand-variable
multilinearity the general degree bound rests on is exercised as a theorem
(`Quad_mle_ml_l` / `Quad_mle_ml_r`, `W_mle_multilinear`) but never at an instance.

---

## Zero-knowledge details

### The construction

The simulator argument is *sequential*: sample the transmitted values, derive the Ligero
constraint system from them, then invoke Ligero's own simulator on that system. That only works
if the system is a function of public data and transmitted values, i.e., no witness.
This witness-freeness is enforced by Lean rather than argued.

`ZkSetup` is the data of one run: the honest transmission `honest : Witness → Chal → Fin nb → F`,
the pad `padOf`, the committed columns `wcol`, the system `sys : Chal → (Fin nb → F) →
LigeroSystem`, and one law, `honest_sat`, the honest run satisfies its own system.
`realTranscript` and `simulate` are then the two families `longfellow_hvzk` compares.

`zkSetupOfRun` builds one from the model's own pieces, for a whole `nl`-layer run:

* **The pad layout is computed, not assumed.** `RunPad` states the layout as data with laws and
  `stdRunPad` constructs the standard `PadLayout` one, for any number of layers. `stdSlots` places layer `ly` at base `ly · layerSize logw`;
  `finProdFinEquiv` is the blinder bijection; `nb = nl · (4·logw + 2)`. The pad is *defined* by
  asking which layer-and-blinder pair an index is — well posed because `blindSlot_inj` says the
  map `(layer, blinder) ↦ pad index` is injective across the whole run and
  `quadSlot_ne_blindSlot` says no layer's quadratic slot is any layer's blinding slot. Both come
  from one multiplication fact, `base_le_of_lt : ly < ly' → ly·S + S ≤ ly'·S`, which is what
  replaces dividing by the symbolic stride `4·logw + 3`.
* **Quantified over the runtime's full challenge schedule.** `Chal = RunChal logw nl F` is a
  record of every challenge the verifier sends: `rounds ly`, `alphas ly` and `betas ly` per
  layer, and one `alpha_in`. So `honest_sat` — hence `longfellow_hvzk` — holds at *every*
  challenge sequence. Each is read where the runtime reads it: `runStartExpr` reads `alphas ly`
  (`begin_layer`, at the top of iteration `ly`, `symbolic_sumcheck_verifier.rs:L73`), and only
  the input row reads `alpha_in` (`L247`, after the loop closes). Keeping those two distinct
  matters: one shared draw would let the layer relation and the input binding fail together,
  which is not something a prover can arrange, so the model would be stronger than the
  protocol. `zkSetupOfLayer` takes `alpha beta alpha_in` for the same reason. Everything the
  challenges determine is a function of them — `P`, `wl`, `wr`, `eqq`, `bcoef`, `pub_binding`.
  `wcolOf` takes them too, but only so the columns can be *read* at a challenge-determined copy
  point; the columns themselves are fixed by `ZkProver::commit` before any challenge exists,
  which is what makes the sumcheck sound.
* **`honest_sat` is derived, and so are the claims it rests on.**
  `honest_buildSystemMulti_Sat` reduces it to the per-layer quadratic triples
  (`RunPad.pad_quad`), the per-layer final claims, and the last layer's claim blinding
  (`runHonestClaimBlinding`), plus public-input consistency and the input-row identity the
  soundness side already proves. The final claims are the parameter `hclaim`, and
  `runHonestFinalClaim` produces exactly that parameter from the honest run's own data — the
  blinded transmission, the true round polynomials and the layer relation — through
  `honest_final_claim_from` and `honestRounds_of_roundData`. That lemma takes the starting
  expression as a parameter, which is what interior layers need, since they start from
  `ConstraintBuilder::first` on the previous layer's `wc`s rather than from `Expression.zero`.

### What you have to assume

`IsLigeroZeroKnowledge eps_hide`: for every constraint system and every satisfying assignment,
no test distinguishes Ligero's real proof from its simulation by more than `eps_hide`. The
simulator's coin space is its own. This is the only assumption on this side.

Inside that box sit the facts that make `eps_hide` small, none of them modelled here:

* per-block randomness `RANDOM[R]` with `r = nreq` (`ligero_param.h:L154`), which makes the
  column-opening interpolation square,  `w + nreq = BLOCK` determines the row polynomial;
* the three blinding rows, one per disclosure, each dimension-matched exactly: ILDT's `block`
  against `y_ldt`; IDOT's `dblock − 1` against `y_dot` modulo the public linear functional;
  IQUAD's `r + block − 1` against `|y_quad_0| + |y_quad_2|`;
* "the indices of XD must be distinct from the indices of BLOCK_EXT", which `ligero_param.h`
  itself flags as a zero-knowledge requirement;
* the Merkle commitment being statistically hiding, which is the *only* reason `eps_hide` is not
  zero.

### What is proved

**The pad blinding is perfect.** `PadLayout` is transliterated from `zk_common.h:L193-L247`.
`blindIdx_injective` shows a layer's blinding slots are contiguous hence distinct;
`layer_blind_disjoint` shows consecutive layers blind with disjoint slots even though their
windows overlap by the claim-pad triple (`claim_pad_overlap`); `blindSlot_inj` and
`quadSlot_ne_blindSlot` are the same two facts for a whole run. `blindEquiv` is the one-time pad
as an `Equiv`, and `exists_pad_explaining` says that for *any* witness and *any* wire content
there are pad coins producing exactly that content — perfect hiding of the transmitted round
polynomials, with no probability and no distinguisher.

**Sumcheck completeness.** `builder_run_verifies` says the rounds always close on
`evaluates_to e pad`, for *any* prover — the ZK verifier substitutes `p(1) = claim − p(0)` rather
than testing it. What it does not say is *which* value that is. `sumcheck_multi_completeness`
supplies the other half: when the transmitted triples agree with the true round polynomials at
`0`, `1` and the challenge, the run closes on `get_last_eval` of the honest chain. Two
expressions for one value, so `honest_run_final_value` reads off the layer polynomial at the
transcript's own challenge point and `honest_final_claim` factors it through
`layer_poly_factors`. Completeness needs no degree bound and no field-size condition.

**The honest prover meets that hypothesis.** `HonestRounds` is not something a caller has to
assume: `honestRounds_of_roundData` derives it for a layer whose transmitted pairs are the
blinded true evaluations. Three pieces make it go through.
`RoundPoly.eval_lagrange_eq_of_agree`, a transmitted triple agreeing with a degree-`≤2`
polynomial at `0`, `1`, `pt2` reproduces it at *every* challenge, because the difference has
degree `≤ 2` and three distinct roots; this is the exact converse of `univariate_roots_bound`.
`padOfBlinders`, `exists_pad_explaining`'s construction as a *function*, which is what
`ZkSetup.padOf` needs. And an induction: `RoundData.unpad` *defines* `eval1` as `claim − eval0`
rather than transmitting it, so `eval1 = P(1)` holds exactly when the incoming claim is the true
one — which is the sumcheck chain, hence `unpad_agrees` threaded over the rounds.

**The challenge parameter is load-bearing**, checked rather than assumed.
`zkSetupOfRun_honest_round` shows the honest transmission at a round slot is that round's true
polynomial at `0`, so the round challenges reach the wire through `P`; `zkSetupOfRun_honest_ne`
shows two sequences with different hand evaluations give different transcripts.

**Where the pad indices are constrained.** `RoundData` carries `pp0`, `pp2` as free `Fin M`
data. That is a deliberate generalisation *past* the protocol, where they are computed by
`PadLayout` from the round index and a prover cannot choose them: soundness holds for every
index assignment, including degenerate ones the implementation cannot produce, which makes the
soundness theorems strictly stronger.

Hiding cannot be that general. If `pp0 = pp2` then `tr[0] − tr[2]` is unblinded and puts
`p(0) − p(2)`, a witness-dependent quantity, on the wire. So the constraint is put back where
it is needed. `PadIndicesOK` states it for a bare `EncTranscript` and `padIndices_distinct`
derives what the one-time pad argument uses: every one of a layer's `2·k` blinding slots is
distinct. In the assembled ZK path it is not an assumption at all, the same content is
`LayerSlots.hpp0`/`hpp2`, which `stdSlots` discharges by `rfl`, the indices being
`blindSlot logw ly k` and `blindSlot_inj` giving distinctness.

### Non-vacuity

1. `ZkExample.hvzk_applies` / `wi_applies`. The instance's Ligero system is a real `buildSystem`
   layer row, input row, quadratic triple, read off the transmitted values, and `honest_sat`
   is discharged by `honest_buildSystem_Sat` rather than by `simp` on an empty list.
   `honest_differs` first shows the two witnesses transmit *differently* before blinding;
   `wi_applies` then shows the blinded transcripts are perfectly indistinguishable, which is
   exactly what the pad is for.
2. `StdLayoutExample` evaluates the computed layout at `logw = 2`, `nl = 3`: layer `1`'s blinding
   block starts at `14`, layer `0`'s `wc[0]` blinder sits exactly at layer `1`'s window base (the
   overlap, at a number), and layer `0`'s quadratic slot is the `13` in the gap between the two
   blocks. The pad returns the right blinder and the right product at those indices by
   evaluation, not by hypothesis.

---

## What is not covered

### Soundness

* **Ligero is a black box.** `eps_FSK` is a parameter and nothing here bounds it. See below for
  what would be needed.
* **The compiler.** `arith` is assumed, and in a form stronger than ordinary compiler
  correctness; see assumption 2. There is also no construction of a `LayeredCircuit` from a
  compiled circuit, so `layer_rel`, `EqqAgree` and `LayeredInputMLE` remain assumptions about the
  arithmetization rather than theorems about `QuadCircuit::mkcircuit`.
* **Standard-model Fiat–Shamir.** The challenge sequence is a coordinate of the sample space,
  which is the ideal-Fiat–Shamir / random-oracle model.
* **Copy rounds.** `RoundPoly` matches `WPoly = Poly<3, Field>`: `eval_lagrange` is the degree-≤2
  Lagrange interpolant through `0`, `1` and the field-specific third point `pt2` (`2` for prime
  fields, the generator `X` for `GF(2)[X]/(Q(X))`, where `2 = 0`). The *copy* rounds of the
  **non-ZK** verifier, `VerifierLayers::layer_c`, use `CPoly = Poly<4, Field>` (degree 3) and are
  not modelled. The ZK path does not have them — `zk_common.h:L72` asserts `logc == 0` — so a
  four-point variant is needed only to model `Verifier::verify` directly. This is also why the
  derived `d = 2` is stated at `logc = 0`.
* **`eps_alpha` and `eps_round` for the multi-layer run** are still taken as numbers.
* **The verifier itself.** `accepts` is abstract, so what is proved are properties of an
  algebraic verifier model, not correctness of the Rust `ZkVerifier::verify`. A refinement theorem
  from Rust-produced constraints and acceptance to `buildSystemMulti` / `ZkRowsHold` is absent.

### Zero-knowledge

* **Honest-verifier only.** `ZkSetup.honest` takes the challenge sequence as an *input*. Under
  Fiat–Shamir the challenges are derived from earlier messages, so `honest` would feed back into
  itself and the blinders-to-transmissions map would be *triangular* rather than a translation —
  still a bijection, but proved by induction over rounds rather than by `blindEquiv`.
  Malicious-verifier ZK and NIZK are not covered; the simulator cannot control Fiat–Shamir
  challenges without programming the random oracle. This is the same boundary the soundness side
  sits at.
* **Ligero's hiding is assumed.** `eps_hide` is a parameter, and no concrete commitment has been
  shown to satisfy `IsLigeroZeroKnowledge` — the `ZkExample` instance uses a `Unit` proof at
  `eps_hide = 0`.

### Bounding `eps_FSK` and `eps_hide`: what exists and what does not

The Ligero box has structure rather than being one opaque constant. Three things are needed:

1. **The commitment binds.** Merkle binding is *already formalized in this repository*, in
   `merkle/`: `mh_binding_of_collision` derives binding from collision resistance alone,
   `mh_binding_bound_rom` gives the closed-form ROM bound, and `mh_root_hiding_rom` /
   `mh_opening_hiding_rom` are the hiding side that `eps_hide` rests on. That library builds
   clean with no `sorry` and no custom axiom.
2. **Interleaved Reed–Solomon proximity.** If the committed rows are jointly far from the code, a
   random linear combination of them is far too. **Not proved anywhere here.**
3. **The column test catches a far word.** `t` random column openings hit a disagreement.

`ligero_rs.lean` proves the code geometry and the column test:

* `rs_agree_card_lt` — distinct polynomials of degree `< k` agree at fewer than `k` evaluation
  points, the classical root-counting argument;
* `rs_min_distance` — hence distinct codewords differ in more than `n − k` places: the Singleton
  bound met with equality, which is why Reed–Solomon is MDS;
* `rs_unique_decoding` — a word closer than half the minimum distance to two codewords forces
  them equal, which is what makes "the committed row decodes" meaningful;
* `opening_all_agree_card` — **exactly** `|A|^t` of the `n^t` opening sequences land inside the
  agreement set `A`, an equality rather than a bound, since the openings are independent;
* `column_test_bound` / `opening_all_agree_prob` — so a word at distance `e` survives `t`
  openings with probability exactly `(|A|/n)^t ≤ ((n−e)/n)^t`. This is the term `nrequests`
  (`ligero_param.h`) is sized against.

Two things this does **not** do. Nothing here imports `merkle/`: joining it to `eps_FSK` needs a
model of Ligero's tableau — rows, the RS encoding, the three blinding rows, the column-opening
protocol — which this development does not have. And item 2, the step that turns "the column test
passed" into "the rows decode", is untouched; it is a substantial theorem in its own right and it
is the reason `eps_FSK` is still assumed.

---

## Axioms

`#print axioms` on every top-level theorem returns `[propext, Classical.choice, Quot.sound]`.
There are no global `axiom` declarations and no `sorry` anywhere.

---

## Remaining work

In the order they would be taken.

1. **Construct a `LayeredCircuit` from a compiled circuit.** This discharges `layer_rel`,
   `V_local`, `Quad_affine_beta`, `EqqAgree` and `LayeredInputMLE` at once — five assumptions
   that exist only because `LayeredCircuit` is abstract.
2. **Exhibit a concrete sample space satisfying
   `multi_layer_soundness_probability_all_derived`.** The theorem is assembled and concludes
   the probability; what no instance yet supplies is a sample space carrying all four bijective
   splittings at once, so the hypotheses are checked only by type.
3. **Swap `ArithmetizedCircuit.arith` for the cube-level statement.** The counted term that
   pays for the difference is proved (`initial_point_bad_card`, on `mlin_zero_card`); what
   remains is that `arith` is a structure *field*, so restating it cascades through every
   witness and use site. Also needed: that the layer claim really is multilinear in
   `(q, g0, g1)` — true because they enter only through `eq` factors, but not proved.
4. **Open the Ligero box.** The code geometry and the column test are proved (`ligero_rs.lean`)
   and Merkle binding/hiding exist in `merkle/`. What is left is a tableau model to join them
   through, and **interleaved Reed–Solomon proximity**, which is the actual mathematical content.
   This closes `eps_FSK` and `eps_hide` together, and is the largest remaining item.
5. **A `CPoly`-shaped four-point `RoundPoly`**, to cover the non-ZK verifier's copy rounds and
   lift the degree bound to `d = 3` there.
6. **Standard-model Fiat–Shamir**: replace the ideal-challenge sample space with a
   correlation-intractable hash family for the root-finding relation, and put the ideal-FS sample
   space in protocol order.
7. **Refinement to the runtime**: the interleaved challenge order, per-layer `logw`, the Rust pad
   layout, index geometry, and `accepts` against the actual `ZkVerifier::verify`.
