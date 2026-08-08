# Longfellow ZK — Lean formalization

**WORK IN PROGRESS.** These files are a partial formalization of the soundness argument
for the Longfellow protocol (Theorem 6 / Protocol 2.5 of "Anonymous credentials from
ECDSA"). They have not been externally audited. The modeling choices are documented as
*choices*, and several still do not match the implementation in `lib/sumcheck/` and
`lib/zk/`; §"Security analysis" below states exactly what the main theorem does and does not
give you.

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
| `types.lean` | `Expression`, `Pad`, `Transcript`, `Transcript.checkV`, and the generic random-combination collision lemmas |
| `builder.lean` | `ZkCommon::Expression` / `ConstraintBuilder`, `EncTranscript`, and the proof that the rounds close on `e(pad)` |
| `circuit.lean` | Multilinear extensions, the layer polynomial, the hypercube-splitting lemmas, the interpolation degree bound, `ArithmetizedCircuit` |
| `ligero.lean` | The Ligero constraint rows, the witness binding, and the `IsLigeroKnowledgeSound` assumption bundle |
| `fiat_shamir.lean` | `IsFiatShamirTranscript`, correlation intractability |
| `layers.lean` | The `for (ly)` loop, the layer-to-layer reduction, and the induction over all layers |
| `fs_derive.lean` | Deriving `eps_sumcheck = K · n · d · \|F\|^(n-1)` instead of assuming it |
| `lfzk.lean` | Event decomposition and `core_soundness_theorem` |
| `example.lean` | A concrete instance discharging every hypothesis — the non-vacuity witness |

---

## Security analysis

### What the main theorem says

`core_soundness_theorem` (`lfzk.lean`), and its variant `core_soundness_derived_eps` with
the sumcheck term filled in:

> Fix a circuit `C`, a public input `x`, and a family of runs indexed by a finite sample
> space `Ω`. Among the runs on which the ZK verifier **accepts**, the number on which the
> combined extractor `E_prime` fails to output a witness satisfying `C(x, ·)` is at most
>
> ```
> eps_FSK  +  eps_bind  +  eps_deg  +  eps_sumcheck
> ```

This is knowledge soundness in counting form: `event_card` is a raw `Finset.card`, never
normalised by `|Ω|`, so each `eps` should be read as a count of bad runs and compared
against `|Ω|` by the caller. (The Fiat–Shamir bound *is* normalised: `n · d · |F|^(n-1)` out
of `|F|^n`.)

Conditioning on acceptance matters and is explicit throughout: a run the verifier rejects
carries no soundness obligation, and every event in the decomposition carries the
`accepts ω` conjunct.

### Where each term comes from

`Event_Fail ⊆ Event_A ∪ Event_B ∪ Event_Degenerate ∪ Event_C`, and:

| Term | Event | Status |
|---|---|---|
| `eps_FSK` | `Event_A` — verifier accepted, Ligero extractor returned nothing | **assumed** (`IsLigeroKnowledgeSound.extraction_bound`) |
| `eps_bind` | `Event_B` — extraction succeeded but `checkV` failed | **reduced** to a random-combination collision (`event_b_subset`); `alpha_bad_card` bounds it by `1/\|F\|` |
| `eps_deg` | `Event_Degenerate` — the layer coefficient `alpha` collapsed a non-zero output claim | **reduced** likewise; `layer_claim_affine` is what makes it countable |
| `eps_sumcheck` | `Event_C` — the prover was lucky in some sumcheck round | **derived** as `K · n · d · \|F\|^(n-1)` (`sumcheck_ci_of_nonadaptive`) |

### What you still have to assume

The theorem is a reduction. A reader who accepts the following, and nothing else, gets the
bound above:

1. **Ligero knowledge soundness** — `extraction_bound`: on accepted runs the extractor fails
   on at most `eps_FSK` of them. Ligero is treated as an ideal primitive; its Reed–Solomon
   internals are not modelled. *This is the one genuinely cryptographic assumption.*
2. **What the Ligero extractor returns** — `layer_constraint` and `input_row`: the extracted
   pad and witness columns satisfy the rows the verifier fed in
   (`ConstraintBuilder::finalize`, `zk_common.h:L373`, and `ZkCommon::input_constraint`,
   `zk_common.h:L406`). This is the definition of extraction, instantiated at the *actual*
   transcript rather than universally quantified.
3. **Public-input consistency** — `pub_consistent`: the extracted columns agree with the real
   public input on the public wires.
4. **Arithmetization** — `ArithmetizedCircuit.arith`: an unsatisfied circuit has a non-zero
   output claim vector. Since step 7 of the plan this no longer mentions the layer
   randomness at all, which is what let the degenerate case become a counted term.
   `W_mle_is_mle` is definitional: `W_mle` is the multilinear extension of `W_col`.
5. **Transcript shape** — `IsWellFormedTranscript.round_count`: the verifier reads exactly
   `logc + 2·logw` rounds.
6. **Fiat–Shamir**, in two pieces: `IsNonAdaptiveRun` (round `i`'s polynomial is fixed before
   challenge `i` is drawn from it — structural, not a random-oracle assumption), and the
   uniformity constant `K` bounding how many runs share a challenge sequence. `K` is the
   only place a hash assumption enters, and
   `uniform_hash_is_correlation_intractable` isolates it.
7. **The degree `d`** — `IsFiatShamirTranscript.hd`. `sumcheck_round_poly_natDegree_le`
   reduces this to exhibiting a degree-`≤ d` polynomial that agrees with the round function,
   which for `WPoly` rounds is the degree-2 product `QUAD · W[l,c] · W[r,c]`.
8. **The two randomness bounds** `h_bind` and `h_deg`. These are counts, not "never
   happens"; `alpha_bad_card` shows each is a `1/|F|` fraction when the sample space factors
   as "everything decided before the challenge" × "the challenge".

### What it does *not* cover

* **The composition is single-layer.** `layers.lean` proves the layer-to-layer reduction and
  the induction over all layers, but `core_soundness_theorem` still joins the Ligero pad
  machinery to *one* layer's sumcheck. See gap 1.
* **`eps_FSK`, `eps_bind`, `eps_deg`, `K` are parameters.** Nothing here instantiates them
  against a concrete `Ω`. See gap 4.
* **Zero-knowledge is not addressed at all** — only soundness. The pad is modelled as a
  vector the extractor produces, not as a distribution.
* **The bounds are counts, not probabilities.** See plan step 9.

### Non-vacuity

An earlier version of this development was vacuous: `False` was derivable from each of its
three global `axiom`s, and `ArithmetizedCircuit` had no inhabitant with a rejecting `eval`.
Both failure modes are now guarded against:

* `example.lean` builds a concrete instance over `ZMod 5` — a circuit that rejects every
  witness, and a cheating prover the verifier accepts — discharging **every** hypothesis of
  `core_soundness_theorem`, and shows `Event_Fail` is genuinely non-empty there, so the
  bound is doing work rather than bounding the empty set.
* `myLC` and `layers_reduction_applies` do the same for the multi-layer machinery.
* `#print axioms core_soundness_theorem` is `[propext, Classical.choice, Quot.sound]` — no
  custom axioms anywhere in the development, and no `sorry`.

---

## What is actually proved

* **`builder_finalize_soundness`** — the linear row emitted by `ConstraintBuilder::finalize`
  (`zk_common.h:L373`), together with the quadratic pad relation, forces
  `CLAIM = EQQ · (W_hat[L] + dW[L]) · (W_hat[R] + dW[R])`. A faithful transliteration of the C++.
* **`input_row_soundness`, `input_row_coeffs_give_mle`, `input_binding_bad_card`,
  `alpha_separates`, `input_row_binds_hands`** — the single input row of
  `ZkCommon::input_constraint`, acting on the *committed witness columns*, forces the
  prover's claimed hand evaluations to equal the honest multilinear evaluations of the
  extracted witness. This is the witness binding, and at most one `alpha` escapes it.
* **`final_binding`** — `EQQ · W[R,C] · W[L,C]` equals the honest layer polynomial at the
  transcript's challenge point. Formerly assumed; now derived.
* **`builder_next_eval`, `builder_run_verifies`, `EncTranscript.rounds_verify`** — the
  `ConstraintBuilder` recursion tracks the verifier's claim exactly, and the sumcheck rounds
  of a builder run always close on the decrypted expression `e(pad)`. This was
  `IsLigeroKnowledgeSound.accepted_sumcheck`; it is now a theorem, because `next`
  *substitutes* `p(1) = claim − p(0)` instead of checking it, so every round check passes by
  construction.
* **`layer_step`, `layers_reduction`** — the GKR induction. `layer_step` turns "the claims
  entering layer `ly` are wrong" into "a round of layer `ly` was lucky, or the claims
  entering layer `ly+1` are wrong", using the `got == claim` check and the state update at
  `verifier_layers.h:L182-L197`. `layers_reduction` iterates it over the whole run, landing
  on the input layer where `input_row_binds_hands` pins the claims to the committed witness.
  Notably this needs **no** `EQQ ≠ 0` condition — the contradiction goes through without
  cancelling `EQ[Q,C] · QUAD`.
* **`multi_round_bad_event_exists`, `sumcheck_ci_of_nonadaptive`** — `eps_sumcheck` is
  *derived*: `K · n · d · |F|^(n-1)`, from `combinatorial_fiat_shamir` plus the structural
  non-adaptivity of Fiat–Shamir. `core_soundness_derived_eps` is the main theorem with that
  substituted in.
* **`event_b_subset`** — a pad and witness columns satisfying the Ligero rows force
  `Transcript.checkV = true` *unless* the run hits the one bad `alpha`, so `Event_B` is
  contained in the collision event rather than assumed empty.
* **`sumcheck_multi_reduction`** — if the verifier accepts a round sequence starting from a
  false claim, then either the final claim is wrong or some round was a lucky guess.
* **`univariate_roots_bound`, `bad_round_roots`, `combinatorial_fiat_shamir`** — at most
  `n · d · |F|^(n-1)` of the `|F|^n` challenge sequences let a non-adaptive prover cheat
  (for `2 ≤ d`). No random-oracle axiom is used.
* **`RoundPoly.eval_lagrange_zero` / `_one` / `_pt2`, `RoundPoly.toPoly_natDegree`** — the
  transmitted round polynomial is the degree-≤2 interpolant through the three evaluation
  points of `WPoly = Poly<3, Field>`.
* **`lagrange_basis_eval`, `sumcheck_round_poly_eval`** — the "true" round polynomials
  really are the interpolants of the partial hypercube sums.
* **`ca_split`, `sumcheck_eval_round_split`, `consistent_generate`, `head_generate`,
  `get_last_eval_generate`** — the hypercube-splitting lemmas. `ArithmetizedCircuit` and
  `LayeredCircuit` used to assume four facts about the honest round polynomials; three are
  now theorems, and `ArithmetizedCircuit.soundness` / `LayeredCircuit.consistent` /
  `.head_sum` / `.last_eval` are derived. What remains assumed is only the arithmetization
  statement itself (`arith`, `layer_rel`).
* **`sumcheck_round_poly_eq_of_agrees`, `sumcheck_round_poly_natDegree_le`** — interpolation
  below `|F|` is unique, so the degree `d` in the Fiat–Shamir bound can be taken from the
  arithmetization rather than from the field size.
* **`layer_claim_affine`, `ArithmetizedCircuit.claim_ne_zero`** — the honest layer claim is
  affine in the combination coefficient, `S(alpha) = S(0) + alpha·(S(1) − S(0))`. This is
  what turns the degenerate-randomness condition from an assumption into a countable event.
* **`alpha_bad_card`, `layer_alpha_bad_card_prod`** — the random-combination trick costs
  exactly `1/|F|`: splitting the sample space as `D × F`, at most `|D|` of the `|D| · |F|`
  runs hit a bad challenge.

---

## Current gaps

Ordered roughly by how much they weaken the result.

### 1. The layer loop and the ZK/Ligero layer are not yet joined

`layers.lean` models the full `for (ly)` loop and proves the layer-to-layer reduction, and
`ligero.lean` proves the input binding that the induction terminates on. What is *not* yet
done is running the two together: `core_soundness_theorem` still composes the Ligero pad
machinery with a **single** layer's sumcheck.

Joining them means making the ZK side per-layer too. Each layer has its own
`ConstraintBuilder` expression and its own claim pads, and consecutive layers *share* pad
entries — `CLAIM_PAD[layer-1]` of one layer is `CLAIM_PAD[layer]` of the previous
(`PadLayout` at `zk_common.h:L207-L213`). That overlap is the piece to model next.

All layers are also assumed to have the same `logw`; the format allows it to vary per layer
(`sumcheck/circuit.h:L30`), which would mean indexing `Vector F (logw ly)` by the layer.

### 2. Copy rounds (`CPoly`) are not covered

`RoundPoly` matches `WPoly = Poly<3, Field>`: `eval_lagrange` is the genuine degree-≤2
Lagrange interpolant through `0`, `1` and the field-specific third point `pt2`, supplied by
the `SumcheckInterp` class (`2` for prime fields, the generator `X` for `GF(2)[X]/(Q(X))`,
where `2 = 0`). `univariate_roots_bound` bounds by `max 2 d` and `bad_round_roots` requires
`2 ≤ d`.

What remains uncovered is the *copy* rounds of the non-ZK verifier,
`VerifierLayers::layer_c`, which use `CPoly = Poly<4, Field>` (degree 3). The ZK path does
not have them — `zk_common.h:L72` asserts `logc == 0` — so a four-point `RoundPoly` variant
is only needed to model `Verifier::verify` directly.

### 3. The degree bound `d` is still an input

`eps_sumcheck` is derived, but the `d` in `K · n · d · |F|^(n-1)` comes from
`IsFiatShamirTranscript.hd`, which the caller supplies.
`sumcheck_round_poly_natDegree_le` reduces `hd` to exhibiting a degree-`≤ d` polynomial that
agrees with the round function — so `d` is no longer at risk of being forced to `|F| − 1` by
`lagrange_basis` — but no concrete arithmetization here supplies that witness.

`K` is the other input; see assumption 6 above.

### 4. The randomness error terms are not yet instantiated

Both non-degeneracy conditions are *counted*, not assumed:

* `Event_AlphaBad` — the unlucky `alpha` in the input binding `wc[0] + alpha·wc[1]`
  (`zk_common.h:L133`);
* `Event_Degenerate` — the unlucky `alpha` in the layer combination
  `claim[0] + alpha·claim[1]` (`verifier_layers.h:L147`), which collapses a non-zero output
  claim vector.

`core_soundness_theorem` has **no** non-degeneracy hypothesis, and `alpha_bad_card` bounds
each term by `|D|` out of `|D|·|F|` runs. What is *not* done is instantiating that: the
theorem takes `eps_bind` and `eps_deg` as parameters, and a caller must exhibit the `D × F`
factorisation of `Ω` to discharge them. The same holds for `eps_FSK`.

### 5. Inner layers of the constraint builder

`builder.lean` models `Expression`, `ConstraintBuilder::first` / `next` and proves
`EncTranscript.rounds_verify`, so the link between the Ligero constraint system and the
sumcheck is no longer assumed. The `p(0) + p(1) == claim` question is settled too: the ZK
path *substitutes* the relation, so `check_round_c` (which models the non-ZK
`VerifierLayers::layer_h`) passes automatically — the two paths agree rather than being
mixed.

What is modelled is the **layer-0** shape: `EncTranscript.e` starts from `Expression.zero`,
matching `finalize`'s `i0 = ovp_poly_pad(0, 0)` when `ly == 0` (`zk_common.h:L389`). Inner
layers start from `builder_first alpha claim0 claim1 cp0 cp1` and their claim pads overlap
with the previous layer's. `builder_first_eval` and `builder_run_verifies` are stated
generally enough to cover them; wiring the overlap is part of gap 1.

### 6. Bookkeeping

* Counts are absolute; `event_card` is never normalised by `Fintype.card Ω`, so the four
  `eps` terms are only meaningful relative to `|Ω|`.
* `beta` (the assert-zero coefficient, `Quad::prep_v` in `quad.h:L213`) is dropped from
  `layer_sumcheck_poly`.
* Mathlib has no `Fintype (Vector F n)` instance, so `[Fintype (Vector F logv)]` must be
  supplied by hand (`example.lean` does this via the equivalence with `Fin n → F`).
* `∑ g ∈ (univ : Finset (Vector F logv))` in `layer_sumcheck_poly` ranges over the whole
  of `F^logv`, not the boolean hypercube `{0,1}^logv` that `bind_g` sums over.
* `extract_vars` treats the two hands as contiguous blocks of the challenge vector, while
  the implementation interleaves them (`for (round) { for (hand) }`, `zk_common.h:L91-L101`).
  This is a permutation of the challenge indexing.
* `ArithmetizedCircuit.W_mle` is required to be the multilinear extension of `W_col` in the
  *hand* variables only; the copy point is carried along as a parameter rather than being
  bound. The ZK path has `logc = 0` (`zk_common.h:L72`), so nothing is lost there.

---

## Plan for a solid soundness proof

8. **Multiple layers.** *Mostly done.* `layers.lean` has `verify_layers` (the fold over
   `claims = {wc[0], wc[1], q, g}`), `layer_step` (the `got == claim` reduction), and
   `layers_reduction` (the induction). Remaining: join it to the ZK/Ligero pad machinery
   (gap 1), allow per-layer `logw`, and sum the error terms across layers.

9. **Instantiate the error terms.** Exhibit an `Ω` that factors as
   "everything before the challenge" × "the challenge" and discharge `eps_bind`, `eps_deg`
   and `K` with `alpha_bad_card` and `uniform_hash_is_correlation_intractable`, so the bound
   is a closed-form function of `|F|`, `n`, `d` and `nl` rather than of four parameters.

10. **Normalise the bounds.** Either divide through by `Fintype.card Ω` and state the result
    in `ℚ` or `ℝ`, or state everything as `|bad| · |F|^k ≤ ε · |Ω|`, so that the theorem reads
    as a probability rather than an unanchored count.

### Invariants to maintain

* Every new assumption goes in a named `structure` with a docstring pointing at the C++ it
  abstracts — never a global `axiom`. Global axioms in this development were previously
  each individually inconsistent (`False` was derivable from any one of them), which is
  precisely the failure mode a `structure` plus an inhabitant prevents.
* Every assumption bundle gets an inhabitant in `example.lean`, in the regime where `eval`
  rejects. A bundle with no such inhabitant makes everything downstream vacuous.
* Check `#print axioms core_soundness_theorem` after every change; it should stay at
  `[propext, Classical.choice, Quot.sound]`.
