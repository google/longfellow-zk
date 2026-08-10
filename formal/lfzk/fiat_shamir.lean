import Mathlib
import sumcheck_soundness
import types
import circuit

open BigOperators
open Classical Polynomial Finset

set_option autoImplicit true
set_option relaxedAutoImplicit true

/-!
# Fiat–Shamir

Two layers and the bridge between them.

**The counting layer** knows nothing about circuits: it is about challenge *sequences*.
`IsFiatShamirTranscript` is a non-adaptive strategy pair — round `i`'s polynomial is a
function of the challenge prefix `r_0 … r_{i-1}` only, so it cannot depend on `r_i` or
later.  That is structural rather than a random-oracle assumption: it holds because
`ts.round(hp)` derives `r_i` from a transcript that already contains `p_i`
(`zk_common.h:L95`).  `combinatorial_fiat_shamir` (`sumcheck_soundness.lean`) then counts,
by counting roots, how many of the `|F|^n` challenge sequences let such a prover cheat: at
most `n · d · |F|^(n-1)`.

**The pullback** is `challenge_pullback_bound`.  That count is over challenge sequences,
but the soundness theorems count over the sample space `Ω`, so it is multiplied by `K`, a
bound on the fibers of `challenge_map : Ω → (Fin n → F)`.  `K` is analysed and eliminated
in `instantiate.lean`.

**The instantiation** connects both to the actual layer polynomial:
`sumcheck_ci_of_nonadaptive` produces `eps_sumcheck`, and `fsOfArithmetized` fixes `d = 2`
by deriving the degree bound from the arithmetization rather than taking it as input.
-/

variable {Ω : Type} [Fintype Ω]

/-! ## The counting layer -/

/--
**A non-adaptive Fiat–Shamir strategy pair.**

* `P_func` — the honest round polynomials, `p_func` — the prover's.  Both take the challenge
  *prefix* `Prefix F i = Fin i → F`, so it is mathematically impossible for round `i`'s
  polynomial to depend on challenge `r_i` or any later one.
* `hd` bounds the degree of the honest round polynomials.  It is not an input in practice:
  `fsOfArithmetized` below derives it, at `d = 2`.
-/
structure IsFiatShamirTranscript (F : Type) [Field F] [SumcheckInterp F] (n d : ℕ) where
  P_func : TruePolyStrategy F n
  p_func : ProverStrategy F n
  hd : ∀ (i : Fin n) (pref : Prefix F i.val), (P_func i pref).natDegree ≤ d
  h2 : 2 ≤ d

/-!
### The pre-state

`IsFiatShamirTranscript` indexes a strategy by the challenge *prefix* alone.  Round 0's prefix
is empty, so that forces round 0's polynomial to be the same across every run the strategy
describes — including runs that differ in prover coins, in the extracted witness, or in the
layer's `alpha` and `beta`.  That is much stronger than Fiat–Shamir causality, which only says
round `i` cannot see challenge `i` or later *given* everything decided before the challenges.

`IsFiatShamirFamily` adds that "everything decided before" as an explicit index `S`.  The
counting is unchanged in character — it is `combinatorial_fiat_shamir` applied **fibrewise**
over `S` — and the resulting bound picks up a factor `|S|`, which cancels against `|Ω|` in
exactly the way `K` does (`core_soundness_probability_ideal_fs`).

`example.lean`'s `honest_polys_need_state` shows the index is not a luxury: on the concrete
instance there, the honest round polynomial genuinely varies with `alpha`, so no state-free
strategy describes the run at all.
-/

/--
**A non-adaptive Fiat–Shamir strategy family, indexed by the pre-challenge state.**

`P_func s` and `p_func s` are the honest and prover strategies of a run whose pre-challenge
state is `s`.  Within a fixed `s`, round `i` still sees only the challenge prefix — that is
the Fiat–Shamir property, and it is what the root count needs.
-/
structure IsFiatShamirFamily (S F : Type) [Field F] [SumcheckInterp F] (n d : ℕ) where
  P_func : S → TruePolyStrategy F n
  p_func : S → ProverStrategy F n
  hd : ∀ (s : S) (i : Fin n) (pref : Prefix F i.val), (P_func s i pref).natDegree ≤ d
  h2 : 2 ≤ d

/-- A state-free strategy is the constant family.  This is how the old
`IsFiatShamirTranscript` embeds, and it makes precise that the generalisation only ever
weakens a hypothesis. -/
def IsFiatShamirTranscript.toFamily {F : Type} [Field F] [SumcheckInterp F] {n d : ℕ}
    (fs : IsFiatShamirTranscript F n d) (S : Type) : IsFiatShamirFamily S F n d where
  P_func := fun _ => fs.P_func
  p_func := fun _ => fs.p_func
  hd := fun _ => fs.hd
  h2 := fs.h2

/--
**The root count, fibrewise over the pre-state.**

For each fixed `s` the strategy pair is non-adaptive in the challenge prefix, so
`combinatorial_fiat_shamir` bounds its bad challenge sequences by `n·d·|F|^(n-1)`.  Summing
over `S` gives `|S|` times that, out of the `|S|·|F|^n` pairs — still an `n·d/|F|` fraction.
-/
lemma combinatorial_fiat_shamir_indexed {S F : Type} [Fintype S] [DecidableEq S]
    [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] {n d : ℕ}
    (fam : IsFiatShamirFamily S F n d) :
    (Finset.filter (fun q : S × (Fin n → F) =>
        any_bad_event n (fam.P_func q.1) (fam.p_func q.1) q.2) Finset.univ).card
      ≤ Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1)) :=
  pairs_card_le_mul (fun s cs => any_bad_event n (fam.P_func s) (fam.p_func s) cs)
    (n * d * (Fintype.card F) ^ (n - 1))
    (fun s => combinatorial_fiat_shamir n d (fam.P_func s) (fam.p_func s) (fam.hd s) fam.h2)

/--
**The pullback, with a pre-state.**

`K` now bounds the fibers of the *pair* `(state, challenge_map)`: how many runs share both a
pre-challenge state and a challenge sequence.  When the two are coordinates of the sample
space that is `K = 1`, and the `|S|` factor cancels against `|Ω| = |S|·|F|^n`.
-/
theorem challenge_pullback_bound_indexed {S F : Type} [Fintype S] [DecidableEq S]
    [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F] {n d : ℕ}
    (fam : IsFiatShamirFamily S F n d)
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ (s : S) (cs : Fin n → F),
      (Finset.filter (fun ω => state ω = s ∧ challenge_map ω = cs) Finset.univ).card ≤ K) :
    event_card (Finset.filter (fun ω => any_bad_event n (fam.P_func (state ω))
        (fam.p_func (state ω)) (challenge_map ω)) Finset.univ)
      ≤ K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1))) := by
  refine le_trans (card_le_of_split state challenge_map K h_unif
    (fun q => any_bad_event n (fam.P_func q.1) (fam.p_func q.1) q.2)) ?_
  exact Nat.mul_le_mul_left K (combinatorial_fiat_shamir_indexed fam)

/--
**Correlation intractability, in counting form.**

The number of *runs* on which the prover gets a lucky challenge is at most `K` times the
number of lucky challenge *sequences*, where `K` bounds the fibers of `challenge_map` — how
many runs share a sequence.  The sequence count is `combinatorial_fiat_shamir`, proved by
counting roots: no random oracle, no probability space.

`K` is where a hash assumption would enter.  It is not left dangling: `card_le_K_mul`
(`instantiate.lean`) shows `K ≥ |Ω|/|F|^n` always, so `K` is a load factor rather than a
security parameter, and over a sample space in which the challenge sequence is a coordinate
it is a *theorem* and cancels against `|Ω|`, leaving `n·d/|F|`.
-/
theorem challenge_pullback_bound {F : Type} [Field F] [Fintype F] [DecidableEq F]
    [SumcheckInterp F] {n d : ℕ} (fs : IsFiatShamirTranscript F n d)
    (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ cs : Fin n → F,
      (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card ≤ K) :
    event_card (Finset.filter
        (fun ω => any_bad_event n fs.P_func fs.p_func (challenge_map ω)) Finset.univ)
      ≤ K * (n * d * (Fintype.card F) ^ (n - 1)) := by
  have h_seq : (Finset.filter (any_bad_event n fs.P_func fs.p_func) Finset.univ).card
      ≤ n * d * (Fintype.card F) ^ (n - 1) :=
    combinatorial_fiat_shamir n d fs.P_func fs.p_func fs.hd fs.h2
  dsimp [event_card]
  rw [card_filter_comp challenge_map (any_bad_event n fs.P_func fs.p_func)]
  calc ∑ y ∈ Finset.filter (any_bad_event n fs.P_func fs.p_func) Finset.univ,
        (Finset.filter (fun x => challenge_map x = y) Finset.univ).card
      ≤ ∑ _y ∈ Finset.filter (any_bad_event n fs.P_func fs.p_func) Finset.univ, K :=
        Finset.sum_le_sum (fun cs _ => h_unif cs)
    _ = (Finset.filter (any_bad_event n fs.P_func fs.p_func) Finset.univ).card * K := by
        simp [Finset.sum_const, mul_comm]
    _ ≤ (n * d * (Fintype.card F) ^ (n - 1)) * K := by gcongr
    _ = K * (n * d * (Fintype.card F) ^ (n - 1)) := by ring

variable {Circuit Input Witness : Type}
variable {Ω : Type} [Fintype Ω]

/-! ## Instantiating at the layer polynomial

`multi_round_bad_event` is stated over *lists* — the transcript's own polynomials and
challenges — while `any_bad_event` is stated over a strategy `Fin n → Prefix F i → …`.
`IsNonAdaptiveRun` says the run's lists are a strategy's outputs, which is exactly
Fiat–Shamir non-adaptivity: round `i`'s polynomial is written into the transcript before
challenge `i` is derived from it (`ch->hb[hand][round] = ts.round(hp)`, `zk_common.h:L95`),
so it cannot depend on `r_i` or later.
-/

/-- A `multi_round_bad_event` locates a specific round at which the prover was lucky. -/
lemma multi_round_bad_event_exists {F : Type} [Field F] [SumcheckInterp F] :
    ∀ (Ps : List (Polynomial F)) (ps : List (RoundPoly F)) (rs : List F),
      multi_round_bad_event Ps ps rs →
      ∃ k : ℕ, ∃ (hP : k < Ps.length) (hp : k < ps.length) (hr : k < rs.length),
        BadRoundEvent (Ps.get ⟨k, hP⟩) (ps.get ⟨k, hp⟩) (rs.get ⟨k, hr⟩) := by
  intro Ps
  induction Ps with
  | nil =>
    intro ps rs h
    cases ps <;> cases rs <;> exact absurd h (by simp [multi_round_bad_event])
  | cons P Pt ih =>
    intro ps rs h
    cases ps with
    | nil => exact absurd h (by simp [multi_round_bad_event])
    | cons p pt =>
      cases rs with
      | nil => exact absurd h (by simp [multi_round_bad_event])
      | cons r rt =>
        rw [multi_round_bad_event] at h
        cases h with
        | inl hb => exact ⟨0, by simp, by simp, by simp, hb⟩
        | inr hrec =>
          obtain ⟨k, hP, hp, hr, hb⟩ := ih pt rt hrec
          refine ⟨k + 1, by simpa using hP, by simpa using hp, by simpa using hr, ?_⟩
          simpa using hb

/--
**Structure: IsNonAdaptiveRun**

Says that the ω-indexed transcripts are generated by a *non-adaptive* Fiat–Shamir strategy
pair `(fs.P_func, fs.p_func)` driven by the challenge sequence `challenge_map ω`.

* `challenges_eq` — the run's challenge list is the sequence `challenge_map ω`.  Together
  with `IsWellFormedTranscript` this pins `n = logc + 2 * logw`.
* `prover_eq` — the prover's round-`i` polynomial depends only on the challenges *before*
  round `i`.  This is the Fiat–Shamir property: `ts.round(hp)` derives `r_i` from a
  transcript that already contains `p_i`.  It is stated for the *unpadded* polynomials, so
  it takes the extracted pad; the transmitted `tr[0]`, `tr[2]` and the blinders are both
  fixed before the challenge.
* `true_eq` — likewise for the honest round polynomials, which depend on the challenge
  prefix through `generate_true_polys`.

Both are stated at the run's own **pre-state** `state ω`, not at a single global strategy.
Without that index the empty prefix of round 0 would force every accepted run to transmit the
same first polynomial, whatever its coins, witness or `(alpha, beta)` — and the honest side
would be outright false as soon as `alpha` varies, since the honest round polynomial depends
on it (`honest_polys_need_state`, `example.lean`).

None of this is a random-oracle assumption; the only probabilistic input is `K` below.
-/
structure IsNonAdaptiveRun {nc nv ninp npub logv logw logc M : ℕ} {S F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (fam : IsFiatShamirFamily S F n d)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) : Prop where
  challenges_eq : ∀ ω : Ω, accepts ω → (T_p ω).challenges = List.ofFn (challenge_map ω)
  prover_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
    (T_p ω).polys pad
      = List.ofFn (fun i : Fin n =>
          fam.p_func (state ω) i (extract_prefix (challenge_map ω) i))
  true_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
    circuit_true_polys AC c inp w
        ((T_p ω).decrypt pad var_dwR var_dwL
          (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2)
        (alpha ω) (beta ω) q_challenge g0 g1
      = List.ofFn (fun i : Fin n =>
          fam.P_func (state ω) i (extract_prefix (challenge_map ω) i))

/--
**`eps_sumcheck`, derived.**

For a non-adaptive run whose Fiat–Shamir hash sends at most `K` runs to any one challenge
sequence, the sumcheck correlation-intractability bound holds with

    eps_sumcheck = K * (n * d * |F|^(n-1)).

The `n * d * |F|^(n-1)` factor is `combinatorial_fiat_shamir`, proved by counting roots —
no random oracle, no probability space.  Out of `|F|^n` challenge sequences that is a
`n * d / |F|` fraction, the textbook sumcheck soundness error.
-/
theorem sumcheck_ci_of_nonadaptive {nc nv ninp npub logv logw logc M : ℕ} {S F : Type}
    [Fintype S] [DecidableEq S] [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw logc F)
    (fam : IsFiatShamirFamily S F n d)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (state : Ω → S) (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ (s : S) (cs : Fin n → F),
      (Finset.filter (fun ω => state ω = s ∧ challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC fam accepts T_p var_dwR var_dwL c inp E_L alpha beta q_challenge
      g0 g1 state challenge_map) :
    IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c inp E_L alpha beta q_challenge g0 g1
      (K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1)))) := by
  constructor
  have h_sub :
      (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
        multi_round_bad_event
          (circuit_true_polys AC c inp w
            ((T_p ω).decrypt pad var_dwR var_dwL
              (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2)
            (alpha ω) (beta ω) q_challenge g0 g1)
          ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ)
      ⊆ Finset.filter (fun ω => any_bad_event n (fam.P_func (state ω)) (fam.p_func (state ω))
          (challenge_map ω)) Finset.univ := by
    intro ω hω
    simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hω ⊢
    obtain ⟨h_acc, w, pad, h_EL, h_bad⟩ := hω
    rw [na.true_eq ω w pad h_acc h_EL, na.prover_eq ω w pad h_acc h_EL,
        na.challenges_eq ω h_acc] at h_bad
    obtain ⟨k, hP, hp, hr, hb⟩ := multi_round_bad_event_exists _ _ _ h_bad
    have hk : k < n := by simpa using hP
    refine ⟨⟨k, hk⟩, ?_⟩
    dsimp [bad_event_at]
    simpa using hb
  calc event_card _
      ≤ (Finset.filter (fun ω => any_bad_event n (fam.P_func (state ω)) (fam.p_func (state ω))
          (challenge_map ω)) Finset.univ).card := Finset.card_le_card h_sub
    _ ≤ K * (Fintype.card S * (n * d * (Fintype.card F) ^ (n - 1))) :=
        challenge_pullback_bound_indexed fam state challenge_map K h_unif

/-!
## `d = 2`, wired in

`IsFiatShamirFamily` bundles a degree bound `hd`, and until now the caller supplied it along
with `d`.  But `d` is not an independent parameter — it is a property of the arithmetization,
which is already an input to the theorem.  The bundle below fixes `d = 2` and *derives* `hd`
from `ArithmetizedCircuit.round_poly_natDegree_le_two`, so the only thing left for the caller
to supply is the prover's own strategy `p_func`.

The honest strategy reads the pre-state through `wOf`, `alphaOf`, `betaOf`.  That is not
generality for its own sake: the honest round polynomial of a layer *is* a function of the
extracted witness and of `(alpha, beta)`, so a state-free version would be describing a
different protocol (`honest_polys_need_state`, `example.lean`).
-/

/--
**The Fiat–Shamir family of an arithmetized ZK layer, at the derived degree `d = 2`.**

`P_func s` is *the* honest round-polynomial function of the layer at pre-state `s` —
`generate_true_polys` is literally `List.ofFn` of it — so `hd` is
`natDegree (sumcheck_round_poly …) ≤ 2`, which is `WPoly = Poly<3, Field>`.
-/
noncomputable def famOfArithmetized {nc nv ninp npub logv logw : ℕ} {S F : Type} [Field F]
    [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (q : Vector F 0) (g0 g1 : Vector F logv)
    (wOf : S → Witness) (alphaOf betaOf : S → F)
    (p_func : S → ProverStrategy F (0 + 2 * logw)) :
    IsFiatShamirFamily S F (0 + 2 * logw) 2 where
  P_func := fun s i pref =>
    sumcheck_round_poly (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
      (AC.Quad_mle c (betaOf s)) (AC.W_mle inp (wOf s)) (alphaOf s) q g0 g1)
      i.val i.isLt (Vector.ofFn pref)
  p_func := p_func
  hd := fun s i pref =>
    AC.round_poly_natDegree_le_two c inp (wOf s) (alphaOf s) (betaOf s) q g0 g1
      i.val i.isLt (Vector.ofFn pref)
  h2 := le_refl 2

/--
**`eps_sumcheck`, with the degree derived too.**

The same bound as `sumcheck_ci_of_nonadaptive`, but `d` is no longer an input: it is the `2`
that `WPoly` fixes, obtained from the arithmetization.  With `n = 2·logw` rounds this is

    eps_sumcheck = K * (|S| * (n * 2 * |F|^(n-1))),

i.e. a `2n/|F|` fraction of the `|S|·|F|^n` (state, challenge-sequence) pairs — the textbook
sumcheck soundness error for a degree-2 protocol.
-/
theorem sumcheck_ci_of_arithmetized {nc nv ninp npub logv logw M : ℕ} {S F : Type}
    [Fintype S] [DecidableEq S] [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q : Vector F 0) (g0 g1 : Vector F logv)
    (wOf : S → Witness) (alphaOf betaOf : S → F)
    (p_func : S → ProverStrategy F (0 + 2 * logw))
    (state : Ω → S) (challenge_map : Ω → (Fin (0 + 2 * logw) → F)) (K : ℕ)
    (h_unif : ∀ (s : S) (cs : Fin (0 + 2 * logw) → F),
      (Finset.filter (fun ω => state ω = s ∧ challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC (famOfArithmetized AC c inp q g0 g1 wOf alphaOf betaOf p_func)
      accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1 state challenge_map) :
    IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1
      (K * (Fintype.card S * ((0 + 2 * logw) * 2 * (Fintype.card F) ^ (0 + 2 * logw - 1)))) :=
  sumcheck_ci_of_nonadaptive AC _ accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1
    state challenge_map K h_unif na

/--
**The constructed `P_func` really is the honest round-polynomial family.**

Without this, `famOfArithmetized` would be bounding the degree of *some* family of polynomials
and nothing would notice.  This says it is exactly the family `circuit_true_polys` produces at
the run's own pre-state, so the derived `d = 2` applies to the honest round polynomials the
sumcheck soundness argument actually compares against.

It also discharges `IsNonAdaptiveRun.true_eq` whenever the pre-state reports the run's own
witness and layer challenges: given only `challenges_eq`, the honest side of non-adaptivity is
then a theorem rather than an assumption.  What remains assumed is `prover_eq`, which is a
statement about the *prover*.
-/
lemma circuit_true_polys_eq_famOfArithmetized {nc nv ninp npub logv logw : ℕ} {S F : Type}
    [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (q : Vector F 0) (g0 g1 : Vector F logv)
    (wOf : S → Witness) (alphaOf betaOf : S → F)
    (p_func : S → ProverStrategy F (0 + 2 * logw))
    (s : S) (t : Transcript F) (cs : Fin (0 + 2 * logw) → F)
    (hch : t.challenges = List.ofFn cs) :
    circuit_true_polys AC c inp (wOf s) t (alphaOf s) (betaOf s) q g0 g1
      = List.ofFn (fun i : Fin (0 + 2 * logw) =>
          (famOfArithmetized AC c inp q g0 g1 wOf alphaOf betaOf p_func).P_func s i
            (extract_prefix cs i)) := by
  have hv : ∀ k : Fin (0 + 2 * logw),
      (Vector.ofFn (fun i : Fin k.val =>
          (Vector.ofFn (n := 0 + 2 * logw) fun j => t.challenges.getD j.val 0).get
            ⟨i.val, by omega⟩))
        = Vector.ofFn (extract_prefix cs k) := by
    intro k
    refine Vector.ext (fun i hi => ?_)
    rw [Vector.getElem_ofFn, Vector.getElem_ofFn]
    show (Vector.ofFn (n := 0 + 2 * logw) fun j => t.challenges.getD j.val 0)[i] = _
    rw [Vector.getElem_ofFn, hch, getD_ofFn cs i (by omega)]
    rfl
  rw [circuit_true_polys, generate_true_polys]
  exact congrArg List.ofFn (funext (fun k => by rw [hv k]; rfl))
