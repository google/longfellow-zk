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

None of this is a random-oracle assumption; the only probabilistic input is `K` below.
-/
structure IsNonAdaptiveRun {nc nv nw ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (fs : IsFiatShamirTranscript F n d)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (challenge_map : Ω → (Fin n → F)) : Prop where
  challenges_eq : ∀ ω : Ω, accepts ω → (T_p ω).challenges = List.ofFn (challenge_map ω)
  prover_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
    (T_p ω).polys pad = List.ofFn (fun i : Fin n => fs.p_func i (extract_prefix (challenge_map ω) i))
  true_eq : ∀ (ω : Ω) (w : Witness) (pad : Pad M F), accepts ω → E_L ω = some (w, pad) →
    circuit_true_polys AC c inp w
        ((T_p ω).decrypt pad var_dwR var_dwL
          (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2)
        (alpha ω) (beta ω) q_challenge g0 g1
      = List.ofFn (fun i : Fin n => fs.P_func i (extract_prefix (challenge_map ω) i))

/--
**`eps_sumcheck`, derived.**

For a non-adaptive run whose Fiat–Shamir hash sends at most `K` runs to any one challenge
sequence, the sumcheck correlation-intractability bound holds with

    eps_sumcheck = K * (n * d * |F|^(n-1)).

The `n * d * |F|^(n-1)` factor is `combinatorial_fiat_shamir`, proved by counting roots —
no random oracle, no probability space.  Out of `|F|^n` challenge sequences that is a
`n * d / |F|` fraction, the textbook sumcheck soundness error.
-/
theorem sumcheck_ci_of_nonadaptive {nc nv nw ninp npub logv logw logc M : ℕ} {F : Type} [Field F] [Fintype F] [DecidableEq F] [SumcheckInterp F]
    {n d : ℕ}
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw logc F)
    (fs : IsFiatShamirTranscript F n d)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q_challenge : Vector F logc) (g0 g1 : Vector F logv)
    (challenge_map : Ω → (Fin n → F)) (K : ℕ)
    (h_unif : ∀ cs : Fin n → F, (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC fs accepts T_p var_dwR var_dwL c inp E_L alpha beta q_challenge g0 g1 challenge_map) :
    IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c inp E_L alpha beta q_challenge g0 g1
      (K * (n * d * (Fintype.card F) ^ (n - 1))) := by
  constructor
  have h_sub :
      (Finset.filter (fun ω => accepts ω ∧ ∃ w pad, E_L ω = some (w, pad) ∧
        multi_round_bad_event
          (circuit_true_polys AC c inp w
            ((T_p ω).decrypt pad var_dwR var_dwL
              (true_evals AC inp w (T_p ω).challenges).1 (true_evals AC inp w (T_p ω).challenges).2)
            (alpha ω) (beta ω) q_challenge g0 g1)
          ((T_p ω).polys pad) (T_p ω).challenges) Finset.univ)
      ⊆ Finset.filter (fun ω => any_bad_event n fs.P_func fs.p_func (challenge_map ω)) Finset.univ := by
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
  calc event_card _ ≤ (Finset.filter (fun ω => any_bad_event n fs.P_func fs.p_func (challenge_map ω)) Finset.univ).card :=
        Finset.card_le_card h_sub
    _ ≤ K * (n * d * (Fintype.card F) ^ (n - 1)) :=
        challenge_pullback_bound fs challenge_map K h_unif

/-!
## `d = 2`, wired in

`IsFiatShamirTranscript` bundles a degree bound `hd`, and until now the caller supplied it
along with `d`.  But `d` is not an independent parameter — it is a property of the
arithmetization, which is already an input to the theorem.  The bundle below fixes `d = 2`
and *derives* `hd` from `ArithmetizedCircuit.round_poly_natDegree_le_two`, so the only thing
left for the caller to supply is the prover's own strategy `p_func`.
-/

/--
**The Fiat–Shamir bundle of an arithmetized ZK layer, at the derived degree `d = 2`.**

`P_func` is *the* honest round-polynomial function of the layer — `generate_true_polys` is
literally `List.ofFn` of it — so `hd` is `natDegree (sumcheck_round_poly …) ≤ 2`, which is
`WPoly = Poly<3, Field>`.
-/
noncomputable def fsOfArithmetized {nc nv nw ninp npub logv logw : ℕ} {F : Type} [Field F] [Fintype F]
    [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q : Vector F 0)
    (g0 g1 : Vector F logv) (p_func : ProverStrategy F (0 + 2 * logw)) :
    IsFiatShamirTranscript F (0 + 2 * logw) 2 where
  P_func := fun i pref =>
    sumcheck_round_poly (layer_sumcheck_poly_concat (nc := nc) (nv := nv)
      (AC.Quad_mle c beta) (AC.W_mle inp w) alpha q g0 g1) i.val i.isLt (Vector.ofFn pref)
  p_func := p_func
  hd := fun i pref =>
    AC.round_poly_natDegree_le_two c inp w alpha beta q g0 g1 i.val i.isLt (Vector.ofFn pref)
  h2 := le_refl 2

/--
**`eps_sumcheck`, with the degree derived too.**

The same bound as `sumcheck_ci_of_nonadaptive`, but `d` is no longer an input: it is the `2`
that `WPoly` fixes, obtained from the arithmetization.  With `n = 2·logw` rounds this is

    eps_sumcheck = K * (n * 2 * |F|^(n-1)),

i.e. a `2n/|F|` fraction of the `|F|^n` challenge sequences — the textbook sumcheck
soundness error for a degree-2 protocol.
-/
theorem sumcheck_ci_of_arithmetized {nc nv nw ninp npub logv logw M : ℕ} {F : Type} [Field F] [Fintype F]
    [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw 0 F)
    (accepts : Ω → Prop) (T_p : Ω → EncTranscript M F) (var_dwR var_dwL : Fin M)
    (c : Circuit) (inp : Input) (E_L : Ω → Option (AugmentedWitness M F Witness))
    (alpha beta : Ω → F) (q : Vector F 0) (g0 g1 : Vector F logv)
    (w0 : Witness) (alpha0 beta0 : F) (p_func : ProverStrategy F (0 + 2 * logw))
    (challenge_map : Ω → (Fin (0 + 2 * logw) → F)) (K : ℕ)
    (h_unif : ∀ cs : Fin (0 + 2 * logw) → F,
      (Finset.filter (fun ω => challenge_map ω = cs) Finset.univ).card ≤ K)
    (na : IsNonAdaptiveRun AC (fsOfArithmetized AC c inp w0 alpha0 beta0 q g0 g1 p_func)
      accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1 challenge_map) :
    IsSumcheckCorrelationIntractable AC accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1
      (K * ((0 + 2 * logw) * 2 * (Fintype.card F) ^ (0 + 2 * logw - 1))) :=
  sumcheck_ci_of_nonadaptive AC _ accepts T_p var_dwR var_dwL c inp E_L alpha beta q g0 g1
    challenge_map K h_unif na

/--
**The constructed `P_func` really is the honest round-polynomial family.**

Without this, `fsOfArithmetized` would be bounding the degree of *some* family of
polynomials and nothing would notice.  This says it is exactly the family
`circuit_true_polys` produces, so the derived `d = 2` applies to the honest round
polynomials that the sumcheck soundness argument actually compares against.

It also discharges `IsNonAdaptiveRun.true_eq` whenever the extracted witness and layer
coefficient are the `w` and `alpha` the bundle was built at: given only `challenges_eq`, the
honest side of non-adaptivity is then a theorem rather than an assumption.  What remains
assumed is `prover_eq`, which is a statement about the *prover*.
-/
lemma circuit_true_polys_eq_fsOfArithmetized {nc nv nw ninp npub logv logw : ℕ} {F : Type} [Field F]
    [Fintype F] [DecidableEq F] [SumcheckInterp F]
    (AC : ArithmetizedCircuit Circuit Input Witness nc nv nw ninp npub logv logw 0 F)
    (c : Circuit) (inp : Input) (w : Witness) (alpha beta : F) (q : Vector F 0)
    (g0 g1 : Vector F logv) (p_func : ProverStrategy F (0 + 2 * logw))
    (t : Transcript F) (cs : Fin (0 + 2 * logw) → F) (hch : t.challenges = List.ofFn cs) :
    circuit_true_polys AC c inp w t alpha beta q g0 g1
      = List.ofFn (fun i : Fin (0 + 2 * logw) =>
          (fsOfArithmetized AC c inp w alpha beta q g0 g1 p_func).P_func i (extract_prefix cs i)) := by
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
