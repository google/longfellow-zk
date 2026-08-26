# Sumcheck
## Special conventions for sumcheck arrays

The square brackets `A[j]` denote generic array indexing.

For the arrays of field elements used in the sumcheck protocol,
however, it is convenient to use the conventions that follow.

The sumcheck array `A[i]` is implicitly assumed to be defined for all
nonnegative integers `i`, padding with zeroes as necessary.  Here,
"zero" is well defined because `A[]` is an array of field elements.

Arrays can be multi-dimensional, as in the three-dimensional array
`Q[g, l, r]`.  It is understood that the array is padded with
infinitely many zeroes in each dimension.

Depending on the context, some arrays may consist of almost all non-zero
values, while other arrays may be sparse, containing very few non-zero
values (ignoring the zero-padding convention above). Implementations
should use dense or sparse representations of arrays as appropriate.

Given array `A[]` and field element `x`, the function
`bind(A, x)` returns the array `B` such that
```
  B[i] = (1 - x) * A[2 * i] + x * A[2 * i + 1]
```

In case of multiple dimensions such as `Q[g, l, r]`, 
always bind across the first dimension.  For example,

```
  bind(Q, x)[g, l, r] =
     (1 - x) * Q[2 * g, l, r] + x * Q[2 * g + 1, l, r]
```

This `bind` can be generalized to an array of field elements as follows:
```
  bindv(A, X) =
       A                                  if X is empty
       bindv(bind(A, X[0]), X[1..])       otherwise
```

Two-dimentional arrays can be transposed in the usual way:
```
  transpose(Q)[l, r] = Q[r, l] .
```

## The `EQ[]` array

`EQ_{n}[i, j]` is a special 2D array defined as

```
   EQ_{n}[i, j] = 1   if i = j and i < n
                  0   otherwise
```

The sumcheck literature usually assumes that `n` is a power of 2,
but this document allows `n` to be an arbitrary integer.  When `n` is clear from
context or unimportant, the subscript is omitted like 
`EQ[i, j]`.

`EQ[]` is important because the general expansion
```
   V[i] = SUM_{j} EQ[i, j] V[j]
```
commutes with binding, yielding
```
   bindv(V, X) = SUM_{j} bindv(EQ, X)[j] V[j] .
```
That is, one way to compute `bindv(V, X)` is via
dot product of `V` with `bindv(EQ, X)`.  This strategy
may or may not be advantageous in practice, but it
becomes mandatory when `bindv(V, X)` must be computed
via a commitment scheme that supports linear
constraints but not binding.

This document only uses bindings of `EQ` and never `EQ` itself,
and therefore the whole array never needs to be stored explicitly.
For `n = 2^l` and `X` of size `l`, `bindv(EQ_{n}, X)` can be computed
recursively in linear time as follows.

``` rust
/// Computes the multilinear extension of the equality polynomial EQ_{2^l}(x, r).
pub fn bindeq<F: Field>(challenges: &[F]) -> Vec<F> {
    let log_n = challenges.len();
    if log_n == 0 {
        return vec![F::one()];
    }
    let n = 1 << log_n;
    let mut b = vec![F::zero(); n];
    let a = bindeq(&challenges[1..]);
    for i in 0..(n / 2) {
        b[2 * i] = (F::one() - challenges[0]) * a[i];
        b[2 * i + 1] = challenges[0] * a[i];
    }
    b
}

/// Evaluates the equality polynomial EQ(r, x) at integer point `x_int` of length `nbits`.
pub fn eq<F: Field>(r: &[F], x_int: usize, nbits: usize) -> F {
    let mut product = F::one();
    for b in 0..nbits {
        if ((x_int >> b) & 1) == 1 {
            product *= r[b];
        } else {
            product *= F::one() - r[b];
        }
    }
    product
}

/// Evaluates a linear combination of equality polynomials across two challenge vectors:
/// `eq2(x, logn, g0, g1, alpha) = eq(g0, x, logn) + alpha * eq(g1, x, logn)`
pub fn eq2<F: Field>(x: usize, logn: usize, g0: &[F], g1: &[F], alpha: F) -> F {
    eq(g0, x, logn) + alpha * eq(g1, x, logn)
}
```

For `m <= n`, `bindv(EQ_{n}, X)[i]` and `bindv(EQ_{m}, X)[i]`
agree for `0 <= i < m`, and thus 
`bindv(EQ_{m}, X)[i]` can be computed by padding `m` to the next power of 2
and ignoring the extra elements.
With some care, it is possible to compute `bindeq()` 
in-place on a single array of arbitrary size `m` and eliminate
the recursion completely.

### Remark
Let `m <= n`, `A = bindv(EQ_{m}, X)` and `B = bindv(EQ_{n}, X)`.  It
is true that `A[i] = B[i]` for `i < m`.  However, it is also true that `A[i] =
0` for `i >= m`, whereas `B[i]` is in general nonzero.  Thus, care
must be taken when computing a further binding `bindv(A, Y)`,
which is in general not the same as `bindv(B, Y)`.  A second binding is
not needed in this document,  but certain closed-form expressions for 
the binding found in the literature agree with these definitions only
when `m` is a power of 2.

## Circuits

### Layered circuits
A circuit consists of `NL` *layers*.  By convention, layer `j`
computes wires `V[j]` given wires `V[j + 1]`, where each `V[j]` is an
array of field elements.  A *wire* is an element `V[j][w]` for some `j`
and `w`.  Thus, `V[0]` denotes the output wires of the entire circuit,
and `V[NL]` denotes the input wires.

A circuit is intended to check that some property of the input holds,
and by convention, the check is considered successful if all output
wires are 0, that is, if `V[0][w] = 0` for all `w`.

### Quad representation
The computation of circuit is defined by a set of *quads* `Q[j]`, one
per layer.  Given the output of layer `j + 1`, the output of of layer
`j` is given by the following equation:

```
  V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r] .
```

The quad `Q[j][]` is thus a three-dimensional array in the indices `g`,
`l`, and `r` where `0 <= g < NW[j]` and `0 <= l, r < NW[j + 1]`.  In
practice, `Q[j][]` is sparse.

The specification of the circuit contains an auxiliary
vector of quantities `LV[j]` with the property that `V[j][w] = 0`
for all `w >= 2^{LV[j]}`.  Informally, `LV[j]` is the number
of bits needed to name a wire at layer `j`, but `LV[j]` may
be larger than the minimum required value.

### In-circuit assertions
In the libzk system, a theorem is represented by a circuit such that
the theorem is true if and only if all outputs of the circuit are
zero.  It happens in practice that many output wires are computed early
in the circuit (i.e., in a layer closer to the input), but because of
layering, they need to be copied all the way to output layer in order
to be compared against zero.  This copy seems to introduce large
overheads in practice.

A special convention can mitigate this problem.  Abstractly,
a layer is represented by *two* quads `Q` and `Z`, and the
operation of the layer is described by the two equations

```
  V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r]
       0  = SUM_{l, r} Z[j][g, l, r] V[j + 1][l] V[j + 1][r]
```

Thus, the `Z` quad asserts that, for given layer `j`
and output wire `g`, a certain quadratic combination of
the input wires is zero.

The actual protocol verifies a random linear combination
of those two equations, effectively operating on a combined
quad `QZ = Q + beta * Z` for some random `beta`.

To allow for a compact representation of the two quads without
losing any real generality, the following conditions are imposed:

* The two quads `Q` and `Z` are disjoint: for all layers `j` and output
  wire `g`, if any `Q[j][g, ., .]` are nonzero, then all `Z[j][g, ., .]`
  are zero, and vice versa.
* `Z` is binary: `Z[j][g, l, r] \in {0, 1}`

With these choices, the two quads allow a compact sparse
representation as a single list of 4-tuples `(g, l, r, v)`
with the following conventions:

* If `v = 0`, the 4-tuple represents an element of `Z`,
  and `Z[j][g, l, r] = 1`.
* If `v != 0`, the 4-tuple represents an element of `Q`,
  and `Q[j][g, l, r] = v`.
* All other elements of `Q` and `Z` not specified by the list are
  zero.

Moreover, this compact representation can be transformed into
a representation of `QZ = Q + beta * Z` by replacing all `v = 0`
with `v = beta`.

## Representation of polynomials
In a generic sumcheck protocol, the prover sends to the verifier
polynomials of a degree specified in advance.  In the present document,
the polynomials are always of degree two, and are represented by their
evaluations at three points `P0 = 0`, `P1 = 1`, and `P2`, where `0`
and `1` are the additive and multiplicative identities in the field.
The choice of `P2` depends upon the field.  For fields of characteristic
greater than 2, set `P2 = 2` (= `1 + 1` in the field).  For `GF(2^128)`
expressed as `GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)`, set `P2 = inj(2)`
as defined in (#gf2k).  This document does not prescribe a choice of
P2 for binary fields other than `GF(2^128)`.

At the start of each round of communication in a sumcheck protocol, both the
prover and the (virtual) sumcheck verifier agree on a claim value, which
represents the sum of the evaluation of some function at all inputs `{0,1}^*`.
The polynomials computed by the prover represent the sum of the
evaluations of the multilinear extension of that same function, with one
argument fixed to `P0`, `P1`, or `P2`, and all other arguments chosen
from `{0,1}`.
Therefore, the sum of `p(P0) + p(P1)` is equal to the claim from the
start of the sumcheck round, and the prover only needs to send two field
elements in order for the parties to agree on the entire degree two
polynomial.
Here, `p(P0)` and `p(P2)` are sent to the (virtual) sumcheck verifier,
and `p(P1)` is reconstructed from `p(P0)` and the claim.

## Transcript encryption and deferred verification

The sumcheck protocol produces a series of polynomials and claim values,
computed from the circuit input values, to prove that the circuit
was evaluated correctly.
As described in (#overview), these polynomials and claims are not
directly revealed to the verifier.
Rather, the field elements that make up these values are encrypted with
a one-time pad by subtracting a randomly chosen pad value from each
field element, and the difference is sent to the verifier.

When the verifier executes the sumcheck protocol, it does not have
direct access to all the circuit inputs, and it is only given the
one-time pad encrypted forms of the sumcheck polynomials and per-layer
claims, not the corresponding plaintext values.
Therefore, the prover and verifier defer part of the verification by
producing a series of linear and quadratic constraints, relating the
private input values and the one-time pad values, so that those
constraints can be checked with the Ligero zero-knowledge system (see
(#ligero-zk-proof)).

The variables used in these constraints are assigned sequentially, first
to the private circuit inputs, then to elements of the one-time pad.
Variables for one-time pad values are assigned to values for circuit
layers in order, starting with the output layer (layer 0). Within each layer,
variables are first assigned to one-time pad values for sumcheck
polynomials, then to the per-layer claim values. The number of sumcheck
polynomials for each layer is equal to double the value of
`logw` for that layer of the circuit (two hands for each round).
The polynomials are represented by two field
elements each, one for the evaluation at `P0 = 0`, and one for the
evaluation at `P2`. At the end of the variables for each layer, three
variables are assigned for claim-related values. Two variables `c0` and `c1` are used
for the one-time pad values for the claims `vl` and `vr`. Then, a
variable `cr` is used for the product of those two one-time pad values (`cr = c0 * c1`).

``` rust
/// Padding for a single round of sumcheck (masks for p0 and p2 evals for both hands).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPad<T> {
    pub hp: [[T; 2]; 2], // hp[hand] = [p0_mask, p2_mask]
}

/// Padding for final layer claim masks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerClaimsPad<T> {
    pub c0: T,
    pub c1: T,
    pub cr: T, // Product c0 * c1
}

/// Padding for a single circuit layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerPad<T> {
    pub rounds: Vec<RoundPad<T>>,
    pub claims: LayerClaimsPad<T>,
}

/// Padding for the entire circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitPad<T> {
    pub layers: Vec<LayerPad<T>>,
}

impl<F: Field> LayerPad<F> {
    /// Samples concrete random field element masks for a single circuit layer.
    pub fn sample<R: Rng>(logw: usize, rng: &mut R) -> Self {
        let mut rounds = Vec::with_capacity(logw);
        for _ in 0..logw {
            rounds.push(RoundPad {
                hp: [
                    [F::sample(rng), F::sample(rng)],
                    [F::sample(rng), F::sample(rng)],
                ],
            });
        }
        let c0 = F::sample(rng);
        let c1 = F::sample(rng);
        let cr = c0 * c1;

        LayerPad {
            rounds,
            claims: LayerClaimsPad { c0, c1, cr },
        }
    }

    /// Appends all pad elements in order to a witness vector.
    pub fn flatten_into(&self, out: &mut Vec<F>) {
        for r in &self.rounds {
            out.extend_from_slice(&r.hp[0]);
            out.extend_from_slice(&r.hp[1]);
        }
        out.push(self.claims.c0);
        out.push(self.claims.c1);
        out.push(self.claims.cr);
    }
}

impl LayerPad<usize> {
    /// Generates the symbolic witness indices for a single circuit layer pad starting at `pad_base`.
    pub fn generate_indices(logw: usize, pad_base: &mut usize) -> Self {
        let mut rounds = Vec::with_capacity(logw);
        for _ in 0..logw {
            let hand0 = [*pad_base, *pad_base + 1];
            let hand1 = [*pad_base + 2, *pad_base + 3];
            *pad_base += 4;
            rounds.push(RoundPad { hp: [hand0, hand1] });
        }
        let c0 = *pad_base;
        let c1 = *pad_base + 1;
        let cr = *pad_base + 2;
        *pad_base += 3;

        LayerPad {
            rounds,
            claims: LayerClaimsPad { c0, c1, cr },
        }
    }
}

impl<F: Field> CircuitPad<F> {
    /// Samples random field element padding for all layers in the circuit and flattens them into witness padding.
    pub fn sample<R: Rng>(circuit_data: &Circuit<F>, rng: &mut R) -> (Self, Vec<F>) {
        let mut pad_witness = Vec::new();
        let mut layers = Vec::with_capacity(circuit_data.layers.len());
        for layer in &circuit_data.layers {
            let layer_pad = LayerPad::sample(layer.logw, rng);
            layer_pad.flatten_into(&mut pad_witness);
            layers.push(layer_pad);
        }
        (CircuitPad { layers }, pad_witness)
    }
}

impl CircuitPad<usize> {
    /// Generates symbolic witness indices for all layers in the circuit starting at `pad_base`.
    pub fn generate_indices<F: Field>(circuit_data: &Circuit<F>, pad_base: &mut usize) -> Self {
        let mut layers = Vec::with_capacity(circuit_data.layers.len());
        for layer in &circuit_data.layers {
            layers.push(LayerPad::generate_indices(layer.logw, pad_base));
        }
        CircuitPad { layers }
    }
}
```

## Transform circuit and wires into a padded proof

The prover constructs a padded proof by executing the sumcheck protocol
in order to certify that the wires at each layer of the circuit are
correctly calculated from the wires at the preceding layer.

The goal is to prove that, for some layer index `j`, and every output
wire index `g` in that layer, the following all hold with high
probability.

```
V[j][g] = SUM_{l, r} Q[j][g, l, r] V[j + 1][l] V[j + 1][r]

0 = SUM_{l, r} Z[j][g, l, r] V[j + 1][l] V[j + 1][r]
```

These equations are combined into one equation after multiplying them by
random verifier challenges. This equation is of the form

```
claim = SUM_{l, r} QUAD[j][l, r] V[j + 1][l] V[j + 1][r]
```

If we reinterpret the wire indices `l` and `r` as binary numbers,
replacing them both with `log_num_input_wires` many variables having
value 0 or 1, then this equation has the form needed to apply the
sumcheck protocol.

At each layer, both parties start with two claims that each represent a
linear combination of the layer's output wire values.
Concretely, the claims for the layer's outputs are `bind(V[j], G[0])`
and `bind(V[j], G[1])` where `G[0]` and `G[1]` are arrays of verifier
challenges.
These two claim values get combined into one using a random challenge
value.
In each successive round of communication, the function inside the
summation is replaced with a new function having one fewer parameter,
one of the output wire arrays is halved in size by binding it with a
random challenge, and the claim value is replaced with a newly computed
claim value.
The prover proves that the new claim values and the new function at each
round are consistent with those in the previous round by evaluating the
multilinear extension of the function at multiple points, including
points with a random challenge coordinate.
The prover computes a degree two polynomial by summing this multilinear
extension at many points, with the polynomial's parameter determining
the last parameter of the multilinear extension.
Two evaluations of this polynomial are sent to the verifier, though as
noted above these evaluations get encrypted with a one-time pad.
After several rounds of communication, the function being summed is
replaced with a constant, and both output wire arrays are replaced with
two new claim values.
Concretely, the new claims will be `bind(V[j + 1], G'[0])` and `bind(V[j
+ 1], G'[0])`, where `V[j + 1]` is the input wires of layer j, and
`G'[0]` and `G'[1]` are a fresh set of verifier challenges, chosen at
each round of the sumcheck protocol.
These two claim values are encrypted with a one-time pad and sent to the
verifier.

Before the first round, a fixed number of verifier challenges are
generated and discarded (`begin_circuit`). These are reserved for possible future
extensions to the protocol. Additionally, a fixed number of challenges
are generated for binding the output wires before the first round, with
the remainder of the challenges being discarded. In both of these cases,
`MAX_LOGW = 40` challenges are generated. For all subsequent layers,
challenges used for binding output wires are generated one at a time,
with no extra unused challenges.

``` rust
#[derive(Clone, Debug)]
pub struct SumcheckRoundEvals<F> {
    pub evals: [F; 2],
}

#[derive(Clone, Debug)]
pub struct SumcheckLayerProof<F> {
    pub hp: [Vec<SumcheckRoundEvals<F>>; 2],
    pub claims: [F; 2],
}

/// Returns the element at `index`, treating the slice as infinitely padded with zeroes.
pub fn vector_ref<F: Field>(w: &[F], index: usize) -> F {
    if index < w.len() { w[index] } else { F::zero() }
}

/// Evaluates a single round polynomial for the sumcheck protocol.
/// Returns evaluations at 0, 1, and x2.
fn eval_round_poly<F: Field + 'static>(
    quad_terms: &[Term<F>],
    active_hand: &[F],
    other_hand: &[F],
    hand: usize,
    eval_point_x2: F,
) -> [F; 3] {
    let one_minus_x2 = F::one() - eval_point_x2;
    let mut ev0 = F::zero();
    let mut ev1 = F::zero();
    let mut ev2 = F::zero();

    let other_hand_idx = 1 - hand;

    for term in quad_terms {
        let is_even = term.h[hand] % 2 == 0;
        let pair_base_idx = term.h[hand] & !1;

        let w0 = vector_ref(active_hand, pair_base_idx);
        let w1 = vector_ref(active_hand, pair_base_idx | 1);
        let other_val = vector_ref(other_hand, term.h[other_hand_idx]);

        let coef = term.k * other_val;
        let wx2 = w0 + eval_point_x2 * (w1 - w0);

        if is_even {
            ev0 += coef * w0;
            ev2 += coef * one_minus_x2 * wx2;
        } else {
            ev1 += coef * w1;
            ev2 += coef * eval_point_x2 * wx2;
        }
    }

    [ev0, ev1, ev2]
}

/// Binds active wires to a challenge point:
/// wires[i] = (1 - challenge) * wires[2*i] + challenge * wires[2*i + 1]
pub fn bind<F: Field>(wires: &mut Vec<F>, challenge: F) {
    let n = wires.len().div_ceil(2);
    let one_minus_c = F::one() - challenge;
    for i in 0..n {
        let w0 = vector_ref(wires, 2 * i);
        let w1 = vector_ref(wires, 2 * i + 1);
        wires[i] = w0 * one_minus_c + w1 * challenge;
    }
    wires.truncate(n);
}

pub fn sumcheck_prove_layer<F: Field + 'static>(
    transcript: &mut Transcript,
    layer_pad: &LayerPad<F>,
    wires: &[F],
    mut quad_terms: Vec<Term<F>>,
    logw: usize,
) -> (SumcheckLayerProof<F>, [Vec<F>; 2], [F; 2]) {
    let mut challenges = [Vec::new(), Vec::new()];
    let mut hp = [Vec::with_capacity(logw), Vec::with_capacity(logw)];

    let x2 = F::sumcheck_eval_points()[2];
    let mut active_wires = [wires.to_vec(), wires.to_vec()];

    for round in 0..logw {
        for hand in 0..2 {
            let other_hand = 1 - hand;
            let evaluations = eval_round_poly(
                &quad_terms,
                &active_wires[hand],
                &active_wires[other_hand],
                hand,
                x2,
            );

            // Pad the polynomial evaluations
            let round_pad = &layer_pad.rounds[round].hp[hand];
            let padded_sumcheck_poly =
                [evaluations[0] - round_pad[0], evaluations[2] - round_pad[1]];

            // Get challenge from transcript
            let challenge = round_poly(transcript, &padded_sumcheck_poly);
            challenges[hand].push(challenge);

            hp[hand].push(SumcheckRoundEvals {
                evals: padded_sumcheck_poly,
            });

            // Fold the active wires with the challenge
            bind(&mut active_wires[hand], challenge);

            // Update quadratic terms for the next round
            let one_minus_c = F::one() - challenge;
            for term in quad_terms.iter_mut() {
                if term.h[hand] % 2 == 0 {
                    term.k *= one_minus_c;
                } else {
                    term.k *= challenge;
                }
                term.h[hand] /= 2;
            }
        }
    }

    let next_claims = [
        vector_ref(&active_wires[0], 0),
        vector_ref(&active_wires[1], 0),
    ];
    let proof_claims = [
        next_claims[0] - layer_pad.claims.c0,
        next_claims[1] - layer_pad.claims.c1,
    ];

    end_layer(transcript, &proof_claims);

    let proof = SumcheckLayerProof {
        hp,
        claims: proof_claims,
    };
    (proof, challenges, next_claims)
}

pub fn sumcheck_prove<F: Field + 'static>(
    transcript: &mut Transcript,
    in_layers: &[Vec<F>],
    circuit_data: &Circuit<F>,
    circuit_pad: &CircuitPad<F>,
) -> (Vec<SumcheckLayerProof<F>>, [F; 2]) {
    let (_copy_challenges, global_challenges) = begin_circuit::<F>(transcript);

    let initial_logv = ceil_lg2(circuit_data.noutput);
    let mut current_logv = initial_logv;
    let mut current_challenges = [
        global_challenges[0..initial_logv].to_vec(),
        global_challenges[0..initial_logv].to_vec(),
    ];

    let mut final_claims = [F::zero(); 2];
    let mut proofs = Vec::with_capacity(circuit_data.layers.len());

    for layer_index in 0..circuit_data.layers.len() {
        let layer = &circuit_data.layers[layer_index];
        let (alpha, beta) = begin_layer(transcript);

        let mut quad_terms = layer.quad.clone();
        bind_g(
            &mut quad_terms,
            current_logv,
            &current_challenges[0],
            &current_challenges[1],
            alpha,
            beta,
        );

        let (proof, next_challenges, next_claims) = sumcheck_prove_layer(
            transcript,
            &circuit_pad.layers[layer_index],
            &in_layers[layer_index],
            quad_terms,
            layer.logw,
        );

        current_logv = layer.logw;
        current_challenges = next_challenges;
        final_claims = next_claims;
        proofs.push(proof);
    }

    (proofs, final_claims)
}
```

## Generate constraints from the public inputs and the padded proof

This section defines the procedure `symbolic_sumcheck_verifier_core` for transforming
the proof returned by `sumcheck_prove` into constraints to be checked
by the commitment scheme. Specifically, each layer produces one linear
constraint and one quadratic constraint. One additional linear
constraint is added after processing the input layer.

The main difficulty in describing the algorithm is that it operates
not on concrete witnesses, but on expressions in which the witnesses
are symbolic quantities. Symbolic manipulation is necessary because
the verifier does not have access to the witnesses. In the reference implementation,
symbolic quantities are represented by affine expressions `Expression<F>`
of the form `k + SUM_{i} a[i] * Var(i)` for known constant `k` and coefficients `a[i]`.
`Var(i)` represents the `i`-th variable in the combined witness vector `W`.

Linear constraints are converted into sparse constraint terms `LigeroTerm<F>` representing
`A * W + b = 0`, and quadratic constraints are represented by variable indices `(c0, c1, cr)`
enforcing `W[c0] * W[c1] = W[cr]`.

``` rust
pub struct ClaimsState<F> {
    pub logv: usize,
    pub claim: [Expression<F>; 2],
    pub hc: [Vec<F>; 2],
}

pub struct SymRes<F> {
    pub a: Vec<LigeroTerm<F>>,
    pub b: Vec<F>,
}

fn constrain_to_be_zero<F: Field>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    expr: &Expression<F>,
) {
    let c = b.len();
    for (&witness_idx, &coeff) in &expr.terms {
        a.push(LigeroTerm {
            coeff,
            constraint_idx: c,
            witness_idx,
        });
    }
    b.push(expr.known);
}

pub fn symbolic_sumcheck_round<F: Field + 'static>(
    claim: Expression<F>,
    round_pad: &[usize; 2],
    hp_evals: &[F; 2],
    ts: &mut Transcript,
) -> (Expression<F>, F) {
    let challenge_val = round_poly(ts, hp_evals);
    let lag = lagrange_basis(challenge_val);

    let p0 = Var(round_pad[0]) + hp_evals[0];
    let p2 = Var(round_pad[1]) + hp_evals[1];
    let p1 = claim - p0.clone();

    let next_claim = p0 * lag[0] + p1 * lag[1] + p2 * lag[2];

    (next_claim, challenge_val)
}

fn verify_layer<F: Field + 'static>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    claims_state: &mut ClaimsState<F>,
    pad: &LayerPad<usize>,
    clr: &CircuitLayer<F>,
    plr: &SumcheckLayerProof<F>,
    ts: &mut Transcript,
) {
    let (alpha, beta) = begin_layer(ts);
    let mut lchal_hc = [Vec::new(), Vec::new()];

    let mut claim = claims_state.claim[0].clone() + claims_state.claim[1].clone() * alpha;

    for round in 0..clr.logw {
        for hand in 0..2 {
            let hp = &plr.hp[hand][round];
            let round_pad = &pad.rounds[round].hp[hand];
            let (next_claim, challenge_val) =
                symbolic_sumcheck_round(claim, round_pad, &hp.evals, ts);
            claim = next_claim;
            lchal_hc[hand].push(challenge_val);
        }
    }

    let eqq = eval_bound_quad(
        &clr.quad,
        claims_state.logv,
        &claims_state.hc[0],
        &claims_state.hc[1],
        &lchal_hc[0],
        &lchal_hc[1],
        clr.logw,
        alpha,
        beta,
    );

    let prod_expr = (Var(pad.claims.c0) * plr.claims[1]
        + Var(pad.claims.c1) * plr.claims[0]
        + Var(pad.claims.cr)
        + (plr.claims[0] * plr.claims[1]))
        * eqq;

    claim -= prod_expr;

    constrain_to_be_zero(a, b, &claim);

    end_layer(ts, &plr.claims);

    *claims_state = ClaimsState {
        logv: clr.logw,
        claim: [
            Var(pad.claims.c0) + plr.claims[0],
            Var(pad.claims.c1) + plr.claims[1],
        ],
        hc: lchal_hc,
    };
}

fn input_constraint<F: Field>(
    a: &mut Vec<LigeroTerm<F>>,
    b: &mut Vec<F>,
    num_public_inputs: usize,
    num_inputs: usize,
    pub_inputs: &[F],
    claims_logv: usize,
    claims_hc0: &[F],
    claims_hc1: &[F],
    got_expr: Expression<F>,
    alpha: F,
) {
    let mut eq_vec = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        eq_vec.push(eq2(i, claims_logv, claims_hc0, claims_hc1, alpha));
    }

    let mut pub_binding = F::zero();
    for i in 0..num_public_inputs {
        pub_binding += eq_vec[i] * pub_inputs[i];
    }

    let mut mle_expr = Expression::from(pub_binding);
    for w in 0..(num_inputs - num_public_inputs) {
        mle_expr += Var(w) * eq_vec[num_public_inputs + w];
    }

    mle_expr -= got_expr;

    constrain_to_be_zero(a, b, &mle_expr);
}

pub fn symbolic_sumcheck_verifier_core<F: Field + 'static>(
    mut pad_index: usize,
    pub_inputs: &[F],
    circuit_data: &Circuit<F>,
    proof: &[SumcheckLayerProof<F>],
    ts: &mut Transcript,
) -> SymRes<F> {
    let mut a = Vec::new();
    let mut b = Vec::new();

    let num_inputs = circuit_data.ninput;
    let num_public_inputs = circuit_data.npublic_input;

    let logv_output = ceil_lg2(circuit_data.noutput);
    let (_, g_ch) = begin_circuit::<F>(ts);
    let hc_init = g_ch[0..logv_output].to_vec();

    let mut claims_state = ClaimsState {
        logv: logv_output,
        claim: [Expression::zero(), Expression::zero()],
        hc: [hc_init.clone(), hc_init],
    };

    let circuit_pad = CircuitPad::generate_indices(circuit_data, &mut pad_index);

    for ly in 0..circuit_data.layers.len() {
        verify_layer(
            &mut a,
            &mut b,
            &mut claims_state,
            &circuit_pad.layers[ly],
            &circuit_data.layers[ly],
            &proof[ly],
            ts,
        );
    }

    let alpha_input = ts.get_elt_field();
    let got_expr = claims_state.claim[0].clone() + claims_state.claim[1].clone() * alpha_input;

    input_constraint(
        &mut a,
        &mut b,
        num_public_inputs,
        num_inputs,
        pub_inputs,
        claims_state.logv,
        &claims_state.hc[0],
        &claims_state.hc[1],
        got_expr,
        alpha_input,
    );

    SymRes { a, b }
}
```
