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
recursively in linear time as `bindv(EQ_{n}, X) = bindeq(l, X)` where

```
   bindeq(l, X) =
      LET n = 2^l
      allocate B[n]
      IF l = 0 THEN
         B[0] = 1
      ELSE
         LET A = bindeq(l - 1, X[1..])
         FOR 0 <= 2 * i < n DO
            B[2 * i]     = (1 - X[0]) * A[i]
            B[2 * i + 1] = X[0] * A[i]
         ENDFOR
      ENDIF
      return B
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
the polynomials are always of degree 2, and are represented by their
evaluations at three points `P0 = 0`, `P1 = 1`, and `P2`, where `0`
and `1` are the additive and multiplicative identities in the field.
The choice of `P2` depends upon the field.  For fields of characteristic
greater than 2, set `P2 = 2` (= `1 + 1` in the field).  For `GF(2^128)`
expressed as `GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)`, and set `P2
= X`.  This document does not prescribe a choice of P2 for binary
fields other than `GF(2^128)`, but other binary fields
represented as `GF(2)[X] / (Q(X))` SHOULD choose `P2 = X` for
consistency.

## Transform circuit and wires into a padded proof

```
sumcheck_circuit(circuit, wires, pad, transcript) {
  G[0] = G[1] = transcript.gen_challenge(circuit.lv)
  FOR 0 <= j < circuit.nl DO
     // Let V[j] be the output wires of layer j.
     // The body of the loop reduces the verification of the
     // two "claims" bind(V[j], G[0]) and bind(V[j], G[1])
     // to the verification of the two claims
     // bind(V[j + 1], G'[0]) and bind(V[j + 1], G'[1]),
     // where the new bindings G' are chosen in sumcheck_layer()

     alpha = transcript.gen_challenge(1)

     // Form the combined quad QZ = Q + beta Z
     // to handle in-circuit assertions
     beta = transcript.gen_challenge(1)
     QZ = circuit.layer[j].quad + beta * circuit.layer[j].Z;

     // QZ is three-dimensional QZ[g, l, r]
     QUAD = bindv(QZ, G[0]) + alpha * bindv(QZ, G[1])
     // having bound g, QUAD is two-dimensional QUAD[l, r]
     
     (proof[j], G) =
         sumcheck_layer(QUAD, wires[j], circuit.layer[j].lv,
                        pad[j], transcript)
  ENDFOR
  return proof
}
```

```
sumcheck_layer(QUAD, wires, lv, layer_pad, transcript) {
   (VL, VR) = wires
   FOR 0 <= round < lv DO
      FOR 0 <= hand < 2 DO
        Let p(x) =
           SUM_{l, r} bind(QUAD, x)[l, r] * bind(VL, x)[l] * VR[r]
        evals.p0 = p(P0) - layer_pad.evals[round][hand].p0
        // p(P1) is implied and not needed
        evals.p2 = p(P2) - layer_pad.evals[round][hand].p2
        layer_proof.evals[round][hand] = evals
        transcript.write(evals);
        challenge = transcript.gen_challenge(1)
        G[round][hand] = challenge

        // bind the L variable to CHALLENGE
        VL = bind(VL, challenge)
        QUAD = bind(QUAD, challenge)

        // swap L and R
        (VL, VR) = (VR, VL)
        QUAD = transpose(QUAD)
      ENDFOR
   ENDFOR
   layer_proof.vl = VL[0] - layer_pad.vl
   layer_proof.vr = VR[0] - layer_pad.vr
   transcript.write(layer_proof.vl)
   transcript.write(layer_proof.vr)
   return (layer_proof, G)
}
```

## Generate constraints from the public inputs and the padded proof

This section defines a procedure `constraints_circuit` for transforming the proof
returned by `sumcheck_circuit` into constraints for the commitment
scheme.  Specifically, each layer produces one linear constraint and one quadratic constraint.

The main difficulty in describing the algorithm is that it operates
not on concrete witnesses, but on expressions in which the witnesses
are symbolic quantities.  Symbolic manipulation is necessary because
the verifier does not have access to the witnesses.  To avoid
overspecifying the exact representation of such symbolic expressions,
the convention is that the prefix `sym_` indicates not a concrete
value, but a symbolic representation of the value.  Thus, `w[3]` is
the fourth concrete witness in the `w` array, and `sym_w[3]` is a
symbolic representation of the fourth element in the `w` array.  The
algorithm does not need arbitrarily complex symbolic expressions.  It
suffices to keep track of affine symbolic expressions of the form 
`k + SUM_{i} a[i] sym_w[i]` for some (concrete, nonsymbolic) field elements
`k` and `a[]`.

```
constraints_circuit(circuit, public_inputs, sym_private_inputs, 
                    sym_pad, transcript, proof) {
  G[0] = G[1] = transcript.gen_challenge(circuit.lv)
  claims = [0, 0]
  FOR 0 <= j < circuit.nl DO
     alpha = transcript.gen_challenge(1)
     beta = transcript.gen_challenge(1)
     QZ = circuit.layer[j].quad + beta * circuit.layer[j].Z;
     QUAD = bindv(QZ, G[0]) + alpha * bindv(QZ, G[1])
     (claims, G) = constraints_layer(
               QUAD, circuit.layer[j].lv, sym_pad[j], transcript,
               proof[j], claims, alpha)
  ENDFOR

  // now add constraints that the two final claims
  // equal the binding of sym_inputs at G[0], G[1]

  gamma = transcript.gen_challenge(1)
  LET eq2 = bindv(EQ, G[0]) + gamma * bindv(EQ, G[1])
  LET sym_layer_pad = sym_pad[circuit.nl - 1]
  LET npub = number of elements in public_inputs

  Output the linear constraint
      SUM_{i} (eq2[i + npub] * sym_private_inputs[i])
      - sym_layer_pad.vl 
      - gamma * sym_layer_pad.vr
    = 
      - SUM_{i} (eq2[i] * public_inputs[i])
      + claims[0]
      + gamma * claims[1]
}
```

```
constraints_layer(QUAD, wires, lv, sym_layer_pad, transcript,
                  layer_proof, claims, alpha) {
   // Initial symbolic claim, which happens to be
   // a known constant but which will be updated to contain
   // symbolic linear terms later.
   LET sym_claim = claims[0] + alpha * claims[1]

   FOR 0 <= round < lv DO
      FOR 0 <= hand < 2 DO
        LET hp = layer_proof.evals[round][hand]
        LET sym_hpad = sym_layer_pad.evals[round][hand]

        transcript.write(hp);
        challenge = transcript.gen_challenge(1)
        G[round][hand] = challenge

        // Now the unpadded polynomial evaluations are expected
        // to be
        //   p(P0) = hp.p0 + sym_hpad.p0
        //   p(P2) = hp.p2 + sym_hpad.p2
        LET sym_p0 = hp.p0 + sym_hpad.p0
        LET sym_p2 = hp.p2 + sym_hpad.p2

        // Compute the implied p(P1) = claim - p(P0) in symbolic form
        LET sym_p1 = sym_claim - sym_p0

        LET lag_i(x) =
               the quadratic polynomial such that
                      lag_i(P_k) = 1  if i = k
                                   0  otherwise
               for 0 <= k < 3

        // given p(P0), p(P1), and p(P2), interpolate the
        // new claim symbolically
        sym_claim =   lag_0(challenge) * sym_p0
                    + lag_1(challenge) * sym_p1
                    + lag_2(challenge) * sym_p2

        // bind L
        QUAD = bind(QUAD, challenge);

        // swap left and right
        QUAD = transpose(QUAD)
      ENDFOR
   ENDFOR

   // now the bound QUAD is a scalar (a 1x1 array)
   LET Q = QUAD[0,0]

   // now verify that
   //
   //   SYM_CLAIM = Q * VL * VR
   //
   // where VL = layer_proof.vl + layer_pad.vl
   //       VR = layer_proof.vr + layer_pad.vr

   // decompose SYM_CLAIM into the known constant
   // and the symbolic part
   LET known + symbolic = sym_claim

   Output the linear constraint
      symbolic
      - (Q * layer_proof.vr) * sym_layer_pad.vl
      - (Q * layer_proof.vl) * sym_layer_pad.vr
      - Q * sym_layer_pad.vl_vr
     =
      Q * layer_proof.vl * layer_proof.vl - known

   Output the quadratic constraint

      sym_layer_pad.vl * sym_layer_pad.vr = sym_layer_pad.vl_vr

   transcript.write(layer_proof.vl)
   transcript.write(layer_proof.vr)

   return (G, [layer_proof.vl, layer_proof.vr])
}
```
