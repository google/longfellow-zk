# Ligero ZK Proof
This section specifies the construction and verification method for a Ligero commitment and zero-knowledge argument. The Ligero system as described by Ames, Hazay, Ishai, and Venkitasubramaniam [@ligero], consists of a commitment scheme, and a method for proving linear and quadratic constraints on the committed values in zero-knowledge. The later interface is sufficient to prove arbitrary circuits, but in the Longfellow scheme, it suffices to describe how to use such constraints to directly verify an IP transcript.

<reference anchor='ligero' target='https://eprint.iacr.org/2022/1608'>
    <front>
        <title>Ligero: Lightweight Sublinear Arguments Without a Trusted Setup</title>
        <author initials='S.' surname='Ames' fullname='Scott Ames'>
        </author>
        <author initials='C.' surname='Hazay' fullname='Carmit Hazay'>
        </author>
        <author initials='Y.' surname='Ishai' fullname='Yuval Ishai'>
        </author>
        <author initials='M.' surname='Venkitasubramaniam' fullname='Muthuramakrishnan Venkitasubramaniam'>
        </author>
        <date year='2022'/>
    </front>
</reference>

## Merkle trees
This section describes how to construct a Merkle tree from a sequence of `n` strings, and how to verify that a given string `x` was placed at leaf `i` in a Merkle tree. These methods do not assume that `n` is a power of two. This construction is parameterized by a cryptographic hash function such as SHA-256 [@RFC6234].  In this application, a leaf in a tree is a message digest instead of an arbitrary string; for example, if the hash function is SHA-256, then the leaf is a 32-byte string.

A tree that contains `n` leaves is represented by an array of `2 * n` message digests in which the input digests are written at indicies `n..(2*n - 1)`.  The tree is constructed by iteratively hashing the concatenation of the values at indicies `2*j` and `2*j+1`, starting at `j=n-1`, and continuing until `j=1`. The root is at index 1. In this specification, the prover and verifier will already know the value of `n` when they produce or verify a Merkle tree.

### Constructing a Merkle tree from `n` digests

```
struct {
   Digest a[2 * n]
} MerkleTree

def set_leaf(M, pos, leaf) {
  assert(pos < M.n)
  M.a[pos + n] = leaf
}

def build_tree(M) {
  FOR M.n < i <= 1 DO
    M.a[i] = hash(M.a[2 * i] || M.a[2 * i + 1])
  return M.a[1]
}
```

### Constructing a proof of inclusion
This section describes how to construct a Merkle proof that `k` input digests at indicies `i[0],...,i[k-1]` belong to the tree.  The simplest way to generate such a proof is to produce independent proofs for each of the `k` leaves. However, this turns out to be wasteful in that internal nodes may be included multiple times along different paths, and some nodes may not need to be included at all because they are implied by nodes that have already been included.

To address these inefficiencies, this section explains how to produce a batch proof of inclusion for `k` leaves. The main idea is to start from the requested set of leaves and build all of the implied internal nodes given the leaves. For example, if sibling leaves are included, then their parent is implied, and the parent need not be included in the compressed proof.  Then it suffices to revisit the same tree and include the necessary siblings along all of the Merkle paths.  It is assumed that the verifier already has the leaf digests that are at the indicies, and thus the proof only contains the necessary internal nodes of the Merkle tree that are used to verify the claim.

It is important in this formulation to treat the input digests as a sequence, i.e. with a given order. Both the prover and verifier of this batch proof must use the same order of the `requested_leaves` array.

```
def compressed_proof(M, requested_leaves[], n) {
  marked = mark_tree(requested_leaves, n)
  FOR n < i <= 1 DO
    IF (marked[i]) {
      child = 2 * i
      IF (marked[child]) {
        child += 1
      }
      IF (!marked[child]) {
        proof.append(M.a[child])
      }
    }
  return proof
}

def mark_tree(requested_leaves[], n) {
  bool marked[2 * n]   // initialized to false

  for(index i : requested_leaves)
    marked[i + n] = true

  FOR n < i <= 1 DO
    // mark parent if child is marked
    marked[i] = marked[2 * i] || marked[2 * i + 1];

  return marked
}
```

### Verifying a proof of inclusion
This section describes how to verify a compressed Merkle proof. The claim to verify is that "the commitment `root` defines an `n`-leaf Merkle tree that contains `k` digests s[0],..s[k-1] at corresponding indicies i[0],...i[k-1]."  The strategy of this verification procedure is to deduce which nodes are needed along the `k` verification paths from index to root, then read these values from the purported proof, and then recompute the Merkle tree and the consistency of the `root` digest. As an optimization, the `defined[]` array avoids recomputing internal portions of the Merkle tree that are not relevant to the verification. By convention, a proof for the degenerate case of `k=0` digests is defined to fail. It is assumed that the `indicies[]` array does not contain duplicates.

```
def verify_merkle(root, n, k,  s[], indicies[], proof[]) {
  tmp = []
  defined = []

  proof_index = 0
  marked = mark_tree(indicies, n)
  FOR n < i <= 1 DO
    if (marked[i]) {
      child = 2 * i
      if (marked[child]) {
        child += 1
      }
      if (!marked[child]) {
        if proof_index > |proof| {
          return false
        }
        tmp[child] = proof[proof_index++]
        defined[child] = true
      }
    }

  FOR 0 <= i < k DO
    tmp[indicies[i] + n] = s[i]
    defined[indicies[i] + n] = true

  FOR n < j <= 1 DO
    if defined[2 * i] && defined[2 * i + 1] {
      tmp[i] = hash(tmp[2 * i] || tmp[2 * i + 1])
      defined[i] = true
    }

  return defined[1] && tmp[1] = root
}
```

## Common parameters
The Prover and Verifier in Ligero must agree on the following parameters. These parameters can be agreed upon out of band.

- `F`: The finite field over which the commit is produced.
- `NREQ`: The number of columns of the commitment matrix that the Verifier requests to be revealed by the Prover.
- `rate`: The inverse rate of the error correcting code. This parameter, along with `NREQ` and Field size, determines the soundness of the scheme.
- `BLOCK`: the size of each row, in terms of number of field elements
- `DBLOCK`: 2 * `BLOCK` - 1
- `WR`: the number of witness values included in each row.
- `QR`: the number of quadratic constraints written in each row
- `IW`: Row index at which the witness values start, usually IW = 2.
- `IQ`: Row index at which the quadratic constraints begin, it is the first row after all of the witnesses have been encoded.
- `NL`: Number of linear constraints.
- `NQ`: Number of quadratic constraints.
- `NWROW`: Number of rows used to encode witnesses.
- `NQT`: Number of row triples needed to encode the quadratic constraints.
- `NQW`: `NWROW + NQT`, rows needed to encode witnesses and quadratic constraints.
- `NROW`: Total number of rows in the witness matrix, `NQW + 2`
- `NCOL`: Total number of columns in the tableau matrix.

A row of the tableau consists of

|     NREQ     |        WR          | ... DBLOCK | ... NCOL  |
|  random pad  |   witness values   | polynomial evaluations |

### Constraints on parameters

- `BLOCK < |F|` The block size must be smaller than the field size.
- `BLOCK > NREQ` The block size must be larger than the number of columns requested.
- `BLOCK = NREQ + WR`

- `BLOCK >= 2 * (NREQ + QR) + (NREQ + WR) - 2`
- `WR >= QR`.
- `BLOCK >= 2 * (NREQ + WR) - 1`.
- `QR >= NREQ` (and thus `WR >= NREQ`) to avoid wasting too much space.

## Ligero commitment
The first step of the proof procedure requires the Prover to commit to a witness vector `W`.  The witness vector is assumed to be padded with zeros at the end so that its length is an even multiple of `WR`. The commitment is the root of a Merkle tree. The leaves of the Merkle tree are a sequence of columns of the tableau matrix `T[][]`.

This tableau matrix is constructed row-by-row by applying the extend procedure to arrays that are formed from random field elements and elements copied from the witness vector. Matrix T[][] has size NROW x NCOL and has the following structure:

    row ILDT = 0                         : RANDOM row for low-degree test
    row IDOT = 1                         : RANDOM row for linear test
    row IQD  = 2                         : RANDOM row for quadratic test
    row i for IW = IDOT + 1 <= i < IQ    : witness rows
    row i for IQ <= i < NROW             : quadratic rows

1)  The first ILDT row is defined as

        extend(RANDOM[BLOCK], BLOCK, NCOL)

    by selecting BLOCK random field elements and applying extend.
1)  The second IDOT row is defined as

        Z = RANDOM[DBLOCK] such that sum_{i = NREQ ... NREQ + WR - 1} Z_i = 0
        extend(Z, DBLOCK, NCOL)

    by first selecting DBLOCK random field elements such that the subarray
    from index NREQ to NREQ + WR sums to 0 and then applying extend.
    The first step can be performed by selecting DBLOCK-1 random
    field elements, and then setting element of the specified range to be the additive inverse of the sum of elements from NREQ...NREQ + WR - 1.
1)  The third IQD row is defined as 
        ZQ = RANDOM[DBLOCK]
        ZQ[NREQ ... NREQ + WR - 1] = 0
        extend(ZQ, DBLOCK, NCOL)
    by first selecting DBLOCK random field elements, and then setting the
    portion coresponding to the witness values to 0 and then applying extend.
        
1)  The next rows from IW=3,...,IQ are *padded witness* rows that contain
    random elements and portions of the witness vector.
    Specifically, row i is formed by applying `extend` to an array that
    consists of `NREQ` random elements and then `WR` elements from the vector `W`:

        extend([RANDOM[NREQ], W[(i-2) * WR .. (i-1) * WR]], BLOCK, NCOL)
    
    When the finite field contains a subfield, and if all of the witness elements in a given row are elements from this subfield, then the randomness for that row can also be chosen from the subfield.
    Consequently, the `extend` method for that row produces polynomial evaluations that are elements of the subfield. When these elements are serialized, they will require less space.
    The simplest way to apply this optimization is for the commiting process to maintain an index `SF` such that witnesses at indices `0..SF` belong to the subfield, and the rest do not. This value `SF` can be conveyed to the verifier as part of the proof, or part of the circuit.

1)  The final portion of the witness matrix consists of *padded quadratic* rows
    that consists of NREQ random elements and WR quadratic constraint elements:

        extend([RANDOM[NREQ], QX[WR]], BLOCK, NCOL)
        extend([RANDOM[NREQ], QY[WR]], BLOCK, NCOL)
        extend([RANDOM[NREQ], QZ[WR]], BLOCK, NCOL)

    The specific elements in the QX, QY, QZ array are determined by the quadratic
    constraints on the witness values that are verified by the proof.

The second step of the procedure is to compute a Merkle tree on columns
of the tableau matrix. Specifically, the i-th leaf of the tree is defined
to be columns DBLOCK...NCOL of the i-th row of the tableau T.

Input:

- The witness vector `W`.
- Array of quadratic constraints `lqc[]`, which consists of triples `(x,y,z)` that represent the constraint that `W[x] * W[y] = W[z]`.

Output:

- A digest; root of a Merkle tree formed from columns of the tableau.

```
def commit(W[], lqc[]) {
    T[NROW][NCOL] = [0];   // 2d array initialized with 0

    layout_zk_rows(T);
    layout_witness_rows(T, W);
    layout_quadratic_rows(T, W, lqc);

    MerkleTree M;
    FOR DBLOCK <= j < NCOL DO
      M.set_leaf(j - BLOCK,
          hash( T[0][j] || T[1][j] || .. || T[NROW][j]) );

    return M.build_tree();
}

def layout_zk_rows(T) {
    T[0][0..NCOL] = extend(random_row(BLOCK), BLOCK, NCOL);

    Z = random_row(DBLOCK)
    s = SUM_{i = NREQ ... NREQ + WR - 2} Z_i 
    Z[NREQ + WR - 1] = -s
    T[1][0..NCOL] = extend(Z, DBLOCK, NCOL)

    ZQ = random_row[DBLOCK]
    ZQ[NREQ ... NREQ + WR - 1] = 0
    T[2][0..NCOL] = extend(ZQ, DBLOCK, NCOL)
}
```

```
def layout_witness_rows(T, w) {

  FOR IW <= i <= IQ DO
    bool subfield = false;

    IF W[i * WR .. (i+1) * WR] are all in the subfield {
      subfield = true;
    }

    row[0...NREQ-1] = random_row(NREQ, subfield)
    row[NREQ..BLOCK] = W[i * WR .. (i+1) * WR]

    T[i + IW][0..NCOL] = extend(row, BLOCK, NCOL)
}
```

```
def layout_quadratic_rows(T, w, lqc[]) {
    FOR 0 <= i < NQT DO
      qx[0..NREQ] = random_row(NREQ)
      qy[0..NREQ] = random_row(NREQ)
      qz[0..NREQ] = random_row(NREQ)

      FOR 0 <= j < BLOCK  DO
        IF (j + i * Q < NQ)
          assert( W[ lqc[j].x ] * W[ lqc[j].x ] == W[ lqc[j].z ] )
          qx[NREQ + j] = W[ lqc[j].x ]
          qy[NREQ + j] = W[ lqc[j].y ]
          qz[NREQ + j] = W[ lqc[j].z ] 

      T[IQ + i * NQT    ][0..NCOL] = extend(qx, BLOCK, NCOL)
      T[IQ + i * NQT + 1][0..NCOL] = extend(qy, BLOCK, NCOL)
      T[IQ + i * NQT + 2][0..NCOL] = extend(qz, BLOCK, NCOL)
}
```

## Ligero Prove
This section specifies how a Ligero proof for a given sequence of linear constraints and quadratic constraints on the committed witness vector `W` is constructed. The proof consists of a low-degree test on the tableau, a linearity test, and a quadratic constraint test.

### Low-degree test
In the low-degree test, the verifier sends a challenge vector consisting of `NROW` field elements, `u[0..NROW]`.  This challenge is generated via the Fiat-Shamir transform. The prover computes the sum of `u[i]*T[i]` where `T[i]` is the i-th row of the tableau, and returns the first BLOCK elements of the result. The verifier applies the `extend` method to this response, and then verifies that the extended row is consistent with the positions of the Merkle tree that the verifier will later request from the Prover.

The Prover's task is therefore to compute a summation. For efficiency, set `u[0]=1` because this first row corresponds to a random row meant to ``pad" the witnesses for zero-knowledge.

### Linear and Quadratic constraints
The linear test is represented by a matrix `A`, and a vector `b`, and aims to verify that `A*W = b`.  The constraint matrix `A` is given as input in a sparse form: it is an array of triples `(c,j,k)` in which `c` indicates the constraint number or row of A, `j` represents the index of the witness or column of A, and `k` represents the constant factor.  For example, if the first constraint (at index 0) is `W[2] + 2W[3] = 3`, then the linear constraints array contains the triples `(0,2,1), (0,3,2)` and the `b` vector has `b[0]=3`.

The quadratic constraints are given as input in an array `lqc[]` that contains triples `(x,y,z)`; one such triple represents the constraint that `W[x] * W[y] = W[z]`. To process quadratic constraints, tableau `T` is augmented with 3 extra rows, called `Qx`, `Qy`, and `Qz` which hold *copied* witnesses and their products. If the `i`-th quadratic constraint is `(x,y,z)`, then the prover sets `Qx[i] = W[x]`, `Qy[i] = W[y]` and `Qz[i] = W[x] * W[y]`. Next, the prover adds a linear constraint that `Qx[i] - W[x] = 0`, `Qy[i] - W[y] = 0` and `Qz[i] - W[z] = 0` to ensure that the copied witness is consistent.

In this sense, the quadratic constraints are reduced to linear constraints, and the additional requirement for the verifier to check that each index of the `Qz` row is the product of its counterpart in the `Qx` and `Qy` row.

### Selection of challenge indicies
The last step of the prove method is for the verifier to select a subset of unique indicies (i.e., they are sampled without replacement) from the range `DBLOCK...NCOL` and request that the prover open these columns of tableau `T`. These opened columns are then used to verify consistency with the previous messages sent by the prover.

### Ligero Prover procedure
```
def prove(transcript, digest, linear[], lqc[])  {

    u = transcript.generate_challenge([BLOCK]);
    transcript.write(digest)

    ldt[0..BLOCK] = T[ILDT][0..BLOCK]

    for(i=3; i < NROW; ++i) {
      ldt[0..BLOCK] += u[i] * T[i][0..BLOCK]
    }

    alpha_l = transcript.generate_challenge([NL]);
    alpha_q = transcript.generate_challenge([NQ,3]);

    A = inner_product_vector(linear, alpha_l, lqc, alpha_q);

    dot = dot_proof(A);
    uquad = transcript.generate_quad()

    qpr = quadratic_proof(lqc, uquad)

    transcript.write(ldt);
    transcript.write(dot);
    transcript.write(qpr);

    challenge_indicies = transcript.generate_challenge([NREQ]);

    columns = requested_columns(challenge_indicies);

    mt_proof = M.compressed_proof(challenge_indicies);

    return (ldt, dot, qpr, columns, mt_proof)
  }
```

```
Input:
- linear: array of (w,c,k) triples specifying the linear constraints
- alpha_l: array of challenges for the linear constraints
- lqc: array of (x,y,z) triples specifying the quadratic constraints
- alpha_q: array of challenges for the quadratic constraints

Output:
- A: a vector of size WR x NROW that contains the combined 
     witness constraints.
     The first NW * W positions correspond to coefficients
     for the linear constraints on witnesses.
     The next 3*NQ positions correspond to coefficients
     for the quadratic constraints.

def inner_product_vector(A, linear, alpha_l, lqc, alpha_q) {
  A = [0]

  // random linear combinations of the linear constraints
  FOR 0 <= i < NL DO
    assert(linear[i].w < NW)
    assert(linear[i].c < NL)
    A[ linear[i].w ] += alpha_l[ linear[i].c ] * linear[i].k

  // pointers to terms for quadratic constraints
  a_x = NW * W
  a_y = NW * W + (NQ * W)
  a_z = NW * W + 2 * (NQ * W)

  FOR 0 <= i < NQT DO
    FOR 0 <= j < QR DO
      IF (j + i * QR < NQ)
        ilqc = j + i * QR  // index into lqc
        ia   = j + i * WR  // index into Ax,Ay,Az sub-arrays
        (x,y,z) = lqc[ilqc]

        // add constraints that the copies are correct
        A[a_x + ia] += alpha_q[ilqc][0]
        A[x]        -= alpha_q[ilqc][0]

        A[a_y + ia] += alpha_q[ilqc][1]
        A[y]        -= alpha_q[ilqc][1]

        A[a_z + ia] += alphaq[ilqc][2]
        A[z]        -= alphaq[ilqc][2]

  return A
}

def dot_proof(A) {
  y = T[IDOT][0..BLOCK]

  Aext[0..BLOCK] = [0]
  FOR 0 <= i < NQW DO
    Aext[0..NREQ]  = [0]
    Aext[NREQ..NREQ + WR] = A[i * WR..(i+1) * WR]
    Af = extend(Aext, BLOCK, DBLOCK)

    axpy(DBLOCK, y[0..DBLOCK], Af[0..DBLOCK], T[i + IW][0...DBLOCK])

  return y
}

def quadratic_proof(lqc, uquad) {

    y[0..DBLOCK] = T[IQD][0..DBLOCK]

    iqx = IQ;
    iqy = iqx + NQT
    iqz = iqy + NQT

    FOR 0 <= i < NQT 
      // y += u_quad[i] * (z[i] - x[i] * y[i])

      tmp = T[iqz + i][0..DBLOCK]

      // tmp -= x[i] \otimes y[i]
      sub(DBLOCK, tmp[0...DBLOCK],
                  mul(DBLOCK, T[iqx][0..DBLOCK],
                              T[iqy][0..DBLOCK]))

      // y += u_quad[i] * tmp
      axpy(DBLOCK, y[0..DBLOCK], u_quad[0..DBLOCK], tmp[0..DBLOCK])
    }

    // sanity check: the Witness part of Y is zero
    assert(y[NREQ...BLOCK] == 0)

    // extract the non-zero parts of y
    return y[0..NREQ], y[BLOCK..DBLOCK]
}

def requested_columns(challenge_indicies) {
  cols = []   // array of columns of T
  FOR (index i : challenge_indicies) {
    cols.append( [ T[0..NROW][i] ] )
  }
  return cols
}


```

## Ligero verification procedure
This section specifies how to verify a Ligero proof with respect to a common set of linear and quadratic constraints.

```
Input:
- commitment: the first Prover message that commits to the witness
- proof: Prover's proof
- transcript: Fiat-Shamir
- linear: array of (w,c,k) triples specifying the linear constraints
- b: the vector b in the constraint equation A*w = b.
- lqc: array of (x,y,z) triples specifying the quadratic constraints

Output:
- a boolean

def verify(commitment, proof, transcript,
           linear[], digest, b[], lqc[]) {

  u = transcript.generate_challenge([BLOCK]);
  transcript.write(digest)
  alpha_l = transcript.generate_challenge([NL]);
  alpha_q = transcript.generate_challenge([NQ,3]);
  transcript.write(proof.ldt);
  transcript.write(proof.dot);
  challenge_indicies = transcript.generate_challenge([NREQ]);

  A = inner_product_vector(linear, alpha_l, lqc, alpha_q);

  // check the putative value of the inner product
  want_dot  = dot(NL, b, alpha_l);
  proof_dot = sum(proof.dot);

  return
    verify_merkle(commitment.root, BLOCK*RATE, NREQ,
          proof.columns, challenge_indicies, mt_proof.mt)
    AND quadratic_check(proof)
    AND low_degree_check(proof, challenge_indicies, u)
    AND dot_check(proof, challenge_indicies, A)
    AND want_dot == proof_dot
}
```

```
def quadratic_check(proof, challenge_indices) {

  iqx = IQ;
  iqy = iqx + NQT
  iqz = iqy + NQT
  yc = proof.iquad

  FOR 0 <= i < NQT {
    // yc += u_quad[i] * (z[i] - x[i] * y[i])
    tmp = proof.z[iqz + i][0..DBLOCK]

      // tmp -= x[i] \otimes y[i]
    sub(DBLOCK, tmp[0...DBLOCK],
                mul(DBLOCK, T[iqx][0..DBLOCK],
                            T[iqy][0..DBLOCK]))

    // y += u_quad[i] * tmp
    axpy(DBLOCK, yc[0..DBLOCK], u_quad[0..DBLOCK], tmp[0..DBLOCK])
  }

  yquad = proof.qpr[0..NREQ] || 0 || proof.qpr[BLOCK...DBLOCK]
  yp = extend(yquad, DBLOCK, NCOL)

  // Verify that yp and yc agree at the challenge indices.
  want = gather(NREQ, yp, challenge_indices)
  return equal(NREQ, want, yc[{idx}])
}

def low_degree_check(proof, u, challenge_indicies) {

  got = proof.columns[ILDT][0..NREQ]

  FOR 1 <= i < NROW DO {
    axpy(NREQ, got, u[i], proof.columns[i][...])
  }

  row = extend(proof.ldt, BLOCK, NCOL)
  want = gather(NREQ, row, challenge_indicies)

  return equal(NREQ, got, want)
}

def dot_check(proof, challenge_indicies, A) {
  yc = proof.columns[IDOT][0..NREQ]

  Aext[0..BLOCK] = [0]
  FOR 0 <= i < NQW DO
    Aext[0..R]  = [0]
    Aext[R..R + WR] = A[i * WR..(i+1) * WR]
    Af = extend(Aext, R + WR, BLOCK)

    Areq = gather(NREQ, Af, challenge_indicies);

    // Accumulate z += A[j] \otimes W[j].
    sum( yc, prod(NCOL, Areq[0..NREQ], 
                        proof.columns[i][0..NREQ]))

  row = extend(proof.dot, BLOCK, NCOL)
  yp  = gather(NREQ, row, challenge_indicies)

  return equal(NREQ, yp, yc)
}
```
