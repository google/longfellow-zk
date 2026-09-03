# Ligero ZK Proof {#ligero-zk-proof}
This section specifies the construction and verification method for a Ligero commitment and zero-knowledge argument. The Ligero system as described by Ames, Hazay, Ishai, and Venkitasubramaniam [@ligero], consists of a commitment scheme, and a method for proving linear and quadratic constraints on the committed values in zero-knowledge. The latter interface is sufficient to prove arbitrary circuits, but in the Longfellow scheme, it suffices to describe how to use such constraints to directly verify an IP transcript.

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
This section describes how to construct a Merkle tree from a sequence of `n` strings, and how to verify that a given string `x` was placed at leaf `i` in a Merkle tree. These methods do not assume that `n` is a power of two. This construction is parameterized by the cryptographic hash function SHA-256 [@RFC6234].  In this application, a leaf in a tree is a message digest instead of an arbitrary string; for example, when the hash function is SHA-256, then the leaf is a 32-byte string.

A tree that contains `n` leaves is represented by an array of `2 * n` message digests in which the input digests are written at indicies `n..(2*n - 1)`.  The tree is constructed by iteratively hashing the concatenation of the values at indicies `2*j` and `2*j+1`, starting at `j=n-1`, and continuing until `j=1`. The root is at index 1. In this specification, the prover and verifier will already know the value of `n` when they produce or verify a Merkle tree.

### Constructing a Merkle tree from `n` digests

```rust
pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[derive(Clone, Debug)]
pub struct MerkleHeap {
    pub num_leaves: usize,
    pub layers: Vec<Vec<u8>>,
    pub root: Vec<u8>,
}

impl MerkleHeap {
    pub fn new(leaves: &[Vec<u8>]) -> Self {
        let n = leaves.len();
        let mut layers = vec![Vec::new(); 2 * n];
        layers[n..(n + n)].clone_from_slice(&leaves[..n]);
        for i in (1..n).rev() {
            let mut data = Vec::new();
            data.extend_from_slice(&layers[2 * i]);
            data.extend_from_slice(&layers[2 * i + 1]);
            layers[i] = sha256_bytes(&data);
        }
        let root = layers[1].clone();
        Self {
            num_leaves: n,
            layers,
            root,
        }
    }
}
```

### Constructing a proof of inclusion
This section describes how to construct a Merkle proof that `k` input digests at indicies `i[0],...,i[k-1]` belong to the tree.  The simplest way to generate such a proof is to produce independent proofs for each of the `k` leaves. However, this turns out to be wasteful in that internal nodes may be included multiple times along different paths, and some nodes may not need to be included at all because they are implied by nodes that have already been included.

To address these inefficiencies, this section explains how to produce a batch proof of inclusion for `k` leaves. The main idea is to start from the requested set of leaves and build all of the implied internal nodes given the leaves. For example, if sibling leaves are included, then their parent is implied, and the parent need not be included in the compressed proof.  Then it suffices to revisit the same tree and include the necessary siblings along all of the Merkle paths.  It is assumed that the verifier already has the leaf digests that are at the indicies, and thus the proof only contains the necessary internal nodes of the Merkle tree that are used to verify the claim.

It is important in this formulation to treat the input digests as a sequence, i.e. with a given order. Both the prover and verifier of this batch proof must use the same order of the `requested_leaves` array.

```rust
pub fn open_merkle_heap(
    mh: &MerkleHeap,
    leaf_indices: &[usize],
) -> Result<Vec<Vec<u8>>, &'static str> {
    let n = mh.num_leaves;
    let mut seen = vec![false; n];
    let mut is_on_path = vec![false; 2 * n];
    for &idx in leaf_indices {
        if idx >= n {
            return Err("Leaf index out of bounds in Merkle opening");
        }
        if seen[idx] {
            return Err("Duplicate leaf index in Merkle opening");
        }
        seen[idx] = true;
        is_on_path[n + idx] = true;
    }
    for i in (1..n).rev() {
        is_on_path[i] = is_on_path[2 * i] || is_on_path[2 * i + 1];
    }

    let mut path = Vec::new();
    for i in (1..n).rev() {
        if is_on_path[i] {
            if is_on_path[2 * i] && !is_on_path[2 * i + 1] {
                path.push(mh.layers[2 * i + 1].clone());
            } else if !is_on_path[2 * i] && is_on_path[2 * i + 1] {
                path.push(mh.layers[2 * i].clone());
            }
        }
    }
    Ok(path)
}
```

### Verifying a proof of inclusion
This section describes how to verify a compressed Merkle proof. The claim to verify is that "the commitment `root` defines an `n`-leaf Merkle tree that contains `k` digests `s[0], ..., s[k-1]` at corresponding indices `i[0], ..., i[k-1]`."  The strategy of this verification procedure is to deduce which nodes are needed along the `k` verification paths from index to root, then read these values from the purported proof, and then recompute the Merkle tree and the consistency of the `root` digest. As an optimization, the `defined[]` array avoids recomputing internal portions of the Merkle tree that are not relevant to the verification. By convention, a proof for the degenerate case of `k=0` digests is defined to fail. It is assumed that the `indices[]` array does not contain duplicates.

```rust
pub fn verify_merkle_proof<F>(
    n: usize,
    root: &[u8],
    leaf_indices: &[usize],
    path: &[Vec<u8>],
    mut leaf_hash_fn: F,
) -> Result<(), &'static str>
where
    F: FnMut(usize) -> Vec<u8>,
{
    let mut seen = vec![false; n];
    let mut is_on_path = vec![false; 2 * n];
    for &idx in leaf_indices {
        if idx >= n {
            return Err("Leaf index out of bounds in Merkle proof verification");
        }
        if seen[idx] {
            return Err("Duplicate leaf index in Merkle proof verification");
        }
        seen[idx] = true;
        is_on_path[n + idx] = true;
    }
    for i in (1..n).rev() {
        is_on_path[i] = is_on_path[2 * i] || is_on_path[2 * i + 1];
    }

    let mut layers: Vec<Option<Vec<u8>>> = vec![None; 2 * n];
    for &idx in leaf_indices {
        layers[n + idx] = Some(leaf_hash_fn(idx));
    }

    let mut path_idx = 0;
    for i in (1..n).rev() {
        if is_on_path[i] {
            let left_val = if is_on_path[2 * i] {
                layers[2 * i].clone()
            } else {
                let val = path.get(path_idx).cloned();
                path_idx += 1;
                val
            };
            let right_val = if is_on_path[2 * i + 1] {
                layers[2 * i + 1].clone()
            } else {
                let val = path.get(path_idx).cloned();
                path_idx += 1;
                val
            };

            if let (Some(left_val), Some(right_val)) = (left_val, right_val) {
                let mut data = Vec::with_capacity(left_val.len() + right_val.len());
                data.extend_from_slice(&left_val);
                data.extend_from_slice(&right_val);
                layers[i] = Some(sha256_bytes(&data));
            } else {
                return Err("Missing path value in Merkle proof verification");
            }
        }
    }

    if path_idx != path.len() {
        return Err("Not all Merkle path elements were consumed");
    }

    if let Some(computed_root) = &layers[1] {
        if computed_root == root {
            Ok(())
        } else {
            Err("Merkle root mismatch")
        }
    } else {
        Err("Merkle root was not computed")
    }
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
- `IW`: Row index at which the witness values start, usually IW = 3.
- `IQ`: Row index at which the quadratic constraints begin, it is the first row after all of the witnesses have been encoded.
- `NL`: Number of linear constraints.
- `NQ`: Number of quadratic constraints.
- `NWROW`: Number of rows used to encode witnesses.
- `NQT`: Number of row triples needed to encode the quadratic constraints.
- `NQW`: `NWROW + NQT`, rows needed to encode witnesses and quadratic constraints.
- `NROW`: Total number of rows in the witness matrix, `3 + NQW + 3*NQT`
- `NCOL`: Total number of columns in the tableau matrix.

A row of the tableau consists of

|     NREQ     |        WR          | ... DBLOCK | ... NCOL  |
|  random pad  |   witness values   | polynomial evaluations |

### Constraints on parameters

- `BLOCK < |F|` The block size must be smaller than the field size.
- `BLOCK > NREQ` The block size must be larger than the number of columns requested.
- `BLOCK = NREQ + WR`
- `BLOCK >= 2 * (NREQ + WR) + (NREQ + WR) - 2`
- `BLOCK >= 2 * (NREQ + WR) - 1`.
- `WR >= NREQ` (and thus `WR >= NREQ`) to avoid wasting too much space.

## Ligero commitment
The first step of the proof procedure requires the Prover to commit to a witness vector `W`.  The witness vector is assumed to be padded with zeros at the end so that its length is an even multiple of `WR`. The commitment is the root of a Merkle tree. The leaves of the Merkle tree are a sequence of columns of the tableau matrix `T[][]`.

This tableau matrix is constructed row-by-row by applying the extend procedure to arrays that are formed from random field elements and elements copied from the witness vector. Matrix T[][] has size NROW x NCOL and has the following structure:

    row ILDT = 0                         : RANDOM row for low-degree test
    row IDOT = 1                         : RANDOM row for linear test
    row IQD  = 2                         : RANDOM row for quadratic test
    row i for IW = IQD + 1 <= i < IQ    : witness rows
    row i for IQ <= i < NROW             : quadratic rows

1)  The first ILDT row is defined as

        extend(RANDOM[BLOCK], BLOCK, NCOL)

    by selecting BLOCK random field elements and applying extend.
1)  The second IDOT row is defined as

        Z = RANDOM[DBLOCK] such that
            sum_{i = NREQ ... NREQ + WR - 1} Z_i = 0
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

```rust
pub struct LigeroCommitResult<F> {
    pub geometry: LigeroGeometry,
    pub tableau: Vec<Vec<F>>,
    pub merkle: MerkleHeap,
    pub nonces: Vec<Vec<u8>>,
}

impl<F: Field + 'static> LigeroProver<F> {
    pub fn commit<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        rng: &mut R,
        subfield_boundary: usize,
    ) -> LigeroCommitResult<F> {
        let tableau = self.layout_tableau(witness, lqc, subfield_boundary, rng);

        let geom = self.geometry;
        let dblock = geom.dblock_len;
        let block_enc = geom.encoded_len;

        let num_committed_cols = block_enc - dblock;
        let update_leaf_hash = |j: usize| {
            let col_idx = j + dblock;
            let mut data = Vec::new();
            for row in 0..tableau.len() {
                data.extend_from_slice(&tableau[row][col_idx].to_bytes());
            }
            data
        };

        let (heap, nonces) = commit_merkle_heap(num_committed_cols, update_leaf_hash, rng);

        LigeroCommitResult {
            geometry: geom,
            tableau,
            merkle: heap,
            nonces,
        }
    }

    fn layout_tableau<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        subfield_boundary: usize,
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let mut tableau = Vec::new();
        tableau.push(self.layout_ildt_row(rng));
        tableau.push(self.layout_idot_row(rng));
        tableau.push(self.layout_iquad_row(rng));
        tableau.extend(self.layout_witness_rows(witness, subfield_boundary, rng));
        tableau.extend(self.layout_quadratic_constraint_rows(witness, lqc, rng));
        tableau
    }

    fn layout_ildt_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let row = (0..self.geometry.block_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        self.rs_block.encode_row()(&row)
    }

    fn layout_idot_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let geom = self.geometry;
        let mut row = (0..geom.dblock_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        let sum_w1 = dot1(&row[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]);
        row[geom.num_queries] -= sum_w1;
        self.rs_dblock.encode_row()(&row)
    }

    fn layout_iquad_row<R: Rng>(&self, rng: &mut R) -> Vec<F> {
        let geom = self.geometry;
        let mut row = (0..geom.dblock_len)
            .map(|_| F::sample(rng))
            .collect::<Vec<F>>();
        for j in 0..geom.witnesses_per_row {
            row[geom.num_queries + j] = F::zero();
        }
        self.rs_dblock.encode_row()(&row)
    }

    fn layout_witness_rows<R: Rng>(
        &self,
        witness: &[F],
        subfield_boundary: usize,
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let geom = self.geometry;
        let nw = witness.len();
        let mut witness_rows = Vec::new();

        for i in 0..geom.num_witness_rows {
            let subfield_only = (i + 1) * geom.witnesses_per_row <= subfield_boundary;
            let mut row_raw = vec![F::zero(); geom.block_len];
            for k in 0..geom.num_queries {
                row_raw[k] = if subfield_only {
                    self.subfield.sample(rng)
                } else {
                    F::sample(rng)
                };
            }
            let start = i * geom.witnesses_per_row;
            if start < nw {
                let max_col = std::cmp::min(geom.witnesses_per_row, nw - start);
                row_raw[geom.num_queries..(geom.num_queries + max_col)]
                    .copy_from_slice(&witness[start..(start + max_col)]);
            }
            witness_rows.push(self.rs_block.encode_row()(&row_raw));
        }

        witness_rows
    }

    fn layout_quadratic_constraint_rows<R: Rng>(
        &self,
        witness: &[F],
        lqc: &[LqcTriple],
        rng: &mut R,
    ) -> Vec<Vec<F>> {
        let geom = self.geometry;
        let nq = lqc.len();

        let mut tableau = Vec::new();
        let mut x_rows = Vec::new();
        let mut y_rows = Vec::new();
        let mut z_rows = Vec::new();
        for i in 0..geom.num_quad_rows {
            let mut row_x = self.sample_random_prefix_row(rng);
            let mut row_y = self.sample_random_prefix_row(rng);
            let mut row_z = self.sample_random_prefix_row(rng);
            let start = i * geom.witnesses_per_row;
            if start < nq {
                let max_j = std::cmp::min(geom.witnesses_per_row, nq - start);
                for j in 0..max_j {
                    let c = lqc[start + j];
                    row_x[geom.num_queries + j] = witness[c.x];
                    row_y[geom.num_queries + j] = witness[c.y];
                    row_z[geom.num_queries + j] = witness[c.z];
                }
            }
            x_rows.push(self.rs_block.encode_row()(&row_x));
            y_rows.push(self.rs_block.encode_row()(&row_y));
            z_rows.push(self.rs_block.encode_row()(&row_z));
        }

        tableau.extend(x_rows);
        tableau.extend(y_rows);
        tableau.extend(z_rows);
        tableau
    }
}
```

## Ligero Prove
This section specifies how a Ligero proof for a given sequence of linear constraints and quadratic constraints on the committed witness vector `W` is constructed. The proof consists of a low-degree test on the tableau, a linearity test, and a quadratic constraint test.


### Low-degree test
In the low-degree test, the verifier sends a challenge vector consisting of `nwqrow = NROW - 3` field elements, `u_ldt[0..nwqrow]`. This challenge is generated via the Fiat-Shamir transform. The prover computes the linear combination:

    y_ldt = T[ILDT][0..BLOCK] + sum_{i = 0 ... nwqrow - 1} u_ldt[i] * T[IW + i][0..BLOCK]

and returns the `BLOCK` elements of `y_ldt`. Notice that the random blinding row `ILDT` (row 0) is included with implicit coefficient 1, while rows 1 (`IDOT`) and 2 (`IQD`) are excluded because their polynomial degree is `DBLOCK` ($2 \cdot \text{BLOCK} - 1$) rather than `BLOCK`. The verifier applies the `extend` method to this response, and verifies consistency with the opened columns of the tableau requested at the challenge indices.

### Linear and Quadratic constraints
The linear test is represented by a matrix `A`, and a vector `b`, and aims to verify that `A * W + b = 0`. The constraint matrix `A` is given as input in a sparse form: it is an array of `LigeroTerm` triples `(c,j,k)` in which `c` indicates the constraint index, `j` represents the witness index, and `k` represents the linear coefficient. For example, if the first constraint (at index 0) is `W[2] + 2*W[3] - 3 = 0`, then the linear constraints array contains the terms `(0,2,1), (0,3,2)` and the `b` vector has `b[0]=-3`.

The quadratic constraints are given as input in an array `lqc[]` that contains triples `(x,y,z)`; one such triple represents the constraint that `W[x] * W[y] = W[z]`. To process quadratic constraints, tableau `T` is augmented with 3 extra rows per triple, called `Qx`, `Qy`, and `Qz` which hold *copied* witnesses and their products. If the `i`-th quadratic constraint is `(x,y,z)`, then the prover sets `Qx[i] = W[x]`, `Qy[i] = W[y]` and `Qz[i] = W[x] * W[y]`. Next, the prover adds a linear constraint that `Qx[i] - W[x] = 0`, `Qy[i] - W[y] = 0` and `Qz[i] - W[z] = 0` to ensure that the copied witness is consistent.

In this sense, the quadratic constraints are reduced to linear constraints, and the additional requirement for the verifier to check that each index of the `Qz` row is the product of its counterpart in the `Qx` and `Qy` row.

The prover computes the quadratic test polynomial `y_quad` across degree `DBLOCK`. The middle `WR` witness values of `y_quad` are identically zero by construction and are omitted from the proof. The proof contains only the non-zero segments: `quad_poly_low` of length `NREQ` (elements `0..NREQ`) and `quad_poly_high` of length `DBLOCK - BLOCK` (elements `BLOCK..DBLOCK`).

### Selection of challenge indicies
The last step of the prove method is for the verifier to select a subset of `NREQ` unique indices (sampled without replacement) from the range `0..(NCOL - DBLOCK)` and request that the prover open these columns of tableau `T` (at column offsets `DBLOCK + idx`). These opened columns, along with their column blinding nonces and Merkle authentication paths, are then used to verify consistency with the polynomial responses sent by the prover.

### Ligero Prover procedure
The `statement_hash` argument is application-dependent and commits to the circuit or statement being proven.

```rust
impl<F: Field + 'static> LigeroProver<F> {
    pub fn prove(
        &self,
        commit: &LigeroCommitResult<F>,
        lqc: &[LqcTriple],
        a: &[LigeroTerm<F>],
        b: &[F],
        statement_hash: &[u8],
        ts: &mut Transcript,
    ) -> LigeroProof<F> {
        ts.write_bytes(statement_hash);

        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let nq = lqc.len();

        let u_ldt = gen_uldt(ts, nwqrow);
        let alphal = gen_alphal(ts, b.len());
        let alphaq = gen_alphaq(ts, nq);
        let u_quad = gen_uquad(ts, geom.num_quad_rows);

        let y_ldt = self.prove_compute_y_ldt(commit, &u_ldt);
        let a_full = self.prove_compute_a_full(lqc, a, &alphal, &alphaq);
        let y_dot = self.prove_compute_y_dot(commit, &a_full);
        let y_quad = self.prove_compute_y_quad(commit, &u_quad);

        let y_quad_0 = y_quad[0..geom.num_queries].to_vec();
        let y_quad_2 = y_quad[geom.block_len..geom.dblock_len].to_vec();

        ts.write_elt_field_slice(&y_ldt);
        ts.write_elt_field_slice(&y_dot);
        ts.write_elt_field_slice(&y_quad_0);
        ts.write_elt_field_slice(&y_quad_2);

        let idx = ts.choose(geom.encoded_len - geom.dblock_len, geom.num_queries);
        let mut query_nonces = Vec::with_capacity(geom.num_queries);
        for &col in &idx {
            query_nonces.push(commit.nonces[col].clone());
        }
        let merkle_paths =
            open_merkle_heap(&commit.merkle, &idx).expect("Failed to open Merkle heap");

        let mut req = Vec::new();
        for row in 0..commit.tableau.len() {
            for &col in &idx {
                let col_idx = col + geom.dblock_len;
                req.push(commit.tableau[row][col_idx]);
            }
        }

        LigeroProof {
            ldt_poly: y_ldt,
            linear_poly: y_dot,
            quad_poly_low: y_quad_0,
            quad_poly_high: y_quad_2,
            column_nonces: query_nonces,
            queried_columns: req,
            merkle_paths,
        }
    }

    fn prove_compute_y_ldt(&self, commit: &LigeroCommitResult<F>, u_ldt: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let mut y_ldt = commit.tableau[geom.ldt_row_idx()][0..geom.block_len].to_vec();
        for i in 0..nwqrow {
            axpy(
                &mut y_ldt,
                &commit.tableau[geom.witness_row_start() + i][0..geom.block_len],
                u_ldt[i],
            );
        }
        y_ldt
    }

    fn prove_compute_a_full(
        &self,
        lqc: &[LqcTriple],
        a: &[LigeroTerm<F>],
        alphal: &[F],
        alphaq: &[Vec<F>],
    ) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let nq = lqc.len();

        let mut a_full = vec![F::zero(); nwqrow * geom.witnesses_per_row];
        for term in a {
            a_full[term.witness_idx] += term.coeff * alphal[term.constraint_idx];
        }

        let nqtriples_w = geom.num_quad_rows * geom.witnesses_per_row;
        let ax_offset = (nwqrow - 3 * geom.num_quad_rows) * geom.witnesses_per_row;
        let ay_offset = ax_offset + nqtriples_w;
        let az_offset = ay_offset + nqtriples_w;

        for i in 0..geom.num_quad_rows {
            let mut j = 0;
            while j < geom.witnesses_per_row && j + i * geom.witnesses_per_row < nq {
                let idx = j + i * geom.witnesses_per_row;
                let l = lqc[idx];
                a_full[ax_offset + idx] += alphaq[idx][0];
                a_full[l.x] -= alphaq[idx][0];
                a_full[ay_offset + idx] += alphaq[idx][1];
                a_full[l.y] -= alphaq[idx][1];
                a_full[az_offset + idx] += alphaq[idx][2];
                a_full[l.z] -= alphaq[idx][2];
                j += 1;
            }
        }
        a_full
    }

    fn prove_compute_y_dot(&self, commit: &LigeroCommitResult<F>, a_full: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let nwqrow = geom.total_rows - 3;
        let mut y_dot = commit.tableau[geom.linear_row_idx()][0..geom.dblock_len].to_vec();
        for i in 0..nwqrow {
            let mut a_ext = vec![F::zero(); geom.block_len];
            let start = i * geom.witnesses_per_row;
            a_ext[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]
                .copy_from_slice(&a_full[start..(start + geom.witnesses_per_row)]);
            let a_evals = self.rs_block.encode_row()(&a_ext);
            vaxpy(
                &mut y_dot,
                &commit.tableau[geom.witness_row_start() + i][0..geom.dblock_len],
                &a_evals[0..geom.dblock_len],
            );
        }
        y_dot
    }

    fn prove_compute_y_quad(&self, commit: &LigeroCommitResult<F>, u_quad: &[F]) -> Vec<F> {
        let geom = self.geometry;
        let mut y_quad = commit.tableau[geom.quad_row_idx()][0..geom.dblock_len].to_vec();
        for i in 0..geom.num_quad_rows {
            let mut tmp = commit.tableau[geom.quad_z_row_start() + i][0..geom.dblock_len].to_vec();
            for j in 0..geom.dblock_len {
                tmp[j] -= commit.tableau[geom.quad_x_row_start() + i][j]
                    * commit.tableau[geom.quad_y_row_start() + i][j];
            }
            axpy(&mut y_quad, &tmp, u_quad[i]);
        }
        y_quad
    }
}
```

## Ligero verification procedure
This section specifies how to verify a Ligero proof with respect to a commitment root, statement hash, linear constraints $A \cdot W + b = 0$, and quadratic constraints $lqc[]$.

The verification procedure checks:
1. **Merkle Proof Consistency (`verify_merkle`)**: Verifies the authentication paths for the opened columns against the committed Merkle root.
2. **Low-Degree Test (`verify_ldt`)**: Verifies that the linear combination of queried column entries equals the Reed-Solomon encoding of `ldt_poly` evaluated at the query column indices.
3. **Linear Constraint Test (`verify_dot`)**: Verifies that the inner product combination matches `linear_poly` evaluations at the query columns, and that $\sum \text{linear\_poly}[j] + \langle b, \alpha_l \rangle = 0$.
4. **Quadratic Constraint Test (`verify_quad`)**: Verifies that $z[i] - x[i] \cdot y[i]$ across the quadratic triple rows matches `y_quad` (reconstructed from `quad_poly_low` and `quad_poly_high`) at the query column indices.

```rust
impl<F: Field + 'static> LigeroVerifier<F> {
    pub fn verify(
        &self,
        nw: usize,
        b: &[F],
        root: &[u8; 32],
        proof: &LigeroProof<F>,
        a: &[LigeroTerm<F>],
        statement_hash: &[u8],
        lqc: &[LqcTriple],
        ts: &mut Transcript,
    ) -> Result<(), VerificationError> {
        ts.write_bytes(statement_hash);

        let geom = LigeroGeometry::new(&self.config, nw, lqc.len());
        let expected_req_len = geom.total_rows * geom.num_queries;
        if proof.queried_columns.len() != expected_req_len {
            return Err(VerificationError::InvalidQueriedColumnsLength {
                expected: expected_req_len,
                actual: proof.queried_columns.len(),
            });
        }
        if proof.ldt_poly.len() != geom.block_len
            || proof.linear_poly.len() != geom.dblock_len
            || proof.quad_poly_low.len() != geom.num_queries
            || proof.quad_poly_high.len() != geom.dblock_len - geom.block_len
            || proof.column_nonces.len() != geom.num_queries
        {
            return Err(VerificationError::InvalidProofPolynomialsLength);
        }
        let nwqrow = geom.total_rows - 3;

        let u_ldt = gen_uldt(ts, nwqrow);
        let alphal = gen_alphal(ts, b.len());
        let alphaq = gen_alphaq(ts, lqc.len());
        let u_quad = gen_uquad(ts, geom.num_quad_rows);

        ts.write_elt_field_slice(&proof.ldt_poly);
        ts.write_elt_field_slice(&proof.linear_poly);
        ts.write_elt_field_slice(&proof.quad_poly_low);
        ts.write_elt_field_slice(&proof.quad_poly_high);

        let idx = ts.choose(geom.encoded_len - geom.dblock_len, geom.num_queries);

        self.verify_merkle(&geom, root, proof, &idx)?;
        self.verify_ldt(&geom, proof, &u_ldt, &idx)?;
        self.verify_dot(&geom, b, proof, a, lqc, &alphal, &alphaq, &idx)?;
        self.verify_quad(&geom, proof, &u_quad, &idx)?;

        Ok(())
    }

    fn verify_merkle(
        &self,
        geom: &LigeroGeometry,
        root: &[u8; 32],
        proof: &LigeroProof<F>,
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let leaf_hash_fn = |col: usize| {
            let mut r_idx = 0;
            for i in 0..idx.len() {
                if idx[i] == col {
                    r_idx = i;
                    break;
                }
            }
            let mut data = Vec::new();
            data.extend_from_slice(&proof.column_nonces[r_idx]);
            for row in 0..geom.total_rows {
                data.extend_from_slice(
                    &proof.queried_columns[row * geom.num_queries + r_idx].to_bytes(),
                );
            }
            sha256_bytes(&data)
        };

        verify_merkle_proof(
            geom.encoded_len - geom.dblock_len,
            root,
            idx,
            &proof.merkle_paths,
            leaf_hash_fn,
        )
        .map_err(|_| VerificationError::MerkleProofInvalid)
    }

    fn verify_ldt(
        &self,
        geom: &LigeroGeometry,
        proof: &LigeroProof<F>,
        u_ldt: &[F],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let nwqrow = geom.total_rows - 3;
        let ildt = geom.ldt_row_idx();
        let iw = geom.witness_row_start();

        let mut yc_ldt =
            proof.queried_columns[ildt * geom.num_queries..(ildt + 1) * geom.num_queries].to_vec();
        for i in 0..nwqrow {
            let row_req = &proof.queried_columns
                [(iw + i) * geom.num_queries..(iw + i + 1) * geom.num_queries];
            axpy(&mut yc_ldt, row_req, u_ldt[i]);
        }
        let yp_ldt = self.interpolate_req_columns(geom, geom.block_len, &proof.ldt_poly, idx);
        if yc_ldt == yp_ldt {
            Ok(())
        } else {
            Err(VerificationError::LowDegreeTestFailed)
        }
    }

    fn verify_dot(
        &self,
        geom: &LigeroGeometry,
        b: &[F],
        proof: &LigeroProof<F>,
        a: &[LigeroTerm<F>],
        lqc: &[LqcTriple],
        alphal: &[F],
        alphaq: &[Vec<F>],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let nwqrow = geom.total_rows - 3;
        let idot = geom.linear_row_idx();
        let iw = geom.witness_row_start();

        let mut a_full = vec![F::zero(); nwqrow * geom.witnesses_per_row];
        for term in a {
            a_full[term.witness_idx] += term.coeff * alphal[term.constraint_idx];
        }
        let nqtriples_w = geom.num_quad_rows * geom.witnesses_per_row;
        let ax_offset = (nwqrow - 3 * geom.num_quad_rows) * geom.witnesses_per_row;
        let ay_offset = ax_offset + nqtriples_w;
        let az_offset = ay_offset + nqtriples_w;

        for i in 0..geom.num_quad_rows {
            let mut j = 0;
            while j < geom.witnesses_per_row && j + i * geom.witnesses_per_row < lqc.len() {
                let idx_lqc = j + i * geom.witnesses_per_row;
                let l = lqc[idx_lqc];
                a_full[ax_offset + idx_lqc] += alphaq[idx_lqc][0];
                a_full[l.x] -= alphaq[idx_lqc][0];
                a_full[ay_offset + idx_lqc] += alphaq[idx_lqc][1];
                a_full[l.y] -= alphaq[idx_lqc][1];
                a_full[az_offset + idx_lqc] += alphaq[idx_lqc][2];
                a_full[l.z] -= alphaq[idx_lqc][2];
                j += 1;
            }
        }

        let mut yc_dot =
            proof.queried_columns[idot * geom.num_queries..(idot + 1) * geom.num_queries].to_vec();
        let a_interp = ReedSolomonCode::new(geom.block_len, geom.encoded_len, &self.subfield);
        for i in 0..nwqrow {
            let mut a_ext = vec![F::zero(); geom.block_len];
            let start = i * geom.witnesses_per_row;
            a_ext[geom.num_queries..geom.block_len]
                .copy_from_slice(&a_full[start..(start + geom.witnesses_per_row)]);
            let a_evals = a_interp.encode_row()(&a_ext);
            let mut a_queried = Vec::with_capacity(geom.num_queries);
            for &col in idx {
                a_queried.push(a_evals[geom.dblock_len + col]);
            }
            let row_req = &proof.queried_columns
                [(iw + i) * geom.num_queries..(iw + i + 1) * geom.num_queries];
            vaxpy(&mut yc_dot, row_req, &a_queried);
        }
        let yp_dot = self.interpolate_req_columns(geom, geom.dblock_len, &proof.linear_poly, idx);
        if yc_dot != yp_dot {
            return Err(VerificationError::LinearConstraintFailed);
        }

        let want_dot = dot(b, alphal);
        let proof_dot =
            dot1(&proof.linear_poly[geom.num_queries..(geom.num_queries + geom.witnesses_per_row)]);
        if proof_dot + want_dot != F::zero() {
            return Err(VerificationError::LinearConstraintSumMismatch);
        }

        Ok(())
    }

    fn verify_quad(
        &self,
        geom: &LigeroGeometry,
        proof: &LigeroProof<F>,
        u_quad: &[F],
        idx: &[usize],
    ) -> Result<(), VerificationError> {
        let iquad = geom.quad_row_idx();
        let iqx = geom.quad_x_row_start();
        let iqy = geom.quad_y_row_start();
        let iqz = geom.quad_z_row_start();

        let mut yc_quad = proof.queried_columns
            [iquad * geom.num_queries..(iquad + 1) * geom.num_queries]
            .to_vec();
        for i in 0..geom.num_quad_rows {
            let u = u_quad[i];
            let mut tmp = vec![F::zero(); geom.num_queries];
            for j in 0..geom.num_queries {
                let x_val = proof.queried_columns[(iqx + i) * geom.num_queries + j];
                let y_val = proof.queried_columns[(iqy + i) * geom.num_queries + j];
                let z_val = proof.queried_columns[(iqz + i) * geom.num_queries + j];
                tmp[j] = z_val - x_val * y_val;
            }
            axpy(&mut yc_quad, &tmp, u);
        }
        let mut y_quad = proof.quad_poly_low.clone();
        y_quad.resize(geom.block_len, F::zero());
        y_quad.extend_from_slice(&proof.quad_poly_high);
        let yp_quad = self.interpolate_req_columns(geom, geom.dblock_len, &y_quad, idx);
        if yc_quad != yp_quad {
            return Err(VerificationError::QuadraticConstraintFailed);
        }

        Ok(())
    }
}
```
