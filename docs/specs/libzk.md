%%%
Title = "Longfellow ZK"
area = "Internet"
workgroup = "Network Working Group"

[seriesInfo]
name = "Internet-Draft"
value = "draft-google-cfrg-libzk-03"
stream = "IETF"
status = "informational"

date = 2026-08-26T00:00:00Z

[[author]]
initials="M."
surname="Frigo"
fullname="Matteo Frigo"
organization = "Google"
[author.address]
  email = "matteof@google.com"

[[author]]
initials="a."
surname="shelat"
fullname="abhi shelat"
organization="Google"
[author.address]
  email = "shelat@google.com"
%%%

.# Abstract

This document defines an algorithm for generating and verifying a succinct non-interactive zero-knowledge argument that for a given input `x` and a circuit `C`, there exists a witness `w`, such that `C(x,w)` evaluates to 0. The technique here combines the MPC-in-the-head approach for constructing ZK arguments described in Ligero [@ligero] with a verifiable computation protocol based on sumcheck for proving that `C(x,w)=0`.

{mainmatter}

# Introduction
A zero-knowledge (ZK) scheme allows a Prover who holds an arithmetic circuit `C` defined over a finite field `F` and two inputs `(x,w)` to convince a Verifier who holds only `(C,x)` that the Prover knows `w` such that `C(x,w) = 0` without revealing any extra information to the Verifier.

The concept of a zero-knowledge scheme was introduced by Goldwasser, Micali, and Rackoff [@GMR], and has since been rigourously explored and optimized in the academic literature.

There are several models and efficiency goals that different ZK schemes aim to achieve, such as reducing prover time, reducing verifier time, or reducing proof size.  Some ZK schemes also impose other requirements to achieve their efficienc goals.  This document considers the scenario in which there are no common reference strings, or trusted parameter setups that are available to the parties.  This immediately rules out several succinct ZK scheme from the literature.  In addition, this document also focuses on schemes that can be instantiated from a collision-resistant hash function and require no other complexity theoretic assumption.  Again, this rules out several schemes in the literature.   All of the ZK schemes from the literature that remain can be defined in the Interactive Oracle Proof (IOP) model, and this document specifies a family of them that enjoys both efficiency and simplicity.

## The Longfellow system
This document specifies the Longfellow ZK scheme described in the paper [@longfellow].  The scheme is constructed from two components: the first is the Ligero scheme, which provides a cryptographic commitment scheme that supports an efficient ZK argument system that enables proving linear and quadratic constraints on the committed witness, and the second is a public-coin interactive protocol (IP) for producing an argument that `C(x,w)=0` where `C` is such a circuit, `x` is a public input, and `w` is a private witness. The overall scheme works by having the Prover commit to the witness `w` as well as a `pad` used to commit the transcript of the IP, then to run the IP with the verifier in a way that produces a commitment to the transcript of the IP, and finally, by running the Ligero proof system to prove that the transcript in the commitment induces the IP verifier to accept.

A companion document specifies how the circuit `C` is specified.
 
<reference anchor='longfellow' target='https://eprint.iacr.org/2024/2010'>
    <front>
        <title>Anonymous credentials from ECDSA</title>
        <author initials='M.' surname='Frigo' fullname='Matteo Frigo'>
        </author>
        <author initials='a.' surname='shelat' fullname='abhi shelat'>
        </author>
        <date year='2024'/>
    </front>
</reference>

# Basic Operations and Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in RFC 6919 [@!RFC6919].

Except if said otherwise, random choices in this specification refer to drawing with uniform distribution from a given set (i.e., "random" is short for "uniformly random").  Random choices can be replaced with fresh outputs from a cryptographically strong pseudorandom generator, according to the requirements in [@!RFC4086], or pseudorandom function.

## Array primitives
The notation `A[0..N]` refers to the array of size `N` that contains `A[0],A[1],...,A[N-1]`, i.e., the right-boundary in the notation `X..Y` is an exclusive index bound.
The following functions are used throughout the document:

* copy(n, Dst, Src): copies n elements from Src to Dst with different strides
* axpy(n, Y, A, X): sets Y[i] += A*X[i] for 0 <= i < n.
* sum(n, A): computes the sum of the first n elements in array A
* dot(n, A, Y): computes the dot product of length n between arrays A and Y.
* add(n, A, Y): returns the array `[A[0]+Y[0], A[1]+Y[1], ..., A[n-1]+Y[n-1]]`.
* prod(n, A, Y): returns the array `[A[0]*Y[0], A[1]*Y[1], ..., A[n-1]*Y[n-1]]`.
* equal(n, A, Y): true if `A[i]==Y[i]` for 0 <= i < n and false otherwise.
* gather(n, A, I): returns the array `[A[I[0]], A[I[1]], ..., A[I[n-1]]`.
* `A[n][m] = [0]`: initializes the 2-dimensional n x m array A to all zeroes.
* `A[0..NREQ] = X` : array assignment, this operation copies the first NREQ elements of X into the corresponding indicies of the A array.


## Polynomial operations
This section describes operations on and associated with polynomials
that are used in the main protocol.


### Extend method in Field F_p 

The `extend(f, n, m)` method interprets the array `f[0..n]` as the evaluations of a polynomial `P` of degree less than `n` at the points `0,...,n-1`, and returns the evaluations of the same `P` at the points `0,...,m-1`.  For sufficiently large fields `|F_p| = p >= m`, polynomial `P` is uniquely determined by the input, and thus `extend` is well defined.

As there are several algorithms for efficiently performing the extend operation, the implementor can choose a suitable one.  In some cases, the brute force method of using Lagrange interpolation formulas to compute each output point independently may suffice.  One can employ a convolution to implement the `extend` operation, and in some cases, either the Number Theoretic Transform or Nussbaumer's algorithm can be used to efficiently compute a convolution.

### Extend method in Field GF 2^k {#gf2k}

The previous section described an extend method that applies to odd prime-order finite fields which contain the elements 0,1,2...,m.  In the special case of GF(2^k), the extend operator is defined in an opinionated way inspired by the Additive FFT algorithm by Lin et al [@additivefft].
Lin et al. define a novel polynomial basis for polynomials as an alternative to the usual monomial
basis x^i^, and give an algorithm for evaluating a degree-(d-1) polynomial at all d points in a subspace, for d=2^\ell^, and for polynomials expressed in the novel basis.

Specifically, this document implements GF(2^128^) as GF{2}[x] / (Q(x)) where 
```
    Q(x) = x^{128} + x^{7} + x^{2} + x + 1
```  
With this choice of Q(x), `x` is a generator of the multiplicative group of the field.
Next, choose GF(2^16^) as the subfield of GF(2^128^) with `g=x^{(2^{128}-1) / (2^{16}-1)}` as its generator, and `beta_i=g^i^` for 0 <= i < 16 as the basis of the subfield.  For relevant problem sizes, this allows encoding elements in a commitment scheme with 16-bits instead of 128.

Writing `j_i` for the `i`-th bit of the binary representation of `j`, that is, 
```
    j = sum_{0 <= i < k} j_i 2^i     j_i \in {0,1}
``` 
inject integer `j` into a field element `inj(j)` by interpreting the bits of `j`  as coordinates in terms of the basis:
```
    inj(j) = sum_{0 <= i < k} j_i beta_i
``` 

In this setting, define the extend operator to interpret the array `f[0..n]` to consist of the evaluations of a polynomial `p(x)` of degree at most `n-1` at the `n` points `x \in { inj(i) : 0 <= i < n }` and to return the set `{ p(inj(i)) : 0 <= i < m}` which consist of the evaluations of the same polynomial `p(x)` at the injected points `0,...,m-1`.

This convention allows this operation to be completed efficiently using various forms of the additive FFT as described in [@longfellow] [@additivefft].

<reference anchor='additivefft' target='https://arxiv.org/abs/1404.3458'>
    <front>
        <title>Novel polynomial basis and its application to Reed-Solomon
erasure codes</title>
        <author initials='S.' surname='Lin' fullname='Sian-Jheng Lin'>
        </author>
        <author initials='W.' surname='Chung' fullname='Wei-Ho Chung'>
        </author>
        <author initials='Y.' surname='Han' fullname='Yunghsiang S. Han'>
        </author>
        <date year='2014'/>
    </front>
</reference>

# Fiat-Shamir primitives {#fiat-shamir}
A ZK protocol may in general instruct the Prover and Verifier to engage in multiple rounds of communication. However, it is often more convenient to deploy a non-interactive or single-message protocol that only requires a single message from Prover to Verifier. It is possible to apply the Fiat-Shamir heuristic to transform an Interactive Oracle Protocol (IOP) into a single-message protocol. In this variant of the protocol, the Verifier does not explicitly send challenges to the Prover; instead, the Verifier computes the challenges by hashing the transcript of the conversation so far.

While the base Fiat-Shamir framework is described in [@I-D.irtf-cfrg-fiat-shamir#03], Interactive Oracle Proofs require more structured multi-round transcripts and multi-challenge extractions (such as combinations without replacement for column queries). The subsections below define a complete, self-contained specification of the *Hash-and-Expand* transcript instantiation and *Universal ZK TLV Codec* aligning with the IOP extensions proposed for the CFRG Fiat-Shamir draft.

{{fs.md}}

{{ligero.md}}

# Overview of the Longfellow protocol {#overview}

The Longfellow ZK protocol uses two protocol components. The first is a variant of the sumcheck protocol, modified to support zero knowledge. Informally, the standard sumcheck prover takes the description of a circuit and the concrete values of all the wires in the circuit, and produces a proof that all wires have been computed correctly.  The proof itself is a sequence of field elements.  Longfellow uses an encrypted-variant of the sumcheck prover that also takes as input a random and secret one-time pad and outputs an "encrypted" proof such that each element in this proof is the difference of the element in the standard sumcheck proof and its corresponding element in the pad.  (The choice of "difference" instead of "sum" is a matter of convention.)

In this encrypted sumcheck variant, the verifier cannot check the proof
directly because it cannot access the one-time pad.  Instead of running the
sumcheck verifier directly, a commitment scheme is used to hide the
one-time pad, and the sumcheck verifier is translated into a sequence of linear and
quadratic constraints on the inputs and the one-time pad.  A secondary proof system
is then used to produce a proof with respect to the commitment that the constraints are satisfied.

The protocol requires both parties to agree on a circuit as part of the theorem statement.  The wire format of a circuit is defined in a separate document.

Some of the wires of the circuit are *inputs*, i.e., set outside the circuit and not computed by the circuit itself.  Some of the inputs are *public*, i.e., known to both parties, and some are *private*, i.e., known only to the prover.  Sumcheck does not use the distinction between public and private inputs. This document distinguishes private inputs from the one-time pad.  The commitment scheme does not use public inputs at all, but it does treat private inputs and the one-time pad elements
equally.  These constraints motivate the following terminology.

* *public inputs*: inputs to the circuit known to both parties.
* *private inputs*: inputs to the circuit known to the prover but not to the verifier.
* *inputs*: both public and private inputs.  When forming an array of all inputs, the public inputs come first, followed
  by the private inputs.
* *witnesses*: the private inputs and the elements in the one-time pad.  When forming an array of all witnesses, the private inputs come first, followed by the one-time pad.

Thus, at a high level, the sequence of operations in the ZK protocol is the following:

1. The prover commits to all witness values.

2. The prover runs the encrypted sumcheck prover on the witness values to producing an encrypted proof, all-the-while sending the encrypted proof to the verifier.

3. Both the prover and the verifier take the public inputs and the
   encrypted proof and produce a sequence of constraints.

4. Using the commitment scheme and the witnesses, the prover generates
   a proof that the constraints from step 3 are satisfied.

5. The verifier uses the proof from step 4 and the constraints from
   step 3 to check the constraints.

Steps 2 and 3 are referred to as "sumcheck", and the rest as "commitment scheme".  While the classification of step 3 as "sumcheck" is  arbitrary, there are situations where one might want to use a commitment scheme other than the Ligero protocol specified in this document.  In this case, the "commitment scheme" can change while the "sumcheck" remains unaffected.

## Parameters needed to define Longfellow
Longfellow is parameterized by a sumcheck protocol, a commitment protocol, and a Fiat-Shamir instantiation.
A selection of all three defines a `Longfellow profile`. This document introduces one opinionated profile that
uses (a) The longfellow sumcheck described below, (b) the Ligero commitment described above, (c) the Fiat-Shamir instantiation defined
above and using SHA-256 as the function `H`.  

In addition to the component profile, the following security parameters described in the [Ligero Zero-Knowledge Proof Section](#ligero-zk-proof) must also be selected:

- `NREQ`: The number of columns of the commitment matrix in the Ligero commitment scheme that the Verifier requests to be revealed by the Prover.
- `rate`: The inverse rate of the error correcting code used by Ligero. 

These two parameters are chosen to balance the size of the proof against the soundness of the protocol.  In principle, these parameters can differ based on the Field size. Based on the latest analysis, we support the following profiles which have been analyzed to provide at least 115 bits of security.

- (p256, 132, 7)
- (GF(2^128^), 132, 7)




{{sumcheck.md}}


# Serializing objects
This section explains how a proof consists of smaller, related objects, and how to serialize each such component.  First, the standard methods for serializing integers and arrays are used:

*  `write_size(n)`: serializes an integer in [0, 2^{24} - 1] that represents the size of an array or an index into an array. The integer is serialized in little endian order.
*  `write_array(arr)`: A variable-sized array is represented as `type array[]` and serialized by first writing its length as a size element, and then serializing each element of the array in order.
*  `write_fixed_array(arr)`: When the length of the array is explicitly known to be `n`, it is specified as `type array[n]` and in this case, the array length is not written first.

## Serializing structs
When a section includes just a struct definition, it is serialized in the natural way, starting from the top-most component and proceeding to the last one, each component is serialized in order.

## Serializing Field elements
This section describes a method to serialize field elements, particularly when the field structure allows efficient encoding for elements of subfields.

Before a field element can be serialized, the context must specify the finite field. In most cases, the Circuit structure will specify the finite field, and all other aspects of the protocol will be defined by this field.

A finite field or `FieldID` is specified using a variable-length encoding. Common finite fields have been assigned special 1-byte codes. An arbitrary prime-order finite field can be specified using the special `0xF_` byte followed by a variable number of bytes to specify the prime in little-endian order. For example, the 3 byte sequence `f11001` specifies F~257~. Similarly, a quadratic extension using the polynomial x^2 + 1 can be specified using the `0xE_` designators.

Finite field                  |  FieldID
------------------------------|-------------:
p256                          |   0x01
p384                          |   0x02
p521                          |   0x03
GF(2^128^)                    |   0x04
GF(2^16^)                     |   0x05
2^128^ - 2^108^ + 1           |   0x06
2^64 - 59                     |   0x07
2^64 - 2^32 + 1               |   0x08
F_{2^64 - 59}^2^              |   0x09
secp256k1                     |   0x0a
F_{2^{0--15}^-byte prime}^2^  |   0xe{0--f}
F_{2^{0--15}^-byte prime}     |   0xf{0--f}
Table: Finite field identifiers.

The GF(2^128^) field uses the irreducible polynomial x^128^ + x^7^ + x^2^ + x + 1.
The p256 prime is equal to 115792089210356248762697446949407573530086143415290314195533631308867097853951, which is the base field used by the NIST P256 elliptic curve.
The p384 prime is equal to 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319 which is the base field used by the NIST P384 curve.  The p512 prime is equal to 2^521^ - 1.  The F_p64^2 field is the quadratic field extension of the base field defined by prime 18446744073709551557 using polynomial x^2 + 1, i.e. by injecting a square root of -1 to the field.


### Serializing a single field element
Unless specified otherwise, a field element, referred to as an `Elt`, is serialized to bytes in little-endian order. For example, a 256-bit element of the finite field F~p256~ is serialized into 32-bytes starting with the least-significant byte.

*  `write_elt(e, F)`: produces a byte encoding of a field element e in field F.

### Serializing an element of a subfield
In some cases, when both Prover and Verifier can explicitly conclude that a field element belongs to a smaller subfield, then both parties can use a more efficient sub-field serialization method.   This optimization can be used when the larger field `F` is a field extension of a smaller field, and both parties can conclude that the serialized element belongs to the smaller subfield.

*  `write_subfield(Elt e, F2, F1)`: produce a byte encoding of a field element e that belongs to a subfield F2 of field F1.


## Serializing a Sumcheck Transcript

```
struct {
	PaddedTranscriptLayer layers[];  // NL layers
} PaddedTranscript;

struct {
	Elt wires[];  // array of 2 * log_w Elts that store the
                // evaluations of deg-2 polynomial at 0, 2
	Elt wc0;
	Elt wc1;
} PaddedTranscriptLayer;
```

The padded transcript incorporates the optimization in which the eval at 1 is omitted and reconstructed from the expected value of the previous challenge.

## Serializing a Ligero Proof

```
def serialize_ligero_proof(C, ldt, dot, columns, mt_proof) {
  write_array(ldt, C.BLOCK)
  write_array(dot, C.BLOCK)
  write_runs(columns, C.NREQ * C.NROW, C.subFieldID, C.FieldID)
  write_merkle(mt_proof)
}
```

The concept of a `run` allows saving space when a long run of field elements belong to a subfield of the Finite field.  Runs consist of a 4-byte size element, and then size Elt elements that are either in the field or the subfield. Runs alternate, beginning with full field elements. In this way, rows that consist of subfield elements can save space.  The maximum run length is set to 2^25^.

```
def write_runs(columns, N, F2, F) {
    bool subfield_run = false
    FOR 0 <= ci < N DO
      size_t runlen = 0
      while (ci + runlen < N &&
             runlen < kMaxRunLen &&
             columns[ci + runlen].is_in_subfield(F2) == subfield_run
             ) {
        ++runlen;
      }
      write_size(runlen, buf);
      for (size_t i = ci; i < ci + runlen; ++i) {
        if (subfield_run) {
          write_subfield(columns[i], F2, F);
        } else {
          write_elt(columns[i], F);
        }
      }
      ci += runlen;
      subfield_run = !subfield_run;
}

def write_merkle(mt_proof) {
  FOR (digest in mt_proof) DO
     write_fixed_array(digest, HASH_LEN)
}
```

## Serializing a Sequence of proofs

For the multi-field optimization, the proof string consists of a sequence of two proofs. This is handled by using the circuit identifier to specify the sequence of proofs to parse.

```
struct {
   Public pub;  // Public arguments to all circuits
   Proof proofs[]; // array of Proof
} Proofs;
```

```
struct {
  uint8 oracle[32]; // nonce used to define the random oracle,
  Digest com;       // commitment to the witness
  PaddedTranscript sumcheck_transcript;
  LigeroProof lp;
} Proof;

struct {
  char* arguments[];   // array of strings representing
                       // public arguments to the circuit
} Public;
```



<reference anchor='GMR' target=''>
    <front>
        <title>THE KNOWLEDGE COMPLEXITY OF INTERACTIVE PROOF SYSTEMS</title>
        <author initials='S.' surname='Goldwasser' fullname='Shafi Goldwasser'>
        </author>
        <author initials='S.' surname='Micali' fullname='Silvio Micali'>
        </author>
        <author initials='C.' surname='Rackoff' fullname='Charles Rackoff'>
        </author>
        <date year='1989'/>
    </front>
</reference>


# Security Considerations

Both the Ligero and Longfellow systems satisfy the standard properties of a zero-knowledge argument system: completeness, soundness, and zero-knowledge.

Frigo and shelat [@longfellow] provide an analysis of the soundness of the system, as it derives from the Soundness of the Ligero proof system and the sumcheck protocol.  Similarly, the zero-knowledge property derives almost entirely from the analysis of Ligero [@ligero].  A mechanically verifiable proof for the soundness
and zero-knowledge properties of the joint scheme is in preparation.



# IANA Considerations

This document does not make any requests of IANA.

{backmatter}

# Acknowledgements

{{testvectors.md}}
