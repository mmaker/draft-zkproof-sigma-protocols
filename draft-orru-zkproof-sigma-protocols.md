---
title: "Sigma Protocols"
category: info

docname: draft-orru-zkproof-sigma-protocols-latest
submissiontype: independent
number:
date:
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - zero-knowledge
venue:
#  group: WG
#  type: Working Group
#  mail: WG@examplecom
#  arch: https://examplecom/WG
  github: "mmaker/draft-zkproof-sigma-protocols"
  latest: "https://mmaker.github.io/draft-zkproof-sigma-protocols/draft-orru-zkproof-sigma-protocols.html"

author:
 -
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"
 -
    fullname: "Cathie Yun"
    organization: Apple, Inc.
    email: cathieyun@gmail.com

normative:

informative:
  fiat-shamir:
    title: "draft-orru-zkproofs-fiat-shamir"
    date: false
    target: https://mmaker.github.io/spfs/draft-orru-zkproof-fiat-shamir.html
  NISTCurves: DOI.10.6028/NIST.FIPS.186-4
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  GiacomelliMO16:
    title: "ZKBoo: Faster Zero-Knowledge for Boolean Circuits"
    target: https://eprint.iacr.org/2016/163.pdf
    date: false
    author:
    -
      fullname: "Irene Giacomelli"
    -
      fullname: "Jesper Madsen"
    -
      fullname: "Claudio Orlandi"
  AttemaCK21:
    title: "A Compressed Sigma-Protocol Theory for Lattices"
    target: https://dl.acm.org/doi/10.1007/978-3-030-84245-1_19
    date: false
    author:
    -
      fullname: Thomas Attema
    -
      fullname: Ronald Cramer
    -
      fullname: Lisa Kohl
  BonehS23:
      title: "A Graduate Course in Applied Cryptography"
      target: https://toc.cryptobook.us/
      author:
      -
        fullname: Dan Boneh
      -
        fullname: Victor Schoup

--- abstract

This document describes Sigma protocols, a secure, general-purpose non-interactive zero-knowledge proof of knowledge. Concretely, the scheme allows proving knowledge of a witness, without revealing any information about the undisclosed messages or the signature itself, while at the same time, guarantying soundness of the overall protocols.

--- middle

# Introduction

A Sigma Protocol is a simple zero-knowledge proof of knowledge.
Any sigma protocol must define three objects:

- A commitment, sometimes also called a nonce. This message is computed by the prover.
- A challenge, computed using the Fiat-Shamir transformation using a hash function.
- A response, computed by the prover, which depends on the commitment and the challenge.

A sigma protocol allows a **prover** to convince a **verifier** of the knowledge of a secret **witness** satisfying a **statement**.

# Public functions interface

A non-interactive sigma protocol provides a `prove` and a `verify` public functions. It is parametrized by:

- a `Codec`, which specifies how to encode prover messages for the hash function, and how to extract verifier challenges in the right domain;
- a `SigmaProtocol`, which specifies an interactive 3-message protocol.

For how to implement these function in prime-order groups and elliptic curves, see {{group-prove}}.
Upon initialization, the protocol receives as input an `iv` of 32-bytes which uniquely describes the protocol and the session being proven and (optionally) pre-processes some information about the protocol using the instance. Guidelines on the generation of this value are given in {{iv-generation}}.

    class NISigmaProtocol:
        Protocol: SigmaProtocol
        Codec: Codec

        def __init__(self, iv: [], instance):
            self.hash_state = self.Codec(iv)
            self.sp = self.Protocol(instance)

        def prove(self, witness, rng):
            (prover_state, commitment) = self.sp.prover_commit(witness, rng)
            challenge = self.hash_state.prover_message(commitment).verifier_challenge()
            response = self.sp.prover_response(prover_state, challenge)

            assert self.sp.verifier(commitment, challenge, response)
            return self.sp.serialize_batchable(commitment, challenge, response)

        def verify(self, proof):
            commitment, response = self.sp.deserialize_batchable(proof)
            challenge = self.hash_state.prover_message(commitment).verifier_challenge()
            return self.sp.verifier(commitment, challenge, response)

## Core interface

The public functions are obtained relying on an internal structure containing the definition of a sigma protocol.

    class SigmaProtocol:
       def new(instance: Statement) -> SigmaProtocol
       def prover_commit(self, witness: Witness) -> (commitment, prover_state)
       def prover_response(self, prover_state, challenge) -> response
       def verifier(self, commitment, challenge, response) -> bool
       # optional
       def simulate_response(self, rng) -> response
       # optional
       def simulate_commitment(self, response, challenge) -> commitment

Where:

- `new(domain_separator: [u8; 32], cs: GroupMorphismPreimage) -> SigmaProtocol`, denoting the initialization function. This function takes as input a label identifying local context information (such as: session identifiers, to avoid replay attacks; protocol metadata, to avoid hijacking; optionally, a timestamp and some pre-shared randomness, to guarantee freshness of the proof) and an instance generated via the `GroupMorphismPreimage`, the public information shared between prover and verifier.
This function should pre-compute parts of the statement, or initialize the state of the hash function.

- `prover_commit(self, witness: Witness) -> (commitment, prover_state)`, denoting the **commitment phase**, that is, the computation of the first message sent by the prover in a Sigma protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover and the statement to be proven. This step generally requires access to a high-quality entropy source to perform the commitment. Leakage of even just of a few bits of the commitment could allow for the complete recovery of the witness. The commitment is meant to be shared, while `prover_state` must be kept secret.

- `prover_response(self, prover_state, challenge) -> response`, denoting the **response phase**, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state `prover_state`. The returned value `response` is meant to be shared.

- `verifier(self, commitment, challenge, response) -> bool`, denoting the **verifier algorithm**. This method checks that the protocol transcript is valid for the given statement. The verifier algorithm outputs true if verification succeeds, or false if verification fails.

The final two algorithms describe the **zero-knowledge simulator** and are optional, as a sigma protocol is not necessarily zero-knowledge by definition. The simulator is primarily an efficient algorithm for proving zero-knowledge in a theoretical construction, but it is also needed for verifying short proofs and for or-composition, where a witness is not known and thus has to be simulated. We have:

- `simulate_response(self, rng) -> response`, denoting the first stage of the simulator. It is an algorithm drawing a random response given a specified cryptographically secure RNG that follows the same output distribution of the algorithm  `prover_response`.

- `simulate_commitment(self, response, challenge) -> commitment`, returning a simulated commitment -- the second phase of the zero-knowledge simulator.

Together, these zero-knowledge simulators provide a transcript that should be computationally indistinguishable from the transcript generated by running the original sigma protocol.

The abstraction `SigmaProtocol` allows implementing different types of statements and combiners of those, such as OR statements, validity of t-out-of-n statements, and more.

# Sigma protocols over prime-order groups {#sigma-protocol-group}

The following sub-section present concrete instantiations of sigma protocols over prime-order elliptic curve groups.
It relies on two components:
- a prime-order elliptic-curve group as described in {{group-abstraction}},
- a hash function.

Valid choices of elliptic curves and hash functions can be found in {{ciphersuites}}.

Traditionally, sigma protocols are defined in Camenish-Stadtler notation as (for example):

    1. DLEQ(G, H, X, Y) = PoK{
    2.   (x):        // Secret variables
    3.   X = x * G, Y = x * H
    4. }

In the above, line 1 declares that the proof name is "DLEQ", the public information (the **instance**) consists of the group elements `(G, X, H, Y)` denoted in upper-case.
Line 2 states that the private information (the **witness**) consists of the scalar `x`.
Finally, line 3 states that the constraints (the equations) that need to be proven are
`x * G  = X` and `x * H = Y`.

## Group abstraction {#group-abstraction}

Because of their dominance, the presentation in the following focuses on proof goals over elliptic curves, therefore leveraging additive notation. For prime-order subgroups of residue classes, all notation needs to be changed to multiplicative, and references to elliptic curves (e.g., curve) need to be replaced by their respective counterparts over residue classes.

We detail the functions that can be invoked on these objects. Example choices can be found in {{ciphersuites}}.

### Group {#group}

- `identity()`, returns the neutral element in the group.
- `generator()`, returns the generator of the prime-order elliptic-curve subgroup used for cryptographic operations.
- `order()`: Outputs the order of the group `p`.
- `random()`: outputs a random element in the group.
- `serialize(elements: [Group; N])`, serializes a list of group elements and returns a canonical byte array `buf` of fixed length `Ne * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ne * N` into `[Group; N]`, and fails if the input is not the valid canonical byte representation of an element of the group. This function can raise a `DeserializeError` if deserialization fails.
- `add(element: Group)`, implements elliptic curve addition for the two group elements.
- `equal(element: Group)`, returns `true` if the two elements are the same and false` otherwise.
- `scalar_mul(scalar: Scalar)`, implements scalar multiplication for a group element by an element in its respective scalar field.

Functions such as `add`, `equal`, and `scalar_mul` SHOULD be implemented using operator overloading whenever possible.

### Scalar

- `identity()`: outputs the (additive) identity element in the scalar field.
- `add(scalar: Scalar)`: implements field addition for the elements in the field.
- `mult(scalar: Scalar)`, implements field multiplication.
- `random()`: outputs a random scalar field element.
- `serialize(scalars: list[Scalar; N])`: serializes a list of scalars and returns their canonical representation of fixed length `Ns * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ns * N` into `[Scalar; N]`, and fails if the input is not the valid canonical byte representation of an element of the group. This function can raise a `DeserializeError` if deserialization fails.

Functions such as `add`, `equal`, and `scalar_mul` SHOULD be implemented using operator overloading whenever possible.

## Codec for non-interactive proofs {#group-prove}

We describe a codec for Schnorr proofs over groups of prime order `p` that is intended for byte-oriented hash functions. Informally, the prover messages are serialized by concatenating the point compresion functions, and the verifier challenge is generated by squeezing out `log2(p) + 16` element and reducing the result modulo `p`

    class ByteSchnorrCodec:
        Group: groups.Group = None
        Hash: DuplexSpongeInterface = None

        def __init__(self, iv: bytes):
            self.hash_state = self.Hash(iv)

        def prover_message(self, elements: list):
            self.hash_state.absorb(self.Group.serialize(elements))
            # calls can be chained
            return self

        def verifier_challenge(self):
            from hash_to_field import OS2IP

            uniform_bytes = self.hash_state.squeeze(
                self.Group.ScalarField.scalar_byte_length() + 16
            )
            scalar = OS2IP(uniform_bytes) % self.Group.ScalarField.order
            return scalar

## Proofs of preimage of a group morphism

### Core protocol

This defines the object `SchnorrProof`. The initialization function takes as input the statement, and pre-processes it.

### Prover procedures

The prover of a sigma protocol is stateful and will send two message, a "commitment" and a "response" message, described below.

#### Prover commitment

    prover_commit(self, witness)

    Inputs:

    - witness, an array of scalars

    Outputs:

    - A (private) prover state, holding the information of the interactive prover necessary for producing the protocol response
    - A (public) commitment message, an element of the morphism image, that is, a vector of group elements.

    Procedure:

    1. nonces = [self.instance.Domain.random(rng) for _ in range(self.instance.morphism.num_scalars)]
    2. prover_state = self.ProverState(witness, nonces)
    3. commitment = self.instance.morphism(nonces)
    4. return (prover_state, commitment)

#### Prover response

    prover_response(self, prover_state, challenge)

    Inputs:

        - prover_state, the current state of the prover
        - challenge, the verifier challenge scalar

    Outputs:

        - An array of scalar elements composing the response

    Procedure:

    1. witness, nonces = prover_state
    2. return [nonces[i] + witness[i] * challenge for i in range(self.instance.morphism.num_scalars)]

### Verifier procedure

    verify(self, commitment, challenge, response)

    Inputs:

    - self, the current state of the SigmaProtocol
    - commitment, the commitment generated by the prover
    - challenge, the challenge generated by the verifier
    - response, the response generated by the prover

    Outputs:

    - A boolean indicating whether the verification succeeded

    Procedure:

    1. assert len(commitment) == self.instance.morphism.num_statements and len(response) == self.instance.morphism.num_scalars
    2. expected = self.instance.morphism(response)
    3. got = [commitment[i] + self.instance.image[i] * challenge for i in range(self.instance.morphism.num_statements)]
    4. return got == expected

### Witness representation {#witness}

A witness is simply a list of `num_scalars` elements.

    Witness = [Scalar; num_scalars]

### Group morphism {#morphism}

A `GroupMorphism` represents a function (a _group morphism_ from the scalar field to the elliptic curve group) that, given as input an array of `Scalar` elements, outputs an array of `Group` element. This can be represented as matrix-vector (scalar) product using group multi-scalar multiplication. However, since the matrix is often times sparse, it is often more convenient to store the matrix in Yale sparse matrix.

Here is an example:

    class LinearCombination:
        scalar_indices: list[int]
        element_indices: list[int]

The morphism can then be presented as:

    class GroupMorphism:
        Group: groups.Group
        linear_combinations: list[LinearCombination]
        group_elements: list[Group]
        num_scalars: int
        num_elements: int

        def map(self, scalars: list[Group.ScalarField]) -> Group

#### Initialization

The group morphism `GroupMorphism` is initialized with

    linear_combinations = []
    group_elements = []
    num_scalars = 0
    num_elements = 0

#### Morphism map

A witness can be mapped to a group element via:

    map(self, witness: [Scalar; num_scalars])

    Inputs:

    - self, the current sate of the constraint system
    - witness,

    1. image = []
    2. for linear_combination in self.linear_combinations:
    3.     coefficients = [scalars[i] for i in linear_combination.scalar_indices]
    4.     elements = [self.group_elements[i] for i in linear_combination.element_indices]
    5.     image.append(self.Group.msm(coefficients, elements))
    6. return image

### Statements for the preimage of a group morphism

The object `GroupMorphismPreimage` has two attributes: a morphism `morphism`, which will be defined in {{morphism}}, and `image`, the morphism image of which the prover wants to show the pre-image of.

class GroupMorphismPreimage:
        Domain = group.ScalarField
        Image = group.Group

        morphism = Morphism
        image = list[group.Group]

    def allocate_scalars(self, n: int) -> list[int]
    def allocate_elements(self, n: int) -> list[int]
    def append_equation(self, lhs: int, rhs: list[(int, int)]) -> None
    def set_elements(self, elements: list[(int, Group)]) -> None

#### Element and scalar variables allocation

Two function allow two allocate the new scalars (the witness) and group elements (the instance).

    allocate_scalars(self, n)

    Inputs:
        - self, the current state of the GroupMorphismPreimage
        - n, the number of scalars to allocate
    Outputs:
        - indices, a list of integers each pointing to the new allocated scalars

    Procedure:

    1. indices = range(self.num_scalars, self.num_scalars + n)
    2. self.num_scalars += n
    3. return indices

and below the allocation of group elements

    allocate_elements(self, n)

    1. linear_combination = Morphism.LinearCombination(scalar_indices=[x[0] for x in rhs], element_indices=[x[1] for x in rhs])
    2. self.morphism.append(linear_combination)
    3. self._image.append(lhs)

Group elements, being part of the instance, can later be set using the function `set_elements`

    set_elements(self, elements)

    Inputs:
        - self, the current state of the GroupMorphismPreimage
        - elements, a list of pairs of indices and group elements to be set

    Procedure:

    1. for index, element in elements:
    2.   self.morphism.group_elements[index] = element

#### Constraint enforcing

    append_equation(self, lhs, rhs)

    Inputs:

    - self, the current state of the constraint system
    - lhs, the left-hand side of the equation
    - rhs, the right-hand side of the equation (a list of (ScalarIndex, GroupEltIndex) pairs)

    Outputs:

    - An Equation instance that enforces the desired relation

    Procedure:

    1. linear_combination = Morphism.LinearCombination(scalar_indices=[x[0] for x in rhs], element_indices=[x[1] for x in rhs])
    2. self.morphism.append(linear_combination)
    3. self._image.append(lhs)

### Example: Schnorr proofs

The statement represented in {{sigma-protocol-group}} can be written as:

    statement = GroupMorphismPreimage(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])

At which point it is possible to set `var_G` and `var_X` whenever the group elements are at disposal.

    G = group.generator()
    statement.set_elements([(var_G, G), (var_X, X)])

It is worth noting that in the above example, `[X] == statement.morphism.map([x])`.

### Example: DLEQ proofs

A DLEQ proof proves a statement:

        DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

Given group elements `G`, `H` and `X`, `Y` such that `x * G = X` and `x * H = Y`, then the statement is generated as:

    1. statement = GroupMorphismPreimage()
    2. [var_x] = statement.allocate_scalars(1)
    3. statement.append_equation(X, [(var_x, G)])
    4. statement.append_equation(Y, [(var_x, H)])

### Example: Pedersen commitments

A representation proof proves a statement

        REPR(G, H, C) = PoK{(x, r): C = x * G + r * H}

Given group elements `G`, `H` such that `C = x * G + r * H`, then the statement is generated as:

    statement = GroupMorphismPreimage()
    var_x, var_r = statement.allocate_scalars(2)
    statement.append_equation(C, [(var_x, G), (var_r, H)])


### Serializing the statement for the Fiat-Shamir transformation

Let `H` be a hash object. The statement is encoded in a stateful hash object as follows.

    hasher = H.new(domain_separator)
    hasher.update_usize([cs.num_statements, cs.num_scalars])
    for equation in cs.equations:
      hasher.update_usize([equation.lhs, equation.rhs[0], equation.rhs[1]])
    hasher.update(generators)
    iv = hasher.digest()

In simpler terms, without stateful hash objects, this should correspond to the following:

    bin_challenge = SHAKE128(iv).update(commitment).digest(scalar_bytes)
    challenge = int(bin_challenge) % p

and the nonce is produced as:

    bin_nonce = SHAKE128(iv)
                .update(random)
                .update(pad)
                .update(cs.scalars)
                .digest(cs.num_scalars * scalar_bytes)
    nonces = [int(bin_nonce[i*scalar_bytes: i*(scalar_bytes+1)]) % p
              for i in range(cs.num_scalars-1)]

Where:
    - `pad` is a (padding) zero string of length `168 - len(random)`.
    - `scalar_bytes` is the number of bytes required to produce a uniformly random group element
    - `random` is a random seed obtained from the operating system memory

## Ciphersuites {#ciphersuites}

### P-256 (secp256r1)

This ciphersuite uses P-256 {{NISTCurves}} for the Group.

#### Elliptic curve group of P-256 (secp384r1) {{NISTCurves}}

- `order()`: Return the integer `115792089237316195423570985008687907852837564279074904382605163141518161494337`.
- `serialize([A])`: Implemented using the compressed Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}; `Ne = 33`.
- `deserialize(buf)`: Implemented by attempting to read `buf` into chunks of 32-byte arrays and convert them using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then performs partial public-key validation as defined in section 5.6.2.3.4 of {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the coordinates of the resulting point are in the correct range, that the point is on the curve, and that the point is not the point at infinity.

#### Scalar Field of P-256

- `serialize(s)`: Relies on the Field-Element-to-Octet-String conversion according to {{SEC1}}; `Ns = 32`.
- `deserialize(buf)`: Reads the byte array `buf` in chunks of 32 bytes using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the input does not represent a Scalar in the range `[0, G.Order() - 1]`.

# Security Considerations

Sigma protocols provide the following guarantees in the random oracle model:

- **Knowledge soundness**: If the proof is valid, the prover must have knowledge of a secret witness satisfying the proof statement. This property ensures that valid proofs cannot be generated without possession of the corresponding witness.

- **Zero-knowledge**: The proof string produced by the `prove` function does not reveal any information beyond what can be directly inferred from the statement itself. This ensures that verifiers gain no knowledge about the witness.

While theoretical analysis demonstrates that both soundness and zero-knowledge properties are statistical in nature, practical security depends on the cryptographic strength of the underlying hash function. It's important to note that the soundness of a zero-knowledge proof provides no guarantees regarding the computational hardness of the relation being proven. An assessment of the specific hardness properties for relations proven using these protocols falls outside the scope of this document.

# Post-Quantum Security Considerations

The zero-knowledge proofs described in this document provide statistical zero-knowledge and statistical soundness properties when modeled in the random oracle model.

### Privacy Considerations

These proofs offer zero-knowledge guarantees, meaning they do not leak any information about the prover's witness beyond what can be inferred from the proven statement itself. This property holds even against quantum adversaries with unbounded computational power.

Specifically, these proofs can be used to protect privacy against post-quantum adversaries, in applications demanding:

- Post-quantum anonymity
- Post-quantum unlinkability
- Post-quantum blindness
- Protection against "harvest now, decrypt later" attacks.

### Soundness Considerations

While the proofs themselves offer privacy protections against quantum adversaries, the hardness of the relation being proven depends (at best) on the hardness of the discrete logarithm problem over the elliptic curves specified in {{ciphersuites}}.
Since this problem is known to be efficiently solvable by quantum computers using Shor's algorithm, these proofs MUST NOT be relied upon for post-quantum soundness guarantees.

Implementations requiring post-quantum soundness SHOULD transition to alternative proof systems such as:

- MPC-in-the-Head approaches as described in {{GiacomelliMO16}}
- Lattice-based approaches as described in {{AttemaCK21}}

Implementations should consider the timeline for quantum computing advances when planning migration to post-quantum sound alternatives.
Implementers MAY adopt a hybrid approach during migration to post-quantum security by using AND composition of proofs. This approach enables gradual migration while maintaining security against classical adversaries.
This composition retains soundness if **both** problem remains hard. AND composition of proofs is NOT described in this specification, but examples may be found in the proof-of-concept implementation and in {{BonehS23}}.

# Generation of the initialization vector {#iv-generation}

As of now, it is responsibility of the user to pick a unique initialization vector that identifies the proof system and the session being used. This will be expanded in future versions of this specification.

# Acknowledgments
{:numbered ="false"}

The authors thank Jan Bobolz, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang for reviewing a previous edition of this specification.
