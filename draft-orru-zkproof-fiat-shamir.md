---
title: "Fiat-Shamir Transformation"
category: info

docname: draft-orru-zkproof-fiat-shamir-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
workgroup: Zkproof
keyword:
 - zero knowledge
 - hash
venue:
  group: "Crypto Forum"
  type: ""
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "mmaker/draft-zkproof-sigma-protocols"
  latest: "https://mmaker.github.io/draft-zkproof-sigma-protocols/draft-orru-zkproof-fiat-shamir.html"

author:
-
    fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"

normative:

informative:
  SHA3:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

--- abstract

This document describes the Fiat-Shamir transformation via a duplex sponge interface that is capable of supporting a number of different hash functions, to "absorb" elements from different domains, and produce pseudoranom elements "squeezing" from the hash object.

In addition, the specification provides codes, a way to absorb specific data types.

--- middle

# Introduction

The Fiat-Shamir transformation relies on a hash function that can absorb inputs incrementally and squeeze variable-length unpredictable messages. On a high level, it puts together:

- An IV uniquely describing the protocol.
- A function H, in a chosen mode, and instantiated over a chosen domain, which the hash state invokes to execute the actions.
- An interactive proof that is public-coin.

The core actions supported from the underlying hash function are:

- `absorb` indicates a sequence of elements in input to be absorbed by the underlying hash function.
- `squeeze` given input `length`, produces that many elements as output.

The API follows the template of duplex sponges.

# The Duplex Sponge API

A duplex sponge operates over an abstract `Unit` type and provides the following interface:

      def new(iv: bytes) -> hash_state
      def absorb(hash_state, x: list[Unit])
      def squeeze(hash_state, length: int) -> list[Unit]

In the remainder of this spec, we assume that `Unit=u8`.
(The type `Unit` MUST have fixed size in memory, partial ordering, and at least two elements.)
The API functions are described as follows:

- `init(iv)`, creates a new `hash_state` object with a 32-byte initialization vector `iv`;
- `absorb(hash_state, values)`, absorbs a list of native elements (that is, of type `Unit`);
- `squeeze(hash_state, length)`, squeezes from the `hash_state` object a list of `Unit` elements.

The above can be extended to support absorption and squeeze from different domains than the domain in which the hash function is initialized over. Such extensions are called codecs.

# Fiat-Shamir transformation for Sigma Protocols

We describe how to construct non-interactive proofs for sigma protocols.
It is parametrized by:

- a `Codec`, which specifies how to encode prover messages for the hash function, and how to extract verifier challenges in the right domain;
- a `SigmaProtocol`, which specifies an interactive 3-message protocol.

Upon initialization, the protocol receives as input an `iv` of 32-bytes which uniquely describes the protocol and the session being proven and (optionally) pre-processes some information about the protocol using the instance.

    class NISigmaProtocol:
        Protocol: SigmaProtocol
        Codec: Codec

        def init(self, iv: [], instance):
            self.hash_state = self.Codec(iv)
            self.ip = self.Protocol(instance)

        def prove(self, witness, rng):
            (prover_state, commitment) = self.ip.prover_commit(witness, rng)
            challenge = self.hash_state.prover_message(commitment).verifier_challenge()
            response = self.ip.prover_response(prover_state, challenge)

            assert self.ip.verifier(commitment, challenge, response)
            return self.ip.serialize_commitment(commitment) + self.ip.serialize_response(response)

        def verify(self, proof):
            commitment_bytes = proof[:self.ip.instance.commit_bytes_len]
            response_bytes = proof[self.ip.instance.commit_bytes_len:]
            commitment = self.ip.deserialize_commitment(commitment_bytes)
            response = self.ip.deserialize_response(response_bytes)
            challenge = self.hash_state.prover_message(commitment).verifier_challenge()
            return self.ip.verifier(commitment, challenge, response)

## Codec for Linear maps {#group-prove}

We describe a codec for Schnorr proofs over groups of prime order `p` that is intended for byte-oriented hash functions.

    class LinearMapCodec:
        Group: groups.Group = None
        DuplexSponge: DuplexSpongeInterface = None

        def __init__(self, iv: bytes):
            self.hash_state = self.DuplexSponge(iv)

        def prover_message(self, elements: list):
            self.hash_state.absorb(self.Group.serialize(elements))
            # calls can be chained
            return self

        def verifier_challenge(self):
            uniform_bytes = self.hash_state.squeeze(
                self.Group.ScalarField.scalar_byte_length() + 16
            )
            scalar = OS2IP(uniform_bytes) % self.Group.ScalarField.order
            return scalar

# Ciphersuites

## SHAKE128

SHAKE128 is a variable-length hash function based on the Keccak sponge construction {{SHA3}}. It belongs to the SHA-3 family but offers a flexible output length, and provides 128 bits of security against collision attacks, regardless of the output length requested.

### Initialization

    new(self, iv)

    Inputs:

    - iv, a byte array

    Outputs:

    -  a hash state interface

    1. h = shake_128(iv)
    2. return h

### SHAKE128 Absorb

    absorb(hash_state, x)

    Inputs:

    - hash_state, a hash state
    - x, a byte array

    1. h.update(x)

### SHAKE128 Squeeze

    squeeze(hash_state, length)

    Inputs:

    - hash_state, the hash state
    - length, the number of elements to be squeezed

    1. h.copy().digest(length)


## Duplex Sponge

A duplex sponge in overwrite mode is based on a permutation function that operates on a state vector. It implements the `DuplexSpongeInterface` and maintains internal state to support incremental absorption and variable-length output generation.


### Initialization

This is the constructor for a duplex sponge object. It is initialized with a 32-byte initialization vector.

    new(iv)

    Inputs:
    - iv, a 32-byte initialization vector

    Procedure:
    1. self.absorb_index = 0
    2. self.squeeze_index = self.permutation_state.R
    3. self.rate = self.permutation_state.R
    4. self.capacity = self.permutation_state.N - self.permutation_state.R

### Absorb

The absorb function incorporates data into the duplex sponge state using overwrite mode.

    absorb(self, input)

    Inputs:
    - self, the current duplex sponge object
    - input, the input bytes to be absorbed

    Procedure:
    1. self.squeeze_index = self.rate
    2. while len(input) != 0:
    3.     if self.absorb_index == self.rate:
    4.         self.permutation_state.permute()
    5.         self.absorb_index = 0
    6.     chunk_size = min(self.rate - self.absorb_index, len(input))
    7.     next_chunk = input[:chunk_size]
    8.     self.permutation_state[self.absorb_index:self.absorb_index + chunk_size] = next_chunk
    9.     self.absorb_index += chunk_size
    10.    input = input[chunk_size:]

### Squeeze

The squeeze operation extracts output elements from the sponge state, which are uniformly distributed and can be used as a digest, key stream, or other cryptographic material.

    squeeze(self, length)

    Inputs:
    - self, the current duplex sponge object
    - length, the number of bytes to be squeezed out of the sponge

    Outputs:
    - digest, a byte array of `length` elements uniformly distributed

    Procedure:
    1. output = b''
    2. while length != 0:
    3.     if self.squeeze_index == self.rate:
    4.         self.permutation_state.permute()
    5.         self.squeeze_index = 0
    6.         self.absorb_index = 0
    7.     chunk_size = min(self.rate - self.squeeze_index, length)
    8.     output += bytes(self.permutation_state[self.squeeze_index:self.squeeze_index+chunk_size])
    9.     self.squeeze_index += chunk_size
    10.    length -= chunk_size
    11. return output

### Keccak-f[1600] Implementation

`Keccak-f` is the permutation function underlying {{SHA3}}.

`KeccakDuplexSponge` instantiated `DuplexSponge` with `Keccak-f[1600]`, using rate `R = 136` bytes and capacity `C = 64` bytes.

# Codecs registry

## Elliptic curves

### Notation and Terminology {#notation}

For an elliptic curve, we consider two fields, the coordinate fields, which indicates the base field, the field over which the elliptic curve equation is defined, and the scalar field, over which the scalar operations are performed.

The following functions and notation are used throughout the document.

- `concat(x0, ..., xN)`: Concatenation of byte strings.
- `bytes_to_int` and `scalar_to_bytes`: Convert a byte string to and from a non-negative integer.
  `bytes_to_int` and `scalar_to_bytes` are implemented as `OS2IP` and `I2OSP` as described in
  {{!RFC8017}}, respectively. Note that these functions operate on byte strings
  in big-endian byte order. These functions MUST raise an exception if the integer over which they
  We consider the function `bytes_to_in`
- The function `ecpoint_to_bytes` converts an elliptic curve point in affine-form into an array string of length `ceil(ceil(log2(coordinate_field_order))/ 8) + 1` using `int_to_bytes` prepended by one byte. This is defined as

    ecpoint_to_bytes(element)

    Inputs:

    - `element`, an elliptic curve element in affine form, with attributes `x` and `y` corresponding to its affine coordinates, represented as integers modulo the coordinate field order.

    Outputs:

    A byte array

    Constants:

    field_bytes_length, the number of bytes to represent the scalar element, equal to `ceil(log2(field.order()))`.

    1. byte = 2 if sgn0(element.y) == 0 else 3
    2. return I2OSP(byte, 1) + I2OSP(x, field_bytes_length)

### Absorb scalars

    absorb_scalars(hash_state, scalars)

    Inputs:

    - hash_state, the hash state
    - scalars, a list of elements of the elliptic curve's scalar field

    Constants:

    - scalar_byte_length = ceil(384/8)

    1. for scalar in scalars:
    2.     hash_state.absorb(scalar_to_bytes(scalar))

Where the function `scalar_to_bytes` is defined in {#notation}

### Absorb elements

    absorb_elements(hash_state, elements)

    Inputs:

    - hash_state, the hash state
    - elements, a list of group elements

    1. for element in elements:
    2.     hash_state.absorb(ecpoint_to_bytes(element))

### Squeeze scalars

    squeeze_scalars(hash_state, length)

    Inputs:

    - hash_state, the hash state
    - length, an unsiged integer of 64 bits determining the output length.

    1. for i in range(length):
    2.     scalar_bytes = hash_state.squeeze(field_bytes_length + 16)
    3.     scalars.append(bytes_to_scalar_mod_order(scalar_bytes))
