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
  github: "mmaker/stdsigma"
  latest: "https://mmaker.github.io/stdsigma/draft-orru-zkproof-fiat-shamir.html"

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

The Fiat-Shamir transformation relies on a hash function that can absorb inputs incrementally and squeeze variable-length unpredictable messages. On a high level, it consists of three main components:

- A label.
- An underlying hash function H, in a chosen mode, and instantiated over a chosen domain, which the hash state invokes to execute the actions.

The core actions supported are:

- `absorb` indicates a sequence of elements in input to be absorbed by the underlying hash function.
- `squeeze` given input `length`, produces that many elements as output.

The API follows the template of duplex sponges.

# The API

A duplex sponge has the following interface:

  class DuplexSpongeInterface:
      type Unit

      def new(iv: bytes) -> hash_state
      def absorb(self, x: [Unit])
      def squeeze(self, length: int) -> [Unit]
      def finalize(self)

where

- `DuplexSpongeInterface.init(label) -> hash_state`, creates a new `hash_state` object with a description label `label`;
- `DuplexSpongeInterface.absorb(hash_state, values)`, absorbs a list of native elements (that is, of type `Unit`);
- `DuplexSpongeInterface.squeeze(hash_state, length)`, squeezes from the `hash_state` object a list of `Unit` elements.
- `DuplexSpongeInterface.finalize(hash_state)`, deletes the hash object safely.

The above can be extended to support absorption and squeeze from different domains than the domain in which the hash function is initialized over. Such extensions are called codecs.

# Duplex Sponges

A duplex sponge in overwrite mode is based on a permutation function `P` that maps a vector of `r + c` elements of type `Unit` elements.

## Implementation

### Initialization

    new(iv)

    assert len(iv) == 32
    self.absorb_index = 0
    self.squeeze_index = 0
    self.rate = self.state.R
    self.capacity = self.state.N - self.state.R

### Absorb

    absorb(input)

    Inputs:
        self

    Outputs:

    Constants:
        permutation,


    self.squeeze_index = self.rate
    if len(input) == 0:
        return
    if 0 <= self.absorb_index < self.rate:
        self.state[self.absorb_index] = input[0]
        self.absorb_index += 1
        input = input[1:]
        return self.absorb(input)
    if self.absorb_index == self.rate:
        self.state.permute()
        self.absorb_index = 0
        return self.absorb(input)

### Squeeze

    def squeeze(self, length: int):
        self.absorb_index = self.rate

        output = b''
        if length == 0:
            return output

        if 0 <= self.squeeze_index < self.rate:
            output += bytes(self.state[self.squeeze_index:self.squeeze_index+1])
            self.squeeze_index += 1
            length -= 1
            return output + self.squeeze(length)

        if self.squeeze_index == self.rate:
            self.state.permute()
            self.squeeze_index = 0
            return output + self.squeeze(length)

## Ciphersuites

## Keccak f-1600

## SHAKE128 compatibility [WIP]

SHAKE128 is a variable-length hash function based on the Keccak sponge construction [SHA3]. It belongs to the SHA-3 family but offers a flexible output length, and provides 128 bits of security against collision attacks, regardless of the output length requested.

### Initialization

    new(self, label)

    Inputs:

    - label, a byte array

    Outputs:

    -  a hash state interface

    1. h = shake_128(label)
    2. return h

### Absorb

    absorb(hash_state, x)

    Inputs:

    - hash_state, a hash state
    - x, a byte array

    1. h.update(x)

This method is also re-exported as `absorb_bytes`.

### Squeeze

    squeeze(hash_state, length)

    Inputs:

    - hash_state, the hash state
    - length, the number of elements to be squeezed

    1. h.digest(length)

This method is also re-exported as `squeeze_bytes`.

# Codecs registry

## P-384 (secp384r1)

### Absorb scalars

    absorb_scalars(hash_state, scalars)

    Inputs:

    - hash_state, the hash state
    - scalars, a list of elements of P-384's scalar field

    Constants:

    - scalar_byte_length = ceil(384/8)

    1. for scalar in scalars:
    2.     hash_state.absorb_bytes(scalar_to_bytes(scalar))

Where the function `scalar_to_bytes` is defined in {#notation}

### Absorb elements

    absorb_elements(hash_state, elements)

    Inputs:

    - hash_state, the hash state
    - elements, a list of P-384 group elements

    1. for element in elements:
    2.     hash_state.absorb_bytes(ecpoint_to_bytes(element))

### Squeeze scalars

    squeeze_scalars(hash_state, length)

    Inputs:

    - hash_state, the hash state
    - length, an unsiged integer of 64 bits determining the output length.

    1. for i in range(length):
    2.     scalar_bytes = hash_state.squeeze_bytes(field_bytes_length + 16)
    3.     scalars.append(bytes_to_scalar_mod_order(scalar_bytes))

# Notation and Terminology {#notation}

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
