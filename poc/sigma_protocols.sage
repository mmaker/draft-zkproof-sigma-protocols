from abc import ABC, abstractmethod
from collections import namedtuple

from sagelib import groups
from sagelib.fiat_shamir import DuplexSpongeInterface, KeccakDuplexSponge

### The abstract APIs for Sigma protocols

class SigmaProtocol(ABC):
    """
    This is the abstract API of a Sigma protocol.

    An (interactive) Sigma protocol is a 3-message protocol that is special sound and honest-verifier zero-knowledge.
    Relations for sigma protocols are seen as ternary relations composed of:
    - instance: the public part of the statement that can be pre-processed offline
    - witness: the secret witness for the relation.
    """
    @abstractmethod
    def __init__(self, index):
        raise NotImplementedError

    @abstractmethod
    def prover_commit(self, rng, witness):
        raise NotImplementedError

    @abstractmethod
    def prover_response(self, prover_state, challenge):
        raise NotImplementedError

    @abstractmethod
    def verifier(self, commitment, challenge, response):
        raise NotImplementedError

    # optional
    def simulate_response(self):
        raise NotImplementedError

    # optional
    def simulate_commitment(self, response, challenge):
        raise NotImplementedError


class Codec(ABC):
    """
    This is the abstract API of a codec.

    A codec is a collection of:
    - functions that map prover messages into the hash function domain,
    - functions that map hash outputs into verifier messages (of the desired distribution).
    """

    @abstractmethod
    def prover_message(self, hash_state, elements: list):
        raise NotImplementedError

    @abstractmethod
    def verifier_challenge(self, hash_state):
        raise NotImplementedError



### Schnorr proofs

class Morphism:
    """
    This class describes a linear morphism of [Maurer09].
    """
    LinearCombination = namedtuple(
        "LinearCombination", ["scalar_indices", "element_indices"])
    Group = None

    def __init__(self, group):
        self.linear_combinations = []
        self.group_elements = []

        self.num_scalars = 0
        self.num_elements = 0

        self.Group = group

    def append(self, linear_combination: LinearCombination):
        self.linear_combinations.append(linear_combination)

    @property
    def num_statements(self):
        return len(self.linear_combinations)

    # def map(self, scalars):
    def __call__(self, scalars):
        image = []
        for linear_combination in self.linear_combinations:
            coefficients = [scalars[i]
                            for i in linear_combination.scalar_indices]
            elements = [self.group_elements[i]
                        for i in linear_combination.element_indices]
            image.append(self.Group.msm(coefficients, elements))
        return image


class GroupMorphismPreimage:
    def __init__(self, group):
        self.morphism = Morphism(group)
        self._image = []

        self.group = group
        self.Domain = group.ScalarField
        self.Image = group

    @property
    def commit_bytes_len(self):
        return self.morphism.num_statements * self.Image.element_byte_length()

    @property
    def response_bytes_len(self):
        return self.morphism.num_scalars * self.Domain.scalar_byte_length()

    def append_equation(self, lhs, rhs):
        linear_combination = Morphism.LinearCombination(
            scalar_indices=[x[0] for x in rhs],
            element_indices=[x[1] for x in rhs]
        )
        self.morphism.append(linear_combination)
        self._image.append(lhs)

    def allocate_scalars(self, n: int):
        indices = list(range(self.morphism.num_scalars,
                       self.morphism.num_scalars + n))
        self.morphism.num_scalars += n
        return indices

    def allocate_elements(self, n: int):
        indices = list(range(self.morphism.num_elements,
                       self.morphism.num_elements + n))
        self.morphism.group_elements.extend([None] * n)
        self.morphism.num_elements += n
        return indices

    def set_elements(self, elements):
        for index, element in elements:
            self.morphism.group_elements[index] = element

    @property
    def image(self):
        return [self.morphism.group_elements[i] for i in self._image]

    def get_description(self):
        # We pad all integers to 32 bytes.
        desc = b''
        # The number of scalars, elements, and statements
        desc += self.morphism.num_scalars.to_bytes(32)
        desc += self.morphism.num_elements.to_bytes(32)
        desc += self.morphism.num_statements.to_bytes(32)
        for (idx, linear_combination) in enumerate(self.morphism.linear_combinations):
            # Index of the group element image of the MSM
            desc += self._image[idx].to_bytes(32)
            # Index of the scalars in the MSM
            desc += (b'').join([scalar_idx.to_bytes(32) for scalar_idx in linear_combination.scalar_indices])
            # Index of the group elements in the MSM
            desc += (b'').join([element_idx.to_bytes(32) for element_idx in linear_combination.element_indices])
        for group_element in self.morphism.group_elements:
            # Add the serialization of the actual group elements
            desc += self.group.serialize([group_element])
        return sha256(desc).digest()


class SchnorrProof(SigmaProtocol):
    # A sparse linear combination
    ProverState = namedtuple("ProverState", ["witness", "nonces"])

    def __init__(self, instance):
        self.instance = instance

    def prover_commit(self, witness, rng):
        nonces = [
            self.instance.Domain.random(rng)
            for _ in range(self.instance.morphism.num_scalars)
        ]
        prover_state = self.ProverState(witness, nonces)
        commitment = self.instance.morphism(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state: ProverState, challenge):
        witness, nonces = prover_state
        return [
            nonces[i] + witness[i] * challenge
            for i in range(self.instance.morphism.num_scalars)
        ]

    def verifier(self, commitment, challenge, response):
        assert len(commitment) == self.instance.morphism.num_statements
        assert len(response) == self.instance.morphism.num_scalars
        expected = self.instance.morphism(response)
        got = [
            commitment[i] + self.instance.image[i] * challenge
            for i in range(self.instance.morphism.num_statements)
        ]

        # fail hard if the proof does not verify
        assert got == expected, f"verification equation fails.\n{got} != {expected}"
        return True

    def serialize_batchable(self, commitment, challenge, response):
        return (
            self.instance.Image.serialize(commitment) +
            self.instance.Domain.serialize(response)
        )

    def deserialize_batchable(self, encoded):
        assert len(encoded) == self.instance.commit_bytes_len + self.instance.response_bytes_len
        commitment_bytes = encoded[: self.instance.commit_bytes_len]
        commitment = self.instance.Image.deserialize(commitment_bytes)

        response_bytes = encoded[self.instance.commit_bytes_len:]
        response = self.instance.Domain.deserialize(response_bytes)

        return (commitment, response)

    def simulate_response(self, rng):
        return [self.instance.Domain.random(rng) for i in range(self.instance.morphism.num_scalars)]

    def simulate_commitment(self, response, challenge):
        h_c_values = [self.instance.image[i] * challenge for i in range(self.instance.morphism.num_statements)]
        # Generate what the correct commitment would be based on the random response and challenge.
        return [self.instance.morphism([response])[0] - h_c_value for (h_c_value, response) in zip(h_c_values, response)]



### The Fiat-Shamir transformation of Sigma protocols

class NISigmaProtocol:
    """
    The generic Fiat-Shamir transformation of a Sigma protocol.
    Puts together 3 components:
    - a Sigma protocol that implements `SigmaProtocol`;
    - a codec that implements `Codec`;
    - a hash function that implements `DuplexSpongeInterface`.
    """

    Protocol: SigmaProtocol = None
    Codec: Codec = None
    Hash: DuplexSpongeInterface = None

    def __init__(self, iv, instance):
        self.hash_state = self.Hash(iv)
        self.sp = self.Protocol(instance)
        self.codec = self.Codec()

    def prove(self, witness, rng):
        hash_state = self.hash_state.clone()

        (prover_state, commitment) = self.sp.prover_commit(witness, rng)
        self.codec.prover_message(hash_state, commitment)
        challenge = self.codec.verifier_challenge(hash_state)
        response = self.sp.prover_response(prover_state, challenge)

        assert self.sp.verifier(commitment, challenge, response)
        return self.sp.serialize_batchable(commitment, challenge, response)

    def verify(self, proof):
        hash_state = self.hash_state.clone()

        commitment, response = self.sp.deserialize_batchable(proof)
        self.codec.prover_message(hash_state, commitment)
        challenge = self.codec.verifier_challenge(hash_state)
        return self.sp.verifier(commitment, challenge, response)

### Codecs for the byte-oriented hash functions and elliptic curve groups

class ByteSchnorrCodec(Codec):
    GG: groups.Group = None

    def prover_message(self, hash_state, elements: list):
        hash_state.absorb(self.GG.serialize(elements))

    def verifier_challenge(self, hash_state):
        from hash_to_field import OS2IP

        uniform_bytes = hash_state.squeeze(
            self.GG.ScalarField.scalar_byte_length() + 16
        )
        scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
        return scalar


class Bls12381Codec(ByteSchnorrCodec):
    GG = groups.BLS12_381_G1


class P256Codec(ByteSchnorrCodec):
    GG = groups.GroupP256()


### Ciphersuite instantiation

class NISchnorrProofKeccakDuplexSpongeP256(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = P256Codec
    Hash = KeccakDuplexSponge


class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = Bls12381Codec
    Hash = KeccakDuplexSponge


CIPHERSUITE = {
    "sigma/OWKeccak1600+P256": NISchnorrProofKeccakDuplexSpongeP256,
    "sigma/OWKeccak1600+BLS12381": NISchnorrProofKeccakDuplexSpongeBls12381,
}