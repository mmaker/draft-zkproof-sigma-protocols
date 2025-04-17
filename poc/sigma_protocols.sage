from abc import ABC, abstractmethod
from collections import namedtuple

from sagelib import groups
from sagelib.fiat_shamir import DuplexSpongeInterface, KeccakDuplexSponge

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


class NISigmaProtocol:
    """
    The generic Fiat-Shamir Transform for the Sigma protocol `Protocol`
    producing challenges using `Codec`.
    """
    Protocol: SigmaProtocol = None
    Codec = None

    def __init__(self, iv, instance):
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
        return self.morphism.num_statements * self.group.element_byte_length()

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
        G = self.instance.morphism.group_elements[0]
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
        commitment_bytes = encoded[: self.instance.commit_bytes_len]
        commitment = self.instance.Image.deserialize(commitment_bytes)

        response_bytes = encoded[self.instance.commit_bytes_len:]
        response = self.instance.Domain.deserialize(response_bytes)

        return (commitment, response)


class ByteSchnorrCodec:
    GG: groups.Group = None
    Hash: DuplexSpongeInterface = None

    def __init__(self, iv: bytes):
        self.hash_state = self.Hash(iv)

    def prover_message(self, elements: list):
        self.hash_state.absorb(self.GG.serialize(elements))
        # calls can be chained
        return self

    def verifier_challenge(self):
        from hash_to_field import OS2IP

        uniform_bytes = self.hash_state.squeeze(
            self.GG.ScalarField.scalar_byte_length() + 16
        )
        scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
        return scalar


### Codecs for the different groups

class KeccakDuplexSpongeP384(ByteSchnorrCodec):
    GG = groups.GroupP384()
    Hash = KeccakDuplexSponge


class KeccakDuplexSpongeBls12381(ByteSchnorrCodec):
    GG = groups.BLS12_381_G1
    Hash = KeccakDuplexSponge

class KeccakDuplexSpongeP256(ByteSchnorrCodec):
    GG = groups.GroupP256()
    Hash = KeccakDuplexSponge


### Ciphersuite instantiation
class NISchnorrProofKeccakDuplexSpongeP256(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = KeccakDuplexSpongeP256

class NISchnorrProofKeccakDuplexSpongeP384(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = KeccakDuplexSpongeP384

class NISchnorrProofKeccakDuplexSpongeBls12381(NISigmaProtocol):
    Protocol = SchnorrProof
    Codec = KeccakDuplexSpongeBls12381

CIPHERSUITE = {
    "sigma/OWKeccak1600+P256": NISchnorrProofKeccakDuplexSpongeP256,
    "sigma/OWKeccak1600+P384": NISchnorrProofKeccakDuplexSpongeP384,
    "sigma/OWKeccak1600+BLS12381": NISchnorrProofKeccakDuplexSpongeBls12381,
}



if __name__ == "__main__":
    label = b"yellow submarine" * 2
    sponge = KeccakDuplexSpongeP384(label)
    sponge.absorb_bytes(b"\0" * 1000)
    output = sponge.squeeze_bytes(1000)
    print(output.hex())