from abc import ABC, abstractmethod
from collections import namedtuple

from sagelib.fiat_shamir import KeccakDuplexSpongeP384


class SigmaProtocol(ABC):
    """
    This is the abstract API of a Sigma protocol.
    It can be extended for AND/OR composition, for OR proofs, for

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


Witness = list
ScalarVar = int

# A sparse linear combination
ProverState = namedtuple("ProverState", ["witness", "nonces"])

class Morphism:
    LinearCombination = namedtuple("LinearCombination", ["scalar_indices", "elements"])
    Group = None

    def __init__(self, group):
        self.linear_combinations = []
        self.num_scalars = 0
        self.Group = group

    def append(self, linear_combination: LinearCombination):
        self.linear_combinations.append(linear_combination)

    @property
    def num_statements(self):
        return len(self.linear_combinations)

    # def map(self, scalars):
    def __call__(self, scalars):
        """
        This is the linear morphism of [Maurer09].
        """
        image = []
        for linear_combination in self.linear_combinations:
            coefficients = [scalars[i] for i in linear_combination.scalar_indices]
            image.append(self.Group.msm(coefficients, linear_combination.elements))
        return image

class GroupMorphismPreimage:
    def __init__(self, group):
        self.morphism = Morphism(group)
        self.image = []
        self.group = group
        self.Domain = group.ScalarField
        self.Image = group

    @property
    def commit_bytes_len(self):
        return self.morphism.num_statements * self.group.element_byte_length()

    def append_equation(self, lhs, rhs):
        linear_combination = Morphism.LinearCombination(
            scalar_indices=[x[0] for x in rhs],
            elements=[x[1] for x in rhs]
        )
        self.morphism.append(linear_combination)
        self.image.append(lhs)

    def allocate_scalars(self, n: int):
        indices = [ScalarVar(i)
                   for i in range(self.morphism.num_scalars, self.morphism.num_scalars + n)]
        self.morphism.num_scalars += n
        return indices


class SchnorrProof(SigmaProtocol):
    def __init__(self, index):
        self.statement = index

    def prover_commit(self, witness, rng):
        nonces = [
            self.statement.Domain.random(rng)
            for _ in range(self.statement.morphism.num_scalars)
        ]
        prover_state = ProverState(witness, nonces)
        commitment = self.statement.morphism(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state: ProverState, challenge):
        (witness, nonces) = prover_state
        return [
            nonces[i] + challenge * witness[i]
            for i in range(self.statement.morphism.num_scalars)
        ]

    def verifier(self, commitment, challenge, response):
        assert len(commitment) == self.statement.morphism.num_statements
        assert len(response) == self.statement.morphism.num_scalars

        expected = self.statement.morphism(response)
        got = [
            commitment[i] + self.statement.image[i] * challenge
            for i in range(self.statement.morphism.num_statements)
        ]

        # fail hard if the proof does not verify
        assert got == expected
        return True

    def serialize_batchable(self, commitment, challenge, response):
        return (
            self.statement.Image.serialize(commitment) +
            self.statement.Domain.serialize(response)
        )

    def deserialize_batchable(self, encoded):
        commitment_bytes = encoded[: self.statement.commit_bytes_len]
        commitment = self.statement.Image.deserialize(commitment_bytes)

        response_bytes = encoded[self.statement.commit_bytes_len :]
        response = self.statement.Domain.deserialize(response_bytes)

        return (commitment, response)



class NISigmaProtocol:
    """
    Performs the Fiat-Shamir Transform for the Sigma protocol `protocol`
    producing challenges using `codec`.
    """
    Protocol = SchnorrProof
    Codec = KeccakDuplexSpongeP384

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

