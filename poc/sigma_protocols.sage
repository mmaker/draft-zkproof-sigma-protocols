from abc import ABC, abstractmethod
from collections import namedtuple

from sagelib import groups


class SigmaProtocol(ABC):
    """
    This is the abstract API of a Sigma protocol.

    An (interactive) Sigma protocol is a 3-message protocol that is special sound and honest-verifier zero-knowledge.
    Relations for sigma protocols are seen as ternary relations composed of:
    - instance: the public part of the statement that can be pre-processed offline
    - witness: the secret witness for the relation.
    """
    @abstractmethod
    def __init__(self, instance):
        raise NotImplementedError

    @abstractmethod
    def prover_commit(self, witness, rng):
        raise NotImplementedError

    @abstractmethod
    def prover_response(self, prover_state, challenge):
        raise NotImplementedError

    @abstractmethod
    def verifier(self, commitment, challenge, response):
        raise NotImplementedError

    @abstractmethod
    def serialize_commitment(self, commitment):
        raise NotImplementedError

    @abstractmethod
    def serialize_response(self, response):
        raise NotImplementedError

    @abstractmethod
    def deserialize_commitment(self, data):
        raise NotImplementedError

    @abstractmethod
    def deserialize_response(self, data):
        raise NotImplementedError

    # optional
    def simulate_response(self, rng):
        raise NotImplementedError

    # optional
    def simulate_commitment(self, response, challenge):
        raise NotImplementedError


class SchnorrProof(SigmaProtocol):
    """
    A sigma protocol for simple linear relations.
    """
    ProverState = namedtuple("ProverState", ["witness", "nonces"])

    def __init__(self, instance):
        self.instance = instance

    def prover_commit(self, witness, rng):
        nonces = [self.instance.Domain.random(rng) for _ in range(self.instance.linear_map.num_scalars)]
        prover_state = self.ProverState(witness, nonces)
        commitment = self.instance.linear_map(nonces)
        return (prover_state, commitment)

    def prover_response(self, prover_state: ProverState, challenge):
        witness, nonces = prover_state
        return [
            nonces[i] + witness[i] * challenge
            for i in range(self.instance.linear_map.num_scalars)
        ]

    def verifier(self, commitment, challenge, response):
        assert len(commitment) == self.instance.linear_map.num_constraints
        assert len(response) == self.instance.linear_map.num_scalars
        expected = self.instance.linear_map(response)
        got = [
            commitment[i] + self.instance.image[i] * challenge
            for i in range(self.instance.linear_map.num_constraints)
        ]

        # fail hard if the proof does not verify
        assert got == expected, f"verification equation fails.\n{got} != {expected}"
        return True

    def serialize_commitment(self, commitment):
        return self.instance.Image.serialize(commitment)

    def serialize_challenge(self, challenge):
        return self.instance.Domain.serialize([challenge])

    def serialize_response(self, response):
        return self.instance.Domain.serialize(response)

    def deserialize_commitment(self, data):
        return self.instance.Image.deserialize(data)

    def deserialize_challenge(self, data):
        scalar_size = self.instance.Domain.scalar_byte_length()
        return self.instance.Domain.deserialize(data[:scalar_size])[0]

    def deserialize_response(self, data):
        return self.instance.Domain.deserialize(data)

    def simulate_response(self, rng):
        return [self.instance.Domain.random(rng) for i in range(self.instance.linear_map.num_scalars)]

    def simulate_commitment(self, response, challenge):
        h_c_values = [self.instance.image[i] * challenge for i in range(self.instance.linear_map.num_constraints)]
        # Generate what the correct commitment would be based on the random response and challenge.
        return [self.instance.linear_map(response)[i] - h_c_values[i] for i in range(self.instance.linear_map.num_constraints)]

    def get_instance_label(self):
        return self.instance.get_label()

    @staticmethod
    def get_protocol_id() -> bytes:
        """
        Returns a 64-bytes unique identifier for this protocol.
        """
        return b'ietf sigma proof linear relation' + b'\0' * 32


class LinearMap:
    """
    This class describes a linear morphism, implemented as a sparse matrix-vector multiplication as in  [Maurer09].
    """

    LinearCombination = namedtuple("LinearCombination", ["scalar_indices", "element_indices"])
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
    def num_constraints(self):
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


class LinearRelation:
    def __init__(self, group):
        self.linear_map = LinearMap(group)
        self._image = []

        self.Domain = group.ScalarField
        self.Image = group

    @property
    def commit_bytes_len(self):
        return self.linear_map.num_constraints * self.Image.element_byte_length()

    @property
    def response_bytes_len(self):
        return self.linear_map.num_scalars * self.Domain.scalar_byte_length()

    def append_equation(self, lhs, rhs):
        linear_combination = LinearMap.LinearCombination(
            scalar_indices=[x[0] for x in rhs],
            element_indices=[x[1] for x in rhs]
        )
        self.linear_map.append(linear_combination)
        self._image.append(lhs)

    def allocate_scalars(self, n: int):
        indices = list(range(self.linear_map.num_scalars,
                       self.linear_map.num_scalars + n))
        self.linear_map.num_scalars += n
        return indices

    def allocate_elements(self, n: int):
        indices = list(range(self.linear_map.num_elements,
                       self.linear_map.num_elements + n))
        self.linear_map.group_elements.extend([None] * n)
        self.linear_map.num_elements += n
        return indices

    def set_elements(self, elements):
        for index, element in elements:
            self.linear_map.group_elements[index] = element

    @property
    def image(self):
        return [self.linear_map.group_elements[i] for i in self._image]

    def _check_relation(self):
        """
        Convert this linear map into a standard representation. Called during serialization.
        """
        assert all(x is not None for x in self.linear_map.group_elements), "All group elements must be set before serialization."
        assert len(self.linear_map.group_elements) == self.linear_map.num_elements, "The number of group elements must match the allocated number."
        assert len(set(self.linear_map.group_elements)) == len(self.linear_map.group_elements), "Group variables must be unique."
        assert all(
            len(linear_combination.scalar_indices) == len(linear_combination.element_indices)
            for linear_combination in self.linear_map.linear_combinations
        ),  "The number of scalars and elements must be the same in a linear combination"

    def get_label(self) -> bytes:
        """
        Generate a canonical description that uniquely identifies this linear relation.

        This includes the linear combination indices for each constraint, and the actual group element used.
        """
        self._check_relation()
        group_elements = self.linear_map.group_elements

        # All integers are serialized as 32-bit big-endian values for consistency
        WORD_SIZE_BITS = 32
        WORD_SIZE = WORD_SIZE_BITS // 8
        serialization_parts = []

        # Encode the number of equations
        serialization_parts.append(len(self.linear_map.linear_combinations).to_bytes(WORD_SIZE, 'little'))
        # Encode each linear combination constraint
        for i, linear_combination in enumerate(self.linear_map.linear_combinations):
            target_element_idx = self._image[i]
            linear_combination_idx = list(zip(linear_combination.scalar_indices, linear_combination.element_indices))

            # The target group element index for this constraint
            serialization_parts.append(target_element_idx.to_bytes(WORD_SIZE, 'little'))
            # Encode the dimension of the equation.
            serialization_parts.append(len(linear_combination).to_bytes(WORD_SIZE, 'little'))

            # Indices of scalars and group elements participating in this linear combination
            for (scalar_idx, element_idx) in linear_combination_idx:
                serialization_parts.append(scalar_idx.to_bytes(WORD_SIZE, 'little'))
                serialization_parts.append(element_idx.to_bytes(WORD_SIZE, 'little'))

        # Encode the actual group element values
        serialization_parts.append(self.Image.serialize(group_elements))

        # Return the canonical description without hashing
        return b''.join(serialization_parts)

