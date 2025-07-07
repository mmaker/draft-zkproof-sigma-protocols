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


### Schnorr proofs

class LinearMap:
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

        self.group = group
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
    
    def convert_linear_map_to_repr(self):
        """
        Convert this linear map into a standard representation. Called during serialization.
        """
        assert all(x is not None for x in self.linear_map.group_elements), "All group elements must be set before serialization."

        # Map from current state index to the index in the representation
        linear_map_idx_to_repr_idx_map = {}
        linear_map_repr = []
        rearranged_group_elements = []
        
        for i, linear_combination in enumerate(self.linear_map.linear_combinations):
            equations = []
            element_indices = linear_combination.element_indices
            scalar_indices = linear_combination.scalar_indices
            assert(len(element_indices) == len(scalar_indices)), "The number of scalars and elements must be the same in a linear combination"
            
            for (element_idx, scalar_idx) in zip(element_indices, scalar_indices):
                # Assign the next available index to the repr.
                repr_element_idx = len(linear_map_idx_to_repr_idx_map)
                if element_idx in linear_map_idx_to_repr_idx_map:
                    repr_element_idx = linear_map_idx_to_repr_idx_map[element_idx]
                # Or used the existing value if we are reusing a group element.
                else: 
                    rearranged_group_elements.append(self.linear_map.group_elements[element_idx])
                    linear_map_idx_to_repr_idx_map[element_idx] = repr_element_idx
                equations.append((scalar_idx, repr_element_idx))
            
            target_element_idx = self._image[i]
            repr_target_element_idx = len(linear_map_idx_to_repr_idx_map)
            # Assign the next available index to the repr.
            if target_element_idx in linear_map_idx_to_repr_idx_map:
                repr_target_element_idx = linear_map_idx_to_repr_idx_map[element_idx]
            # Or used the existing value if we are reusing a group element.
            else: 
                rearranged_group_elements.append(self.linear_map.group_elements[target_element_idx])
                linear_map_idx_to_repr_idx_map[target_element_idx] = repr_target_element_idx
            linear_map_repr.append((repr_target_element_idx, equations))
        
        # The rearranged group elements are simply a permutation of those in the linear map.
        assert(len(rearranged_group_elements) == len(self.linear_map.group_elements))
        return (rearranged_group_elements, linear_map_repr)

    def get_label(self):
        """
        Generate a canonical description that uniquely identifies this linear relation.

        This includes the linear combination indices for each constraint, and the actual group element used.

        Returns:
            bytes: Canonical byte representation of the linear relation
        """

        (group_elements, linear_equations) = self.convert_linear_map_to_repr()

        # All integers are serialized as 32-bit big-endian values for consistency
        WORD_SIZE_BITS = 32
        WORD_SIZE = WORD_SIZE_BITS // 8
        serialization_parts = []

        # Encode the number of equations
        serialization_parts.append(len(self.linear_map.linear_combinations).to_bytes(WORD_SIZE, 'little'))

        # Encode each linear combination constraint
        for (target_element_idx, linear_combination) in linear_equations:
            # The target group element index for this constraint
            serialization_parts.append(target_element_idx.to_bytes(WORD_SIZE, 'little'))

            # Encode the dimension of the equation.
            serialization_parts.append(len(linear_combination).to_bytes(WORD_SIZE, 'little'))

            # Indices of scalars and group elements participating in this linear combination
            for (scalar_idx, element_idx) in linear_combination:
                serialization_parts.append(scalar_idx.to_bytes(WORD_SIZE, 'little'))
                serialization_parts.append(element_idx.to_bytes(WORD_SIZE, 'little'))

        # Encode the actual group element values
        for group_element in group_elements:
            serialization_parts.append(self.group.serialize([group_element]))

        # Return the canonical description without hashing
        return b''.join(serialization_parts)


class SchnorrProof(SigmaProtocol):
    # A sparse linear combination
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

    def get_protocol_id():
        return 'draft-zkproof-fiat-shamir'.encode('utf-8')