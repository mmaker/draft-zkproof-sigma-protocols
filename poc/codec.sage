
from abc import ABC, abstractmethod
from sagelib import groups

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


class ByteSchnorrCodec(Codec):
    GG: groups.Group = None

    def prover_message(self, hash_state, elements: list):
        hash_state.absorb(self.GG.serialize(elements))

    def verifier_challenge(self, hash_state):
        from groups.hash_to_field import OS2IP

        uniform_bytes = hash_state.squeeze(
            self.GG.ScalarField.scalar_byte_length() + 16
        )
        scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
        return scalar


class Bls12381Codec(ByteSchnorrCodec):
    GG = groups.BLS12_381_G1


class P256Codec(ByteSchnorrCodec):
    GG = groups.GroupP256()

