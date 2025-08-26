
from abc import ABC, abstractmethod
from sagelib import groups
from sagelib.hash_to_field import OS2IP, I2OSP


class Codec(ABC):
    """
    This is the abstract API of a codec.

    A codec is a collection of:
    - functions that map prover messages into the hash function domain,
    - functions that map hash outputs into verifier messages (of the desired distribution).
    In addition, the "init" function initializes the hash state with a session ID and an instance label.
    For byte-oriented codecs, this is just the concatenation of the two prefixed by their lengths.
    """

    def init(self, session_id, instance_label):
        return b''.join((
            I2OSP(len(session_id), 4),
            session_id,
            I2OSP(len(instance_label), 4),
            instance_label
        ))

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
        # see https://eprint.iacr.org/2025/536.pdf, Appendix C.
        uniform_bytes = hash_state.squeeze(
            self.GG.ScalarField.scalar_byte_length() + 16
        )
        scalar = OS2IP(uniform_bytes) % self.GG.ScalarField.order
        return scalar


class Bls12381Codec(ByteSchnorrCodec):
    GG = groups.BLS12_381_G1


class P256Codec(ByteSchnorrCodec):
    GG = groups.GroupP256()

