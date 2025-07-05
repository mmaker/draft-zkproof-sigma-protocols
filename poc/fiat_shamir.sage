from sagelib.groups import Group
from sagelib import groups
from sagelib.sigma_protocols import SigmaProtocol
from sagelib.codec import Codec
from sagelib.duplex_sponge import DuplexSpongeInterface


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
    Hash: 'DuplexSpongeInterface' = None

    def __init__(self, iv, instance):
        self.hash_state = self.Hash(iv)
        self.sp = self.Protocol(instance)
        self.codec = self.Codec()

    @classmethod
    def init_with_session_id(cls, session_id, instance):
        protocol_id = instance.get_protocol_id()
        instance_label = instance.get_instance_label()
        iv_from_id = self.Hash.get_iv_from_identifiers(protocol_id, session_id, instance_label)
        return cls(iv_from_id, instance)

    def prove(self, witness, rng):
        (prover_state, commitment) = self.sp.prover_commit(witness, rng)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        response = self.sp.prover_response(prover_state, challenge)

        assert self.sp.verifier(commitment, challenge, response)
        return self.sp.serialize_commitment(commitment) + self.sp.serialize_response(response)

    def verify(self, proof):
        commitment_bytes = proof[:self.sp.instance.commit_bytes_len]
        response_bytes = proof[self.sp.instance.commit_bytes_len:]
        commitment = self.sp.deserialize_commitment(commitment_bytes)
        response = self.sp.deserialize_response(response_bytes)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        return self.sp.verifier(commitment, challenge, response)


