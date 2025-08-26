from sagelib.codec import Codec
from sagelib.groups import Group
from sagelib.sigma_protocols import SigmaProtocol
from sagelib.duplex_sponge import DuplexSpongeInterface


class NIZK:
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

    def __init__(self, session_id, instance):
        protocol_id = self.Protocol.get_protocol_id()
        assert len(protocol_id) == 64, f"Invalid protocol ID length: {len(protocol_id)} for {protocol_id}"

        self.sigma_protocol = self.Protocol(instance)
        self.codec = self.Codec()
        instance_label = self.sigma_protocol.get_instance_label()

        # Use the appropriate initialization based on hash function type
        if hasattr(self.Hash, 'get_iv_from_identifiers'):
            iv = self.Hash.get_iv_from_identifiers(protocol_id, session_id, instance_label)
            self.hash_state = self.Hash(iv)
        else:
            self.hash_state = self.Hash(protocol_id)
            self.hash_state.absorb(self.codec.init(session_id, instance_label))


    def prove(self, witness, rng):
        (prover_state, commitment) = self.sigma_protocol.prover_commit(witness, rng)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        response = self.sigma_protocol.prover_response(prover_state, challenge)
        assert self.sigma_protocol.verifier(commitment, challenge, response)
        return self.sigma_protocol.serialize_commitment(commitment) + self.sigma_protocol.serialize_response(response)

    def verify(self, proof):
        # Before running the sigma protocol verifier, one must also check that:
        # - the proof length is exactly commit_bytes_len + response_bytes_len
        assert len(proof) == self.sigma_protocol.instance.commit_bytes_len + self.sigma_protocol.instance.response_bytes_len, f"Invalid proof length: {len(proof)} != {self.sigma_protocol.instance.commit_bytes_len + self.sigma_protocol.instance.response_bytes_len}"
        # - proof deserialization successfully produces a valid commitment and a valid response
        commitment_bytes = proof[:self.sigma_protocol.instance.commit_bytes_len]
        response_bytes = proof[self.sigma_protocol.instance.commit_bytes_len:]
        commitment = self.sigma_protocol.deserialize_commitment(commitment_bytes)
        response = self.sigma_protocol.deserialize_response(response_bytes)

        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        return self.sigma_protocol.verifier(commitment, challenge, response)