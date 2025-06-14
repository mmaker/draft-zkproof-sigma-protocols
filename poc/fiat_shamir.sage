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

    def prove(self, witness, rng):
        (prover_state, commitment) = self.sp.prover_commit(witness, rng)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        response = self.sp.prover_response(prover_state, challenge)

        assert self.sp.verifier(commitment, challenge, response)
        return self.sp.serialize_batchable(commitment, challenge, response)

    def verify(self, proof):
        commitment, response = self.sp.deserialize_batchable(proof)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        return self.sp.verifier(commitment, challenge, response)


