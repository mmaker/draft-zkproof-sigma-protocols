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

    def _prove(self, witness, rng):
        """
        Core proving logic that returns commitment, challenge, and response.
        The challenge is generated via the hash function.
        """
        (prover_state, commitment) = self.sp.prover_commit(witness, rng)
        self.codec.prover_message(self.hash_state, commitment)
        challenge = self.codec.verifier_challenge(self.hash_state)
        response = self.sp.prover_response(prover_state, challenge)
        return (commitment, challenge, response)

    def prove(self, witness, rng):
        """
        Proving method using commitment-response format.

        Allows for batching.
        """
        (commitment, challenge, response) = self._prove(witness, rng)
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

    def prove_short(self, witness, rng):
        """
        Alternative proving method using challenge-response format.
        """
        (commitment, challenge, response) = self._prove(witness, rng)
        assert self.sp.verifier(commitment, challenge, response)
        return self.sp.serialize_challenge(challenge) + self.sp.serialize_response(response)

    def verify_short(self, proof):
        """
        Alternative verification method using challenge-response format.
        """
        challenge_len = self.sp.instance.Domain.scalar_byte_length()
        challenge_bytes = proof[:challenge_len]
        response_bytes = proof[challenge_len:]

        challenge = self.sp.deserialize_challenge(challenge_bytes)
        response = self.sp.deserialize_response(response_bytes)
        commitment = self.sp.simulate_commitment(response, challenge)

        return self.sp.verifier(commitment, challenge, response)


