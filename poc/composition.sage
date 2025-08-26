from sagelib.test_drng import TestDRNG
from sagelib.sigma_protocols import LinearRelation, SigmaProtocol, SchnorrProof
from sagelib.fiat_shamir import NIZK
from sagelib.codec import P256Codec
from sagelib.duplex_sponge import KeccakDuplexSponge
from sagelib import groups

class AndProof(SchnorrProof):
    ProverState: list[SchnorrProof.ProverState]

    def __init__(self, instances: list[LinearRelation]):
        self.protocols = [SchnorrProof(instance) for instance in instances]
        self.instance = self  # For compatibility with fiat_shamir

    @property
    def commit_bytes_len(self):
        return sum(protocol.instance.commit_bytes_len for protocol in self.protocols)

    @property
    def response_bytes_len(self):
        return sum(protocol.instance.response_bytes_len for protocol in self.protocols)

    def prover_commit(self, witnesses, rng):
        prover_states = []
        commitments = []

        for protocol, witness in zip(self.protocols, witnesses):
            prover_state, commitment = protocol.prover_commit(witness, rng)
            commitments.append(commitment)
            prover_states.append(prover_state)

        return (prover_states, commitments)

    def prover_response(self, prover_states, challenge):
        responses = []
        for prover_state, protocol in zip(prover_states, self.protocols):
            response = protocol.prover_response(prover_state, challenge)
            responses.append(response)
        return responses

    def verifier(self, commitments, challenge, responses):
        assert len(commitments) == len(responses)
        assert all(
            protocol.verifier(commitment, challenge, response)
            for protocol, commitment, response in zip(self.protocols, commitments, responses)
        )
        return True

    def serialize_commitment(self, commitments):
        return b''.join([protocol.serialize_commitment(commitment) for protocol, commitment in zip(self.protocols, commitments)])

    def serialize_response(self, responses):
        return b''.join([protocol.serialize_response(response) for protocol, response in zip(self.protocols, responses)])

    def deserialize_commitment(self, data):
        commitments = []
        offset = 0
        for protocol in self.protocols:
            commit_len = protocol.instance.commit_bytes_len
            commitment = protocol.deserialize_commitment(data[offset:offset + commit_len])
            commitments.append(commitment)
            offset += commit_len
        return commitments

    def deserialize_response(self, data):
        responses = []
        offset = 0
        for protocol in self.protocols:
            response_len = protocol.instance.response_bytes_len
            response = protocol.deserialize_response(data[offset:offset + response_len])
            responses.append(response)
            offset += response_len
        return responses


class P256AndCodec(P256Codec):
    def prover_message(self, hash_state, elements):
        flat_elements = sum(elements, [])
        return super().prover_message(hash_state, flat_elements)


class NIAndProof(NIZK):
    Protocol = AndProof
    Codec = P256AndCodec
    Hash = KeccakDuplexSponge


class OrProof(SchnorrProof):
    ProverState: list[SchnorrProof.ProverState]

    def __init__(self, instances: list[LinearRelation]):
        self.protocols = [SchnorrProof(instance) for instance in instances]
        self.instance = self  # For compatibility with fiat_shamir

    @property
    def commit_bytes_len(self):
        return sum(protocol.instance.commit_bytes_len for protocol in self.protocols)

    @property
    def response_bytes_len(self):
        return (sum(protocol.instance.response_bytes_len for protocol in self.protocols) +
                sum(protocol.instance.Domain.scalar_byte_length() for protocol in self.protocols[:-1]))

    def prover_commit(self, witnesses, rng):
        assert witnesses.count(None) == len(self.protocols) - 1

        prover_states = []
        unknown_witness_prover_states = []
        commitments = []

        # We want to keep track of the commitment of the known protocol,
        # as well as which index it occurs in in order to insert it in
        # the correct spot in the array.
        known_index = 0
        known_value_hit = False
        known_commitment = None

        for protocol, witness in zip(self.protocols, witnesses):
            if not witness is None:
                known_value_hit = True
                prover_state, known_commitment = protocol.prover_commit(witness, rng)
                prover_states.append((prover_state, known_index))
            else:
                if not known_value_hit:
                    known_index += 1
                # We perform the simulator for the prover in order to generate valid commitments
                # for the unknown witnesses, assuming the prover starts with a random response.
                simulated_responses = protocol.simulate_response(rng)
                # Also pick a random value for the challenge
                prover_challenge = protocol.instance.Domain.random(rng)
                simulated_commitments = protocol.simulate_commitment(simulated_responses, prover_challenge)
                commitments.append(simulated_commitments)
                unknown_witness_prover_states.append((prover_challenge, simulated_responses))
        assert(not known_commitment is None)
        commitments.insert(known_index, known_commitment)
        # We assume there is only one protocol the prover knows the witness to.
        assert len(prover_states) == 1
        return ((prover_states, unknown_witness_prover_states), commitments)

    def prover_response(self, prover_states, challenge):
        (known_prover_states, unknown_witness_prover_states) = prover_states
        known_state_challenge = challenge
        responses = []
        challenges = []

        # The sum of all of the challenges for each of the protocols should be
        # the verifier challenge. Therefore find the unknown challenge by
        # subtracting the prover's shares from the verifier challenge.
        for challenge_share, sim_responses in unknown_witness_prover_states:
            known_state_challenge -= challenge_share
            responses.append(sim_responses)
            challenges.append(challenge_share)

        # Include the response for the known protocol at the correct index
        # (i.e., the index of the protocol in the original list of protocols)
        (known_prover_state, known_index) = known_prover_states[0]
        known_response = self.protocols[known_index].prover_response(known_prover_state, known_state_challenge)

        responses.insert(known_index, known_response)
        challenges.insert(known_index, known_state_challenge)

        return (challenges[:-1], responses)

    def verifier(self, commitments, challenge, _response):
        challenges, responses = _response
        assert len(commitments) == len(responses)
        last_challenge = challenge - sum(challenges)
        challenges.append(last_challenge)
        assert all(
            protocol.verifier(commitment, challenge, response)
            for protocol, commitment, challenge, response in zip(self.protocols, commitments, challenges, responses)
        )

        return True

    def serialize_commitment(self, commitments):
        return b''.join([protocol.serialize_commitment(commitment) for protocol, commitment in zip(self.protocols, commitments)])

    def serialize_response(self, _response):
        challenges, responses = _response
        return (b''.join([protocol.serialize_response(response) for protocol, response in zip(self.protocols, responses)]) +
                b''.join([protocol.instance.Domain.serialize([challenge]) for (protocol, challenge) in zip(self.protocols[:-1], challenges)]))

    def deserialize_commitment(self, data):
        commitments = []
        offset = 0
        for protocol in self.protocols:
            commit_len = protocol.instance.commit_bytes_len
            commitment = protocol.deserialize_commitment(data[offset:offset + commit_len])
            commitments.append(commitment)
            offset += commit_len
        return commitments

    def deserialize_response(self, data):
        challenges = []
        responses = []
        offset = 0

        # First deserialize all responses
        for protocol in self.protocols:
            response_len = protocol.instance.response_bytes_len
            response = protocol.deserialize_response(data[offset:offset + response_len])
            responses.append(response)
            offset += response_len

        # Then deserialize the challenges (all but the last one)
        for protocol in self.protocols[:-1]:
            challenge_len = protocol.instance.Domain.scalar_byte_length()
            challenge = protocol.instance.Domain.deserialize(data[offset:offset + challenge_len])
            challenges.append(challenge[0])
            offset += challenge_len

        return (challenges, responses)


class P256OrCodec(P256Codec):
    def prover_message(self, hash_state, elements):
        flat_elements = sum(elements, [])
        return super().prover_message(hash_state, flat_elements)

    def verifier_challenge(self, hash_state):
        return super().verifier_challenge(hash_state)


class NIOrProof(NIZK):
    Protocol = OrProof
    Codec = P256OrCodec
    Hash = KeccakDuplexSponge


def test_and_composition():
    CONTEXT_STRING = b'yellow submarine' * 2
    rng = TestDRNG("test vector seed".encode('utf-8'))
    group = P256Codec.GG

    statement_1 = LinearRelation(group)
    [var_x] = statement_1.allocate_scalars(1)
    [var_G, var_X] = statement_1.allocate_elements(2)
    statement_1.append_equation(var_X, [(var_x, var_G)])
    G = group.generator()
    statement_1.set_elements([(var_G, G)])
    x = group.ScalarField.random(rng)
    X = G * x
    assert [X] == statement_1.linear_map([x])
    statement_1.set_elements([(var_X, X)])
    witness_1 = [x]

    statement_2 = LinearRelation(group)
    [var_y] = statement_2.allocate_scalars(1)
    [var_H, var_Y] = statement_2.allocate_elements(2)
    statement_2.append_equation(var_Y, [(var_y, var_H)])
    H = group.generator()
    statement_2.set_elements([(var_H, H)])
    y = group.ScalarField.random(rng)
    Y = H * y
    assert [Y] == statement_2.linear_map([y])
    statement_2.set_elements([(var_Y, Y)])
    witness_2 = [y]

    instances = [statement_1, statement_2]
    witnesses = [witness_1, witness_2]

    narg_string = NIAndProof(CONTEXT_STRING, instances).prove(witnesses, rng)
    assert NIAndProof(CONTEXT_STRING, instances).verify(narg_string)
    print(f"test_and_composition narg_string: {narg_string.hex()}\n")


def test_or_composition():
    CONTEXT_STRING = b'yellow submarine' * 2

    rng = TestDRNG("test vector seed".encode('utf-8'))
    group = P256Codec.GG

    statement_1 = LinearRelation(group)
    [var_x] = statement_1.allocate_scalars(1)
    [var_G, var_X] = statement_1.allocate_elements(2)
    statement_1.append_equation(var_X, [(var_x, var_G)])
    G = group.generator()
    statement_1.set_elements([(var_G, G)])
    x = group.ScalarField.random(rng)
    X = G * x
    assert [X] == statement_1.linear_map([x])
    statement_1.set_elements([(var_X, X)])
    witness_1 = [x]

    statement_2 = LinearRelation(group)
    [var_y] = statement_2.allocate_scalars(1)
    [var_H, var_Y] = statement_2.allocate_elements(2)
    statement_2.append_equation(var_Y, [(var_y, var_H)])
    H = group.generator()
    statement_2.set_elements([(var_H, H)])
    y = group.ScalarField.random(rng)
    Y = H * y
    assert [Y] == statement_2.linear_map([y])
    statement_2.set_elements([(var_Y, Y)])
    witness_2 = None

    instances = [statement_1, statement_2]
    witnesses = [witness_1, witness_2]

    narg_string = NIOrProof(CONTEXT_STRING, instances).prove(witnesses, rng)
    assert NIOrProof(CONTEXT_STRING, instances).verify(narg_string)
    print(f"test_or_composition narg_string: {narg_string.hex()}")


def test():
    test_and_composition()
    test_or_composition()


if __name__ == "__main__":
    test()