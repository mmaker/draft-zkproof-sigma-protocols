#!/usr/bin/sage
# vim: syntax=python

from sagelib.test_drng import TestDRNG
from sagelib.sigma_protocols import LinearRelation
import json

CONTEXT_STRING = b'yellow submarine' * 2


def test_vector(test_vector_function):
    from sagelib.ciphersuite import NISchnorrProofKeccakDuplexSpongeP256 as NIZK

    def inner(vectors):
        rng = TestDRNG("test vector seed".encode('utf-8'))
        test_vector_name = f"{test_vector_function.__name__}"

        instance, witness = test_vector_function(rng, NIZK.Codec.GG)
        narg_string = NIZK(CONTEXT_STRING, instance).prove(witness, rng)
        assert NIZK(CONTEXT_STRING, instance).verify(narg_string)
        hex_narg_string = narg_string.hex()
        print(f"{test_vector_name} narg_string: {hex_narg_string}\n")

        vectors[test_vector_name] = {
            "Ciphersuite": "sigma/OWKeccak1600+P256",
            "Context": CONTEXT_STRING.hex(),
            "Statement": "TODO",
            "Proof": hex_narg_string,
        }

    return inner


def wrap_write(fh, *args):
    assert args
    line_length = 68
    string = " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")


def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)


def write_group_vectors(fh, label, vector):
    print("## ", label, file=fh)
    print("~~~", file=fh)
    for key in vector:
        write_value(fh, key, vector[key])
    print("~~~", file=fh, end="\n\n")


@test_vector
def discrete_logarithm(rng, group):
    """
    Proves the following statement:

        DL(X) = PoK{(x): X = x * G}

    """

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_X] = statement.allocate_elements(2)
    statement.append_equation(var_X, [(var_x, var_G)])

    G = group.generator()
    statement.set_elements([(var_G, G)])

    x = group.ScalarField.random(rng)
    X = G * x
    assert [X] == statement.linear_map([x])

    statement.set_elements([(var_X, X)])
    return statement, [x]


@test_vector
def dleq(rng, group):
    """
    Proves the following statement:

        DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

    """
    G = group.generator()
    H = group.random(rng)
    x = group.ScalarField.random(rng)
    X = G * x
    Y = H * x

    statement = LinearRelation(group)
    [var_x] = statement.allocate_scalars(1)
    [var_G, var_H, var_X, var_Y] = statement.allocate_elements(4)
    statement.set_elements([(var_G, G), (var_H, H), (var_X, X), (var_Y, Y)])
    statement.append_equation(var_X, [(var_x, var_G)])
    statement.append_equation(var_Y, [(var_x, var_H)])

    assert [X, Y] == statement.linear_map([x])
    return statement, [x]


@test_vector
def pedersen_commitment(rng, group):
    """
    Proves the following statement:

        PEDERSEN(G, H, C) = PoK{(x, r): C = x * G + r * H}

    """
    G = group.generator()
    H = group.random(rng)
    x = group.ScalarField.random(rng)
    r = group.ScalarField.random(rng)
    witness = [x, r]

    C = G * x + H * r
    statement = LinearRelation(group)
    var_x, var_r = statement.allocate_scalars(2)
    var_G, var_H, var_C = statement.allocate_elements(3)
    statement.set_elements([(var_G, G), (var_H, H), (var_C, C)])
    statement.append_equation(var_C, [(var_x, var_G), (var_r, var_H)])

    return statement, witness


@test_vector
def pedersen_commitment_dleq(rng, group):
    """
    Proves the following statement:

        PEDERSEN(G0, G1, G2, G3, X, Y) =
            PoK{
              (x0, x1):
                X = x0 * G0  + x1 * G1,
                Y = x0 * G2 + x1 * G3
            }
    """
    generators = [group.random(rng) for i in range(4)]
    witness = [group.ScalarField.random(rng) for i in range(2)]
    X = group.msm(witness, generators[:2])
    Y = group.msm(witness, generators[2:4])

    statement = LinearRelation(group)
    var_x, var_r = statement.allocate_scalars(2)
    var_Gs = statement.allocate_elements(4)
    var_X, var_Y = statement.allocate_elements(2)

    statement.set_elements([(var_Gs[i], generators[i]) for i in range(4)])
    statement.set_elements([(var_X, X), (var_Y, Y)])

    statement.append_equation(var_X, [(var_x, var_Gs[0]), (var_r, var_Gs[1])])
    statement.append_equation(var_Y, [(var_x, var_Gs[2]), (var_r, var_Gs[3])])
    return statement, witness


@test_vector
def bbs_blind_commitment_computation(rng, group):
    """
    This example test vector is meant to replace:
    https://www.ietf.org/archive/id/draft-kalos-bbs-blind-signatures-01.html#section-4.1.1

    Proves the following statement:
        PoK{
        (secret_prover_blind, msg_1, ..., msg_M):
            C = secret_prover_blind * Q_2 + msg_1 * J_1 + ... + msg_M * J_M
        }
    """
    # length(committed_messages)
    M = 3
    # BBS.create_generators(M + 1, "BLIND_" || api_id)
    (Q_2, J_1, J_2, J_3) = [group.random(rng) for i in range(M+1)]
    # BBS.messages_to_scalars(committed_messages,  api_id)
    (msg_1, msg_2, msg_3) = [group.ScalarField.random(rng) for i in range(M)]

    # these are computed before the proof in the specification
    secret_prover_blind = group.ScalarField.random(rng)
    C = secret_prover_blind * Q_2 + msg_1 * J_1 + msg_2 * J_2 + msg_3 * J_3

    # This is the part that needs to be changed in the specification of blind bbs.
    statement = LinearRelation(group)
    [var_secret_prover_blind, var_msg_1, var_msg_2,
        var_msg_3] = statement.allocate_scalars(M+1)
    [var_Q_2, var_J_1, var_J_2, var_J_3] = statement.allocate_elements(M+1)
    var_C, = statement.allocate_elements(1)
    statement.set_elements([(var_Q_2, Q_2),
                            (var_J_1, J_1),
                            (var_J_2, J_2),
                            (var_J_3, J_3),
                            (var_C, C)
                            ])

    statement.append_equation(
        var_C, [
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3)
        ]
    )

    witness = [secret_prover_blind, msg_1, msg_2, msg_3]
    return statement, witness


def test_and_composition():
    from sagelib.sigma_protocols import SigmaProtocol, SchnorrProof
    from sagelib.fiat_shamir import NISigmaProtocol
    from sagelib.codec import P256Codec
    from sagelib.duplex_sponge import KeccakDuplexSponge
    from sagelib import groups

    class AndProof(SchnorrProof):
        ProverState: list[SchnorrProof.ProverState]

        def __init__(self, instances: list[LinearRelation]):
            self.protocols = [SchnorrProof(instance) for instance in instances]

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

        def serialize_batchable(self, commitments, challenge, responses):
            return b''.join(
                [protocol.serialize_batchable(commitment, challenge, response) for protocol, commitment, response in zip(self.protocols, commitments, responses)]
            )

        def deserialize_batchable(self, proof_string):
            commitments = []
            responses = []
            for protocol in self.protocols:
                proof_len = protocol.instance.commit_bytes_len + protocol.instance.response_bytes_len
                commitment, response = protocol.deserialize_batchable(proof_string[:proof_len])
                proof_string = proof_string[proof_len:]
                commitments.append(commitment)
                responses.append(response)
            return (commitments, responses)

    class P256AndCodec(P256Codec):
        def prover_message(self, hash_state, elements):
            flat_elements = sum(elements, [])
            return super().prover_message(hash_state, flat_elements)

    class NIAndProof(NISigmaProtocol):
        Protocol = AndProof
        Codec = P256AndCodec
        Hash = KeccakDuplexSponge

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
    from sagelib.sigma_protocols import SchnorrProof
    from sagelib.fiat_shamir import NISigmaProtocol
    from sagelib.codec import P256Codec
    from sagelib.duplex_sponge import KeccakDuplexSponge

    class OrProof(SchnorrProof):
        ProverState: list[SchnorrProof.ProverState]

        def __init__(self, instances: list[LinearRelation]):
            self.protocols = [SchnorrProof(instance) for instance in instances]

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

        def serialize_batchable(self, commitments, challenge, _response):
            challenges, responses = _response
            return b''.join(
                    [protocol.serialize_batchable(commitment, challenge, response) for protocol, commitment, response in zip(self.protocols, commitments, responses)] +
                    [protocol.instance.Domain.serialize([challenge]) for (protocol, challenge) in zip(self.protocols[:-1], challenges)]
                )

        def deserialize_batchable(self, proof_string):
            commitments = []
            challenges = []
            responses = []

            start = 0
            for protocol in self.protocols:
                proof_len = protocol.instance.commit_bytes_len + protocol.instance.response_bytes_len
                commitment, response = protocol.deserialize_batchable(proof_string[start : start + proof_len])
                start += proof_len
                commitments.append(commitment)
                responses.append(response)

            # The last part of the proof string is the challenges
            for protocol in self.protocols[:-1]:
                # we should not be needing to inspect Domain here
                challenge_len = protocol.instance.Domain.scalar_byte_length()
                challenge = protocol.instance.Domain.deserialize(proof_string[start : start + challenge_len])
                challenges.append(challenge[0])
                start += challenge_len

            return (commitments, (challenges, responses))


    class P256OrCodec(P256Codec):
        def prover_message(self, hash_state, elements):
            flat_elements = sum(elements, [])
            return super().prover_message(hash_state, flat_elements)

        def verifier_challenge(self, hash_state):
            return super().verifier_challenge(hash_state)

    class NIOrProof(NISigmaProtocol):
        Protocol = OrProof
        Codec = P256OrCodec
        Hash = KeccakDuplexSponge

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


def main(path="vectors"):
    vectors = {}
    test_vectors = [
        discrete_logarithm,
        dleq,
        pedersen_commitment,
        pedersen_commitment_dleq,
        bbs_blind_commitment_computation,
    ]
    for test_vector in test_vectors:
        test_vector(vectors)

    test_and_composition()
    test_or_composition()

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    with open(path + "/allVectors.txt", 'wt') as f:
        for proof_type in vectors:
            write_group_vectors(f, proof_type, vectors[proof_type])


if __name__ == "__main__":
    main()
