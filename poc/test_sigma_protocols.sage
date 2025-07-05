#!/usr/bin/sage
# vim: syntax=python

from sagelib.test_drng import TestDRNG
from sagelib.sigma_protocols import LinearRelation
import json

CONTEXT_STRING = b'yellow submarine' * 2


def test_vector(test_vector_function):
    from sagelib.ciphersuite import NISchnorrProofKeccakDuplexSpongeBls12381 as NIZK

    def inner(vectors):
        rng = TestDRNG(b'hello world')
        test_vector_name = f"{test_vector_function.__name__}"

        instance, witness = test_vector_function(rng, NIZK.Codec.GG)
        narg_string = NIZK(CONTEXT_STRING, instance).prove(witness, rng)
        assert NIZK(CONTEXT_STRING, instance).verify(narg_string)
        hex_narg_string = narg_string.hex()
        print(f"{test_vector_name} narg_string: {hex_narg_string}\n")

        vectors[test_vector_name] = {
            "Ciphersuite": "sigma/OWKeccak1600+Bls12381",
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


    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    with open(path + "/allVectors.txt", 'wt') as f:
        for proof_type in vectors:
            write_group_vectors(f, proof_type, vectors[proof_type])


if __name__ == "__main__":
    main()
