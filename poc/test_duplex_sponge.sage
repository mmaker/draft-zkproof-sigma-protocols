#!/usr/bin/sage
# vim: syntax=python

from sagelib.duplex_sponge import KeccakDuplexSponge
import json

def run_operations(tag, operations):
    """Execute a sequence of operations on a sponge and return the final output"""
    sponge = KeccakDuplexSponge(tag)
    output = None

    for op in operations:
        if op["type"] == "absorb":
            data = bytes.fromhex(op["data"]) if op["data"] else b""
            sponge.absorb(data)
        elif op["type"] == "squeeze":
            output = sponge.squeeze(op["length"])

    return output

def test_vector(test_vector_function):
    def inner(vectors):
        test_vector_name = f"{test_vector_function.__name__}"
        test_data = test_vector_function()
        test_data["HashFunction"] = "Keccak-f[1600] overwrite mode"
        vectors[test_vector_name] = test_data
        print(f"{test_vector_name} test vector generated\n")
    return inner

@test_vector
def test_keccak_duplex_sponge():
    """Basic test of Keccak duplex sponge"""
    tag = b"unit_tests_keccak_tag___________"
    operations = [
        {"type": "absorb", "data": b"Hello, World!".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_before_does_not_break():
    """Test absorbing empty message after actual message"""
    tag = b"unit_tests_keccak_tag___________"
    operations = [
        {"type": "absorb", "data": b"Hello, World!".hex()},
        {"type": "absorb", "data": ""},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_after_does_not_break():
    """Test absorbing empty message before actual message"""
    tag = b"unit_tests_keccak_tag___________"
    operations = [
        {"type": "absorb", "data": ""},
        {"type": "absorb", "data": b"Hello, World!".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_behavior():
    """Test squeezing zero bytes between operations"""
    tag = b"unit_tests_keccak_tag___________"
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"Hello, World!".hex()},
        {"type": "squeeze", "length": int(0)},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_after_behavior():
    """Test squeezing zero bytes after operations"""
    tag = b"unit_tests_keccak_tag___________"
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"Hello, World!".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_squeeze_absorb_consistency():
    """Test interleaving absorb and squeeze operations"""
    tag = b"edge-case-test-domain-absorb0000"
    operations = [
        {"type": "absorb", "data": b"first".hex()},
        {"type": "squeeze", "length": int(32)},
        {"type": "absorb", "data": b"second".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output = run_operations(tag, operations)
    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_associativity_of_absorb():
    """Test that absorbing data is associative"""
    tag = b"absorb-associativity-domain-----"
    expected = bytes.fromhex("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58")

    # Test case 1: absorb all at once
    operations1 = [
        {"type": "absorb", "data": b"hello world".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out1 = run_operations(tag, operations1)
    assert out1 == expected

    # Test case 2: absorb in parts
    operations2 = [
        {"type": "absorb", "data": b"hello".hex()},
        {"type": "absorb", "data": b" world".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out2 = run_operations(tag, operations2)
    assert out2 == expected

    return {
        "Tag": tag.hex(),
        "Operations": operations1,
        "Expected": out1.hex()
    }

@test_vector
def test_tag_affects_output():
    """Test that different tags produce different outputs"""
    tag1 = b"domain-one-differs-here-00000000"
    tag2 = b"domain-two-differs-here-00000000"

    operations = [
        {"type": "absorb", "data": b"input".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output1 = run_operations(tag1, operations)
    output2 = run_operations(tag2, operations)

    expected1 = bytes.fromhex("2ecad63584ec0ff7f31edb822530762e5cb4b7dc1a62b1ffe02c43f3073a61b8")
    expected2 = bytes.fromhex("6310fa0356e1bab0442fa19958e1c4a6d1dcc565b2b139b6044d1a809f531825")

    assert output1 == expected1
    assert output2 == expected2

    return {
        "Tag": tag1.hex(),
        "Operations": operations,
        "Expected": output1.hex()
    }

@test_vector
def test_multiple_blocks_absorb_squeeze():
    """Test absorbing and squeezing multiple blocks"""
    tag = b"multi-block-absorb-test_________"
    input_data = bytes([0xAB] * (3 * 200))

    operations = [
        {"type": "absorb", "data": input_data.hex()},
        {"type": "squeeze", "length": int(3 * 200)}
    ]

    output = run_operations(tag, operations)
    expected_output = bytes.fromhex(
        "606310f839e763f4f37ce4c9730da92d4d293109de06abee8a7b40577125bcbfca331b97aee104d03139247e801d8b1a5f6b028b8e51fd643de790416819780a1235357db153462f78c150e34f29a303288f07f854e229aed41c786313119a1cee87402006ab5102271576542e5580be1927af773b0f1b46ce5c78c15267d3729928909192ea0115fcb9475b38a1ff5004477bbbb1b1f5c6a5c90c29b245a83324cb108133efc82216d33da9866051d93baab3bdf0fe02b007d4eb94885a42fcd02a9acdd47b71b6eeac17f5946367d6c69c95cbb80ac91d75e22c9862cf5fe10c7e121368e8a8cd9ff8eebe21071ff014e053725bcc624cd9f31818c4d049e70c14a22e5d3062a553ceca6157315ef2bdb3619c970c9c3d60817ee68291dcd17a282ed1b33cb3afb79c8247cd46de13add88da4418278c8b6b919914be5379daa823b036da008718c1d2a4a0768ecdf032e2b93c344ff65768c8a383a8747a1dcc13b5569b4e15cab9cc8f233fb28b13168284c8a998be6f8fa05389ff9c1d90c5845060d2df3fe0a923be8603abbd2b6f6dd6a5c09c81afe7c06bec789db87185297d6f7261f1e5637f2d140ff3b306df77f42cceffe769545ea8b011022387cd9e3d4f2c97feff5099139715f72301799fcfd59aa30f997e26da9eb7d86ee934a3f9c116d4a9e1012d795db35e1c61d27cd74bb6002f463fc129c1f9c4f25bc8e79c051ac2f1686e393d670f8d1e4cea12acfbff5a135623615d69a88f390569f17a0fc65f5886e2df491615155d5c3eb871209a5c7b0439585ad1a0acbede2e1a8d5aad1d8f3a033267e12185c5f2bbab0f2f1769247"
    )

    assert output == expected_output

    return {
        "Tag": tag.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

def main(path="vectors"):
    vectors = {}
    test_vectors = [
        test_keccak_duplex_sponge,
        test_absorb_empty_before_does_not_break,
        test_absorb_empty_after_does_not_break,
        test_squeeze_zero_behavior,
        test_squeeze_zero_after_behavior,
        test_absorb_squeeze_absorb_consistency,
        test_associativity_of_absorb,
        test_tag_affects_output,
        test_multiple_blocks_absorb_squeeze,
    ]

    print("Generating duplex sponge test vectors...\n")

    for test_fn in test_vectors:
        test_fn(vectors)

    with open(path + "/duplexSpongeVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    print(f"Test vectors written to {path}/duplexSpongeVectors.json")

if __name__ == "__main__":
    main()