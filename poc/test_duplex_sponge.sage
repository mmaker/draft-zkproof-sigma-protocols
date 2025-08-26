#!/usr/bin/sage
# vim: syntax=python

from sagelib.duplex_sponge import KeccakDuplexSponge, SHAKE128
import json

def run_operations(iv, operations, DuplexSponge):
    """Execute a sequence of operations on a sponge and return the final output"""
    sponge = DuplexSponge(iv)
    output = None

    for op in operations:
        if op["type"] == "absorb":
            data = bytes.fromhex(op["data"]) if op["data"] else b""
            sponge.absorb(data)
        elif op["type"] == "squeeze":
            output = sponge.squeeze(op["length"])

    return output

def test_vector(test_vector_function):
    def inner(vectors, hash_function, DuplexSponge):
        # Create unique test vector name based on function name and hash function
        hash_suffix = "Keccak" if "Keccak" in hash_function else "SHAKE128"
        test_vector_name = f"{test_vector_function.__name__}_{hash_suffix}"
        
        # Create a run_operations function bound to this specific DuplexSponge
        def bound_run_operations(iv, operations):
            return run_operations(iv, operations, DuplexSponge)
        
        # Pass the bound function to the test
        test_data = test_vector_function(bound_run_operations)
        test_data["HashFunction"] = hash_function
        vectors[test_vector_name] = test_data
        print(f"{test_vector_name} test vector generated\n")
    return inner

@test_vector
def test_keccak_duplex_sponge(run_ops):
    """Basic test of Keccak duplex sponge"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"basic duplex sponge test".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_before_does_not_break(run_ops):
    """Test absorbing empty message after actual message"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"empty message after".hex()},
        {"type": "absorb", "data": ""},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_empty_after_does_not_break(run_ops):
    """Test absorbing empty message before actual message"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": ""},
        {"type": "absorb", "data": b"empty message before".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_behavior(run_ops):
    """Test squeezing zero bytes between operations"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"zero squeeze test".hex()},
        {"type": "squeeze", "length": int(0)},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_squeeze_zero_after_behavior(run_ops):
    """Test squeezing zero bytes after operations"""
    iv = b"unit_tests_keccak_iv".ljust(64, b'\x00')
    operations = [
        {"type": "squeeze", "length": int(0)},
        {"type": "absorb", "data": b"zero squeeze after".hex()},
        {"type": "squeeze", "length": int(64)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_absorb_squeeze_absorb_consistency(run_ops):
    """Test interleaving absorb and squeeze operations"""
    iv = b"edge-case-test-domain-absorb".ljust(64, b'\x00')
    operations = [
        {"type": "absorb", "data": b"interleave first".hex()},
        {"type": "squeeze", "length": int(32)},
        {"type": "absorb", "data": b"interleave second".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
        "Operations": operations,
        "Expected": output.hex()
    }

@test_vector
def test_associativity_of_absorb(run_ops):
    """Test that absorbing data is associative"""
    iv = b"absorb-associativity-domain".ljust(64, b'\x00')

    # Test case 1: absorb all at once
    operations1 = [
        {"type": "absorb", "data": b"associativity test full".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out1 = run_ops(iv, operations1)

    # Test case 2: absorb in parts
    operations2 = [
        {"type": "absorb", "data": b"associativity".hex()},
        {"type": "absorb", "data": b" test split".hex()},
        {"type": "squeeze", "length": int(32)}
    ]
    out2 = run_ops(iv, operations2)
    assert out2 == out2

    return {
        "IV": iv.hex(),
        "Operations": operations1,
        "Expected": out1.hex()
    }

@test_vector
def test_iv_affects_output(run_ops):
    """Test that different IVs produce different outputs"""
    iv1 = b"domain-one-differs-here".ljust(64, b'\x00')
    iv2 = b"domain-two-differs-here".ljust(64, b'\x00')

    operations = [
        {"type": "absorb", "data": b"iv difference test".hex()},
        {"type": "squeeze", "length": int(32)}
    ]

    output1 = run_ops(iv1, operations)
    output2 = run_ops(iv2, operations)
    assert output1 != output2

    return {
        "IV": iv1.hex(),
        "Operations": operations,
        "Expected": output1.hex()
    }

@test_vector
def test_multiple_blocks_absorb_squeeze(run_ops):
    """Test absorbing and squeezing multiple blocks"""
    iv = b"multi-block-absorb-test".ljust(64, b'\x00')
    input_data = bytes([0xAB] * (3 * 200))

    operations = [
        {"type": "absorb", "data": input_data.hex()},
        {"type": "squeeze", "length": int(3 * 200)}
    ]

    output = run_ops(iv, operations)
    return {
        "IV": iv.hex(),
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
        test_iv_affects_output,
        test_multiple_blocks_absorb_squeeze,
    ]

    hash_functions = {
        "Keccak-f[1600] overwrite mode": KeccakDuplexSponge,
        "SHAKE128": SHAKE128
    }

    print("Generating duplex sponge test vectors...\n")

    for hash_function, DuplexSponge in hash_functions.items():
        for test_fn in test_vectors:
            test_fn(vectors, hash_function, DuplexSponge)

    with open(path + "/duplexSpongeVectors.json", 'wt') as f:
        json.dump(vectors, f, sort_keys=True, indent=2)

    print(f"Test vectors written to {path}/duplexSpongeVectors.json")

if __name__ == "__main__":
    main()