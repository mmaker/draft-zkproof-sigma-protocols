#!/usr/bin/sage
# vim: syntax=python

import unittest
from sagelib.duplex_sponge import KeccakDuplexSponge
import binascii

class TestKeccakDuplexSponge(unittest.TestCase):
    def test_keccak_duplex_sponge(self):
        sponge = KeccakDuplexSponge(b"unit_tests_keccak_tag___________")
        sponge.absorb(b"Hello, World!")
        output = sponge.squeeze(64)

        expected = binascii.unhexlify("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c")
        self.assertEqual(output, expected)

    def test_absorb_empty_before_does_not_break(self):
        sponge = KeccakDuplexSponge(b"unit_tests_keccak_tag___________")
        sponge.absorb(b"Hello, World!")
        sponge.absorb(b"")
        output = sponge.squeeze(64)

        expected = binascii.unhexlify("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c")
        self.assertEqual(output, expected)

    def test_absorb_empty_after_does_not_break(self):
        sponge = KeccakDuplexSponge(b"unit_tests_keccak_tag___________")
        sponge.absorb(b"")
        sponge.absorb(b"Hello, World!")
        output = sponge.squeeze(64)

        expected = binascii.unhexlify("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c")
        self.assertEqual(output, expected)

    def test_squeeze_zero_behavior(self):
        sponge = KeccakDuplexSponge(b"unit_tests_keccak_tag___________")
        sponge.squeeze(0)
        sponge.absorb(b"Hello, World!")
        sponge.squeeze(0)
        output = sponge.squeeze(64)

        expected = binascii.unhexlify("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c")
        self.assertEqual(output, expected)

    def test_squeeze_zero_after_behavior(self):
        sponge = KeccakDuplexSponge(b"unit_tests_keccak_tag___________")
        sponge.squeeze(0)
        sponge.absorb(b"Hello, World!")
        output = sponge.squeeze(64)

        expected = binascii.unhexlify("73e4a040a956f57693fb2b2dde8a8ea2c14d39ff8830060cd0301d6de25b2097ba858efedeeb89368eaf7c94a68f62835f932b5f0dd0ba376c48a0fdb5e21f0c")
        self.assertEqual(output, expected)

    def test_absorb_squeeze_absorb_consistency(self):
        sponge = KeccakDuplexSponge(b"edge-case-test-domain-absorb0000")
        sponge.absorb(b"first")
        sponge.squeeze(32)
        sponge.absorb(b"second")
        output = sponge.squeeze(32)

        expected = binascii.unhexlify("20ce6da64ffc09df8de254222c068358da39d23ec43e522ceaaa1b82b90c8b9a")
        self.assertEqual(output, expected)

    def test_associativity_of_absorb(self):
        tag = b"absorb-associativity-domain-----"
        expected = binascii.unhexlify("7dfada182d6191e106ce287c2262a443ce2fb695c7cc5037a46626e88889af58")

        sponge1 = KeccakDuplexSponge(tag)
        sponge1.absorb(b"hello world")
        out1 = sponge1.squeeze(32)

        sponge2 = KeccakDuplexSponge(tag)
        sponge2.absorb(b"hello")
        sponge2.absorb(b" world")
        out2 = sponge2.squeeze(32)

        self.assertEqual(out1, expected)
        self.assertEqual(out2, expected)

    def test_tag_affects_output(self):
        sponge1 = KeccakDuplexSponge(b"domain-one-differs-here-00000000")
        sponge2 = KeccakDuplexSponge(b"domain-two-differs-here-00000000")

        sponge1.absorb(b"input")
        output1 = sponge1.squeeze(32)

        sponge2.absorb(b"input")
        output2 = sponge2.squeeze(32)

        expected1 = binascii.unhexlify("2ecad63584ec0ff7f31edb822530762e5cb4b7dc1a62b1ffe02c43f3073a61b8")
        expected2 = binascii.unhexlify("6310fa0356e1bab0442fa19958e1c4a6d1dcc565b2b139b6044d1a809f531825")

        self.assertEqual(output1, expected1)
        self.assertEqual(output2, expected2)

    def test_multiple_blocks_absorb_squeeze(self):
        sponge = KeccakDuplexSponge(b"multi-block-absorb-test_________")
        
        input_data = bytes([0xAB] * (3 * 200))
        expected_output = binascii.unhexlify(
            "606310f839e763f4f37ce4c9730da92d4d293109de06abee8a7b40577125bcbfca331b97aee104d03139247e801d8b1a5f6b028b8e51fd643de790416819780a1235357db153462f78c150e34f29a303288f07f854e229aed41c786313119a1cee87402006ab5102271576542e5580be1927af773b0f1b46ce5c78c15267d3729928909192ea0115fcb9475b38a1ff5004477bbbb1b1f5c6a5c90c29b245a83324cb108133efc82216d33da9866051d93baab3bdf0fe02b007d4eb94885a42fcd02a9acdd47b71b6eeac17f5946367d6c69c95cbb80ac91d75e22c9862cf5fe10c7e121368e8a8cd9ff8eebe21071ff014e053725bcc624cd9f31818c4d049e70c14a22e5d3062a553ceca6157315ef2bdb3619c970c9c3d60817ee68291dcd17a282ed1b33cb3afb79c8247cd46de13add88da4418278c8b6b919914be5379daa823b036da008718c1d2a4a0768ecdf032e2b93c344ff65768c8a383a8747a1dcc13b5569b4e15cab9cc8f233fb28b13168284c8a998be6f8fa05389ff9c1d90c5845060d2df3fe0a923be8603abbd2b6f6dd6a5c09c81afe7c06bec789db87185297d6f7261f1e5637f2d140ff3b306df77f42cceffe769545ea8b011022387cd9e3d4f2c97feff5099139715f72301799fcfd59aa30f997e26da9eb7d86ee934a3f9c116d4a9e1012d795db35e1c61d27cd74bb6002f463fc129c1f9c4f25bc8e79c051ac2f1686e393d670f8d1e4cea12acfbff5a135623615d69a88f390569f17a0fc65f5886e2df491615155d5c3eb871209a5c7b0439585ad1a0acbede2e1a8d5aad1d8f3a033267e12185c5f2bbab0f2f1769247"
        )

        sponge.absorb(input_data)
        output = sponge.squeeze(3 * 200)

        self.assertEqual(output, expected_output)

if __name__ == "__main__":
    unittest.main()