#!/usr/bin/sage
# vim: syntax=python

import hashlib

class TestDRNG:
    def __init__(self, seed: bytes):
        assert isinstance(seed, bytes) and len(seed) > 0
        self.seed = hashlib.sha256(seed).digest()

    def next_u32(self) -> int:
        val = int.from_bytes(self.seed[:4], 'big')
        self.seed = hashlib.sha256(val.to_bytes(4, 'big')).digest()
        return val

    def fill_bytes(self, n_bytes: int) -> bytes:
        result = bytearray()
        while len(result) < n_bytes:
            val = self.next_u32()
            result.extend(val.to_bytes(4, 'big'))
        return bytes(result[:n_bytes])

    def randint(self, l: int, h: int) -> int:
        assert l <= h
        range_size = h - l + 1
        n_bits = range_size.bit_length()
        n_bytes = (n_bits + 7) // 8
        while True:
            rand_bytes = self.fill_bytes(n_bytes)
            val = int.from_bytes(rand_bytes, 'big')
            if val < (1 << n_bits):
                return l + (val % range_size)