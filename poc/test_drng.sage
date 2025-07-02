#!/usr/bin/sage
# vim: syntax=python

import random
import hashlib


class TestDRNG(object):
    def __init__(self, seed):
        seed_bytes = hashlib.sha256(seed).digest()
        for elem in seed_bytes:
            print(elem)
        self.seed = int.from_bytes(hashlib.sha256(seed).digest(), 'big')

    def randint(self, l, h):
        random.seed(self.seed)
        val = random.randint(l, h)
        self.seed = int.from_bytes(hashlib.sha256(
            int(val % 2^32).to_bytes(4, 'big')).digest(), 'big')
        return val
