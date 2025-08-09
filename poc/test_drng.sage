#!/usr/bin/sage
# vim: syntax=python

import random
import hashlib


class TestDRNG(object):
    def __init__(self, seed):
        self.seed = hashlib.sha256(seed).digest()

    def next_u32(self):
        val = int.from_bytes([self.seed[0], self.seed[1], self.seed[2], self.seed[3]], byteorder = 'big')
        self.seed = hashlib.sha256(val.to_bytes(4, 'big')).digest()
        return val

    def randint(self, l, h):
        rand_range = h - l
        num_bits = len(bin(rand_range)) - 2
        num_bytes = (num_bits + 7) // 8
        while True:
            i = 0 
            ret_bytes = []
            while i < num_bytes:
                rand = self.next_u32()
                for b in rand.to_bytes(4, 'big'):
                    if i < num_bytes:
                        ret_bytes.append(b)
                        i += 1
                    else:
                        break
            potential_res = int.from_bytes(ret_bytes, byteorder = 'big')
            if (len(bin(potential_res)) - 2) <= num_bits:
                return l + (potential_res % rand_range)
