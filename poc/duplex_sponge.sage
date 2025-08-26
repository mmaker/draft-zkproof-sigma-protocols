
from abc import ABC, abstractmethod
import struct
import hashlib
from keccak import Keccak


class DuplexSpongeInterface(ABC):
    """
    The duplex sponge interface defines the space (the `Unit`) where the hash function operates in,
    plus a function for absorbing and squeezing prover messages.
    """
    Unit = None

    @abstractmethod
    def __init__(self, iv: bytes):
        raise NotImplementedError

    @abstractmethod
    def absorb(self, x: list[Unit]):
        raise NotImplementedError

    @abstractmethod
    def squeeze(self, length: int):
        raise NotImplementedError


class SHAKE128(DuplexSpongeInterface):
    """
    The SHAKE128 implementation of the duplex sponge interface
    using python's standard library.
    """
    def __init__(self, iv: bytes):
        assert len(iv) == 64
        # Only the initial 64 bytes of the first block are used,
        # the remaining ones are reserved for future use.
        initial_block = iv + b'\00' * (168-64)
        self.hash_state = hashlib.shake_128()
        self.hash_state.update(initial_block)

    def absorb(self, x: bytes):
        self.hash_state.update(x)

    def squeeze(self, length: int) -> bytes:
        return self.hash_state.copy().digest(length)


class KeccakPermutationState:
    # rate
    R = 136
    # rate + capacity = sponge length
    N = 136 + 64

    def __init__(self, iv: bytes):
        assert len(iv) == 64
        self.state = bytearray(200)
        self.state[self.R: self.R + 64] = iv
        self.p = Keccak(1600)

    def __getitem__(self, i):
        return self.state[i]

    def __setitem__(self, i, value):
        self.state[i] = value

    def __len__(self):
        return len(self.state)

    def _keccak_state_to_bytes(self, state):
        flat = [0]*25
        for y in range(5):
            for x in range(5):
                flat[5*y + x] = state[x][y]
        packed = struct.pack('<25Q', *flat)
        return bytearray(packed)

    def _bytes_to_keccak_state(self):
        flat = struct.unpack('<25Q', bytes(self.state))
        A = [[0]*5 for _ in range(5)]
        for y in range(5):
            for x in range(5):
                A[x][y] = flat[5*y + x]
        return A

    def permute(self):
        state = self._bytes_to_keccak_state()
        new_state = self.p.KeccakF(state)
        self.state = self._keccak_state_to_bytes(new_state)


class DuplexSponge(DuplexSpongeInterface):
    permutation_state = None

    def __init__(self, iv: bytes):
        assert len(iv) == 64
        self.absorb_index = 0
        self.squeeze_index = self.permutation_state.R
        self.rate = self.permutation_state.R
        self.capacity = self.permutation_state.N - self.permutation_state.R

    def absorb(self, input: bytes):
        self.squeeze_index = self.rate

        while len(input) != 0:
            if self.absorb_index == self.rate:
                self.permutation_state.permute()
                self.absorb_index = 0

            chunk_size = min(self.rate - self.absorb_index, len(input))
            next_chunk = input[:chunk_size]
            self.permutation_state[self.absorb_index:
                                   self.absorb_index + chunk_size] = next_chunk
            self.absorb_index += chunk_size
            input = input[chunk_size:]

    def squeeze(self, length: int):
        output = b''
        while length != 0:
            if self.squeeze_index == self.rate:
                self.permutation_state.permute()
                self.squeeze_index = 0
                self.absorb_index = 0

            chunk_size = min(self.rate - self.squeeze_index, length)
            output += bytes(
                self.permutation_state[self.squeeze_index:self.squeeze_index + chunk_size]
            )
            self.squeeze_index += chunk_size
            length -= chunk_size

        return output


class KeccakDuplexSponge(DuplexSponge):
    def __init__(self, iv: bytes):
        self.permutation_state = KeccakPermutationState(iv)
        super().__init__(iv)


if __name__ == "__main__":
    # Example usage
    iv = b'\0' * 64  # Initialization vector
    sponge = SHAKE128(iv)
    sponge.absorb(b'hello!')
    output = sponge.squeeze(64)
    print(output.hex())  # Output the squeezed bytes in hex format