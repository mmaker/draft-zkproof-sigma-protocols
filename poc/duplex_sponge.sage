
from abc import ABC, abstractmethod
import struct
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


class KeccakPermutationState:
    # rate
    R = 136
    # rate + capacity = sponge length
    N = 136 + 64

    def __init__(self):
        self.state = bytearray(200)
        self.p = Keccak(1600)

    def __getitem__(self, i):
        return self.state[i]

    def __setitem__(self, i, value):
        self.state[i] = value

    def __len__(self):
        return len(self.state)

    def _keccak_state_to_bytes(self, state):
        flattened_matrix = [val for row in state for val in row]
        result = struct.pack('<25Q', *flattened_matrix)
        return bytearray(result)

    def _bytes_to_keccak_state(self, byte_array):
        flat_state = list(struct.unpack('<25Q', byte_array))
        return [flat_state[i:i+5] for i in range(0, 25, 5)]

    def permute(self):
        state = self._bytes_to_keccak_state(bytearray(self.state))
        new_state = self.p.KeccakF(state)
        self.state = self._keccak_state_to_bytes(new_state)


class DuplexSponge(DuplexSpongeInterface):
    permutation_state = None

    def __init__(self, iv: bytes):
        assert len(iv) == 32
        self.absorb_index = 0
        self.squeeze_index = 0
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
        self.absorb_index = self.rate

        output = b''
        while length != 0:
            if self.squeeze_index == self.rate:
                self.permutation_state.permute()
                self.squeeze_index = 0

            chunk_size = min(self.rate - self.squeeze_index, length)
            self.squeeze_index += chunk_size
            length -= chunk_size
            output += bytes(
                self.permutation_state[self.squeeze_index:self.squeeze_index+chunk_size])
        return output


class KeccakDuplexSponge(DuplexSponge):
    def __init__(self, iv: bytes):
        self.permutation_state = KeccakPermutationState()
        super().__init__(iv)
