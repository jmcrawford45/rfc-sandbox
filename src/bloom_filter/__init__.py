# in practice, a more efficient non-secure hash could be used
# if you know callers aren't malicious
from hashlib import sha256
from math import ceil, log2, log
from typing import Iterator


class BloomFilter:
    def __init__(self, expected_capacity=100, error_rate=0.01):
        self.num_hash_functions = ceil(-1 * log2(error_rate))
        # Round up to nearest power of two to ensure uniform distribution
        self.digest_prefix_len = ceil(
            1 + log2(-1 * expected_capacity * log(error_rate) / (log(2) ** 2))
        )
        # Round up to a byte boundary
        self.digest_prefix_len = ceil(self.digest_prefix_len / 8)
        self.bit_array_len = int(2 ** (self.digest_prefix_len * 8))
        self.array = [False] * self.bit_array_len

    def indices(self, elem: bytes) -> Iterator[bytes]:
        for i in range(self.num_hash_functions):
            m = sha256()
            m.update(str(i).encode() + elem)
            digest = m.digest()
            yield int.from_bytes(digest[: self.digest_prefix_len], "big")

    def add(self, elem: bytes) -> None:
        for index in self.indices(elem):
            self.array[index] = True

    def contains(self, elem: bytes) -> bool:
        for index in self.indices(elem):
            if not self.array[index]:
                return False
        return True
