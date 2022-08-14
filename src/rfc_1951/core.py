NON_COMPRESSABLE_MAX_SIZE = 65535
LZ77_MAX_LOOKBACK = 32 * (2 ** 10)
MAX_DUPLICATED_LENGTH = 258
CODE_END_OF_BLOCK = 256
GZIP_FILE_ID = bytes.fromhex("1f8b")
COMPRESSION_METHOD = b"\x08"

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from math import ceil
from datetime import datetime


class BlockType(Enum):
    NO_COMPRESSION = 0b00
    FIXED_HUFFMAN_COMPRESSION = 0b01
    DYNAMIC_HUFFMAN_COMPRESSION = 0b10
    RESERVED_ERROR = 0b11


class OS(Enum):
    FAT_FILESYSTEM = 0
    AMIGA = 1
    VMS = 2
    UNIX = 3
    VM_CMS = 4
    ATARI_TOS = 5
    HPFS_FILESYSTEM = 6
    MACINTOSH = 7
    Z_SYSTEM = 8
    CP_M = 9
    TOPS_20 = 10
    NTFS_FILESYSTEM = 11
    QDOS = 12
    ACORN_RISCOS = 13
    UNKNOWN = 255


@dataclass
class BlockHeader:
    is_final: bool
    block_type: BlockType


@dataclass
class FileHeader:
    os: OS
    mtime: datetime
    extra_data: bytes | None = None
    filename: str | None = None
    comment: str | None = None
    crc: int | None = None


class Length:
    def __init__(self, code: int):
        if not (257 <= code <= 285):
            raise ValueError("Length must have code where 257 <= code <= 285")
        self.code = code
        if code in range(257, 265):
            self.extra_bits = 0
            self.min_length = 3 + (code - 257) * (2 ** self.extra_bits)
        elif code in range(265, 269):
            self.extra_bits = 1
            self.min_length = 11 + (code - 265) * (2 ** self.extra_bits)
        elif code in range(269, 273):
            self.extra_bits = 2
            self.min_length = 19 + (code - 269) * (2 ** self.extra_bits)
        elif code in range(273, 277):
            self.extra_bits = 3
            self.min_length = 35 + (code - 273) * (2 ** self.extra_bits)
        elif code in range(277, 281):
            self.extra_bits = 4
            self.min_length = 67 + (code - 277) * (2 ** self.extra_bits)
        elif code in range(281, 285):
            self.extra_bits = 5
            self.min_length = 131 + (code - 281) * (2 ** self.extra_bits)
        else:
            self.extra_bits = 0
            self.min_length = 258


class Distance:
    def __init__(self, code: int):
        if not (0 <= code <= 29):
            raise ValueError("Distance must have code where 0 <= code <= 29")
        self.code = code
        self.extra_bits = max(0, 1 + (code - 4) // 2)
        if code in range(0, 4):
            self.min_distance = code + 1
        else:
            self.min_distance = (
                1
                + 2 ** (self.extra_bits + 1)
                + (2 ** (self.extra_bits) if code % 2 else 0)
            )


class HuffmanEncoding:
    """
    The Huffman codes used for each alphabet in the "deflate"
    format have two additional rules:

     * All codes of a given bit length have lexicographically
       consecutive values, in the same order as the symbols
       they represent;

     * Shorter codes lexicographically precede longer codes.
    """

    def __init__(self, encoding: list[int]):
        self.encoding = encoding

    @classmethod
    def from_alphabet_code_lengths(cls, alphabet_code_lengths: list[int]):
        """
        Given the additional lexicographical rules, we can define the Huffman code for an alphabet
        just by giving the bit lengths of the codes for each symbol of
        the alphabet in order; this is sufficient to determine the
        actual codes.
        For example (2, 1, 3, 3), completely defines the following encoding on the alphabet "ABCD":

           Symbol  Code
           ------  ----
           A       10
           B       0
           C       110
           D       111

        """
        if not all(alphabet_code_lengths):
            raise ValueError("Invalid Huffman code with bit length of 0")
        # Count the number of codes for each code length.  Let
        # bl_count[N] be the number of codes of length N, N >= 1.
        counts_by_length = defaultdict(int, Counter(alphabet_code_lengths))
        # Find the numerical value of the smallest code for each code length
        next_code = dict()
        code = 0
        for bits in range(1, max(counts_by_length) + 1):
            code = (code + counts_by_length[bits - 1]) << 1
            next_code[bits] = code
        # Assign numerical values to all codes, using consecutive
        # values for all codes of the same length with the base
        # values determined at step 2. Codes that are never used
        # (which have a bit length of zero) must not be assigned a
        # value.
        alphabet_encode_map = [0] * len(alphabet_code_lengths)
        for letter_num in range(len(alphabet_code_lengths)):
            code_length = alphabet_code_lengths[letter_num]
            alphabet_encode_map[letter_num] = next_code[code_length]
            next_code[code_length] += 1
        return cls(alphabet_encode_map)
