NON_COMPRESSABLE_MAX_SIZE = 65535
LZ77_MAX_LOOKBACK = 32 * (2 ** 10)
MAX_DUPLICATED_LENGTH = 258
CODE_END_OF_BLOCK = 256
GZIP_FILE_ID = bytes.fromhex("1f8b")
COMPRESSION_METHOD = b"\x08"
CODE_CODE_ORDER = [
    16,
    17,
    18,
    0,
    8,
    7,
    9,
    6,
    10,
    5,
    11,
    4,
    12,
    3,
    13,
    2,
    14,
    1,
    15,
]

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from io import BufferedIOBase, BytesIO
from math import ceil, floor, log2
from datetime import datetime
from typing import Union
from struct import pack


class BitStream:
    """
    A thin wrapper around a byte stream that allows reading bits instead of bytes.
    """

    def __init__(self, underlying: Union[bytes, BufferedIOBase]):
        if isinstance(underlying, bytes):
            underlying = BytesIO(underlying)
        self.underlying = underlying
        self.num_bits = 0
        self.buffer = 0b00000000

    def _get_buffered_bits(self, n: int) -> int:
        """Return extracted bits as an int."""
        mask = 2 ** n - 1
        out = self.buffer & mask
        self.buffer = self.buffer >> n
        self.num_bits -= n
        return out

    def _buffer_byte(self):
        self.buffer += (
            int.from_bytes(self.underlying.read(1), "big") << self.num_bits
        )
        self.num_bits += 8

    def clear_buffer(self):
        """Useful for ignoring partial bytes"""
        self.num_bits = 0
        self.buffer = 0b00000000

    def read_huffman_bits(self, huffman: "HuffmanEncoding") -> int:
        """Return a value decoded from a Huffman tree, or throw a KeyError if not possible"""
        node = huffman.node
        while node and node.value is None:
            node = node.children.get(self.read(1))
        if not node:
            raise KeyError("stream does not have a valid code")
        return node.value

    def read(self, n: int, prefer_bytes: bool = True) -> Union[bytes, int]:
        if prefer_bytes and not self.num_bits and n % 8 == 0:
            out = b""
            to_read = n // 8
            while to_read:
                out += self.underlying.read(1)
                to_read -= 1
            return out
        if (n + self.num_bits) not in range(33):
            raise ValueError("Cannot buffer more than 32 bits")
        to_get = n
        while self.num_bits < n:
            self._buffer_byte()
        return self._get_buffered_bits(n)

    def write_code(self, n: int, content: int):
        self.write(n, content, prefer_bytes=False)

    def write(self, n: int, content: bytes | int, prefer_bytes: bool = True):
        if isinstance(content, bytes) and n % 8:
            raise ValueError("Cannot write partial byte")
        if prefer_bytes and not self.num_bits and n % 8 == 0:
            for i in range(len(content)):
                self.underlying = BytesIO(
                    self.underlying.getvalue() + content[i : i + 1]
                )
        else:
            while n:
                if isinstance(content, bytes):
                    to_add = int.from_bytes(content[0:1], "big")
                    content = content[1:]
                    num_bits_added = 8
                else:
                    num_bits_added = n % 8 if n != 8 else 8
                    to_add = content & (2 ** (num_bits_added) - 1)
                    content = content >> (num_bits_added)
                self.buffer += to_add << self.num_bits
                self.num_bits += num_bits_added
                n -= num_bits_added
                while self.num_bits >= 8:
                    self.flush_byte()

    def flush_byte(self):
        if self.num_bits:
            self.underlying = BytesIO(
                self.underlying.getvalue() + pack("B", self.buffer & 0xFF)
            )
        self.num_bits = max(0, self.num_bits - 8)
        self.buffer = self.buffer >> 8

    def flush(self):
        while self.buffer:
            self.flush_byte()


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

    def to_bytes(self) -> bytes:
        flags = 0b00000000

        if self.extra_data:
            flags |= 0b100
        if self.filename:
            flags |= 0b1000
        if self.comment:
            flags |= 0b10000
        # if self.crc:
        #     flags |= 0b10
        flags = pack("B", flags)
        xfl = b"\x00"

        header = (
            GZIP_FILE_ID
            + COMPRESSION_METHOD
            + flags
            + pack("<i", int(self.mtime.timestamp()))
            + xfl
            + pack("B", self.os.value)
        )
        if self.extra_data:
            header += pack("<H", len(extra_data)) + extra_data
        if self.filename:
            header += self.filename.encode("latin-1") + b"\x00"
        if self.comment:
            header += self.comment.encode("latin-1") + b"\x00"
        # if self.crc:
        #     header += pack("<H", self.crc)
        return header


class Length:
    MIN_LENGTH = 3
    MAX_LENGTH = 258

    def __init__(self, code: int, additional_content: int | None = None):
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
        self.additional_content = additional_content

    @classmethod
    def from_length(cls, length: int):
        if length not in range(cls.MIN_LENGTH, cls.MAX_LENGTH + 1):
            raise ValueError(
                f"Invalid length {length}. must be in range(3, 259)"
            )
        if length in range(3, 11):
            extra_bits = 0
            min_code = 257
            min_length = 3
        elif length in range(11, 19):
            extra_bits = 1
            min_code = 265
            min_length = 11
        elif length in range(19, 35):
            extra_bits = 2
            min_code = 269
            min_length = 19
        elif length in range(35, 67):
            extra_bits = 3
            min_code = 273
            min_length = 35
        elif length in range(67, 131):
            extra_bits = 4
            min_code = 277
            min_length = 67
        elif length in range(131, 258):
            extra_bits = 5
            min_code = 281
            min_length = 131
        else:
            extra_bits = 0
            min_code = 285
            min_length = 258
        min_code += (length - min_length) // (2 ** extra_bits)
        return cls(min_code, (length - min_length) % (2 ** extra_bits))


class Distance:
    #      Extra           Extra               Extra
    # Code Bits Dist  Code Bits   Dist     Code Bits Distance
    # ---- ---- ----  ---- ----  ------    ---- ---- --------
    #   0   0    1     10   4     33-48    20    9   1025-1536
    #   1   0    2     11   4     49-64    21    9   1537-2048
    #   2   0    3     12   5     65-96    22   10   2049-3072
    #   3   0    4     13   5     97-128   23   10   3073-4096
    #   4   1   5,6    14   6    129-192   24   11   4097-6144
    #   5   1   7,8    15   6    193-256   25   11   6145-8192
    #   6   2   9-12   16   7    257-384   26   12  8193-12288
    #   7   2  13-16   17   7    385-512   27   12 12289-16384
    #   8   3  17-24   18   8    513-768   28   13 16385-24576
    #   9   3  25-32   19   8   769-1024   29   13 24577-32768
    TABLE = {
        range(5, 7): (4, 1),
        range(7, 9): (5, 1),
        range(9, 13): (6, 2),
        range(13, 17): (7, 2),
        range(17, 25): (8, 3),
        range(25, 33): (9, 3),
        range(33, 49): (10, 4),
        range(49, 65): (11, 4),
        range(65, 97): (12, 5),
        range(97, 129): (13, 5),
        range(129, 193): (14, 6),
        range(193, 257): (15, 6),
        range(257, 385): (16, 7),
        range(385, 513): (17, 7),
        range(513, 769): (18, 8),
        range(769, 1025): (19, 8),
        range(1025, 1537): (20, 9),
        range(1537, 2049): (21, 9),
        range(2049, 3073): (22, 10),
        range(3073, 4097): (23, 10),
        range(4097, 6145): (24, 11),
        range(6145, 8193): (25, 11),
        range(8193, 12289): (26, 12),
        range(12289, 16385): (27, 12),
        range(16385, 24577): (28, 13),
        range(24577, 32769): (29, 13),
    }

    def __init__(self, code: int, additional_content: int | None = None):
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
        self.additional_content = additional_content

    @classmethod
    def from_distance(cls, distance: int):
        if distance in range(1, 5):
            return cls(distance - 1)
        else:
            for interval in cls.TABLE:
                if distance in interval:
                    code, _ = cls.TABLE[interval]
                    return cls(code, distance - interval.start)
        raise ValueError(f"Distance {distance} was not in range [3, 32678]")


class CodeCode:
    EXTRA_BITS = {16: 2, 17: 3, 18: 7}
    MIN_LENGTH = {16: 3, 17: 3, 18: 11}

    def __init__(self, code: int):
        if not (16 <= code <= 18):
            raise ValueError("CodeCode must have code where 0 <= code <= 29")
        self.code = code
        self.extra_bits = self.EXTRA_BITS[code]
        self.min_length = self.MIN_LENGTH[code]


class Node:
    def __init__(self):
        self.children = defaultdict(Node)
        self.value = None

    def traverse(self, binary):
        node = self
        for char in binary:
            node = node.children.get(int(char))
        return node


class HuffmanEncoding:

    """
    The Huffman codes used for each alphabet in the "deflate"
    format have two additional rules:

     * All codes of a given bit length have lexicographically
       consecutive values, in the same order as the symbols
       they represent;

     * Shorter codes lexicographically precede longer codes.
    """

    def __init__(self, encoding: list[int], alphabet_code_lengths: list[int]):
        self.encoding = encoding
        self.decode_map = dict([(v, k) for k, v in enumerate(self.encoding)])
        self.alphabet_code_lengths = alphabet_code_lengths

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
        # if not all(alphabet_code_lengths):
        #     raise ValueError("Invalid Huffman code with bit length of 0")
        # Count the number of codes for each code length.  Let
        # bl_count[N] be the number of codes of length N, N >= 1.
        counts_by_length = defaultdict(int, Counter(alphabet_code_lengths))
        # Find the numerical value of the smallest code for each code length
        next_code = dict()
        code = 0
        if 0 in counts_by_length:
            del counts_by_length[0]
        for bits in range(1, max(counts_by_length) + 1):
            code = (code + counts_by_length[bits - 1]) << 1
            next_code[bits] = code
        # Assign numerical values to all codes, using consecutive
        # values for all codes of the same length with the base
        # values determined at step 2. Codes that are never used
        # (which have a bit length of zero) must not be assigned a
        # value.
        root = node = Node()
        alphabet_encode_map = [0] * len(alphabet_code_lengths)
        for letter_num in range(len(alphabet_code_lengths)):
            code_length = alphabet_code_lengths[letter_num]
            if code_length == 0:
                continue
            alphabet_encode_map[letter_num] = next_code[code_length]
            binary = format(
                alphabet_encode_map[letter_num], f"0{code_length}b"
            )
            node = root
            for char in binary:
                node = node.children[int(char)]
            node.value = letter_num
            alphabet_encode_map[letter_num] = binary
            next_code[code_length] += 1
        base = cls(alphabet_encode_map, alphabet_code_lengths)
        base.node = root
        return base


STATIC_LEN_CODES = HuffmanEncoding.from_alphabet_code_lengths(
    [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
)
STATIC_DIST_CODES = HuffmanEncoding.from_alphabet_code_lengths([5] * 32)
