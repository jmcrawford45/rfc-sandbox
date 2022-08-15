import sys

import pytest

from rfc_1951.core import *
from rfc_1951.decompress import *

from struct import pack
from datetime import datetime

VALID_FILE_HEADER = "1f8b08083ed0675b000348656c6c6f2e7363616c6100cb4f"

@pytest.mark.parametrize(
    "input_stream,expected",
    [
        (
            BitStream(BytesIO(0b00000001 .to_bytes(1, "big"))),
            BlockHeader(True, BlockType.NO_COMPRESSION),
        ),
        (
            BitStream(BytesIO(0b00000100.to_bytes(1, "big"))),
            BlockHeader(False, BlockType.DYNAMIC_HUFFMAN_COMPRESSION),
        ),
        (
            BitStream(BytesIO(0b00000011.to_bytes(1, "big"))),
            BlockHeader(True, BlockType.FIXED_HUFFMAN_COMPRESSION),
        ),
        (
            BitStream(BytesIO(0b00000110.to_bytes(1, "big"))),
            BlockHeader(False, BlockType.RESERVED_ERROR),
        ),
    ],
)
def test_get_block_header(input_stream, expected):
    assert get_block_header(input_stream) == expected


def test_get_file_header_valid():
    hello_dot_scala = BytesIO(bytes.fromhex(VALID_FILE_HEADER))
    header = get_file_header(BitStream(hello_dot_scala))
    assert header == FileHeader(
        os=OS.UNIX,
        mtime=datetime(2018, 8, 5, 23, 36, 14),
        filename="Hello.scala",
    )


def test_get_file_header_invalid_id():
    invalid_header = b"\x00" + bytes.fromhex(VALID_FILE_HEADER[2:])
    with pytest.raises(IOError, match="not a gzip file"):
        get_file_header(BitStream(invalid_header))


def test_get_file_header_invalid_cm():
    invalid_header = (
        bytes.fromhex(VALID_FILE_HEADER[:4])
        + b"\x07"
        + bytes.fromhex(VALID_FILE_HEADER[6:])
    )
    with pytest.raises(IOError, match="unsupported compression method"):
        get_file_header(BitStream(invalid_header))


def test_get_file_header_invalid_flags():
    invalid_header = (
        bytes.fromhex(VALID_FILE_HEADER[:6])
        + 0b10000000 .to_bytes(1, "big")
        + bytes.fromhex(VALID_FILE_HEADER[8:])
    )
    with pytest.raises(IOError, match="unknown gzip flag"):
        get_file_header(BitStream(invalid_header))
