from io import BytesIO
import sys

import pytest

from rfc_1951.core import *
from rfc_1951.decompress import *

from struct import pack
from datetime import datetime

VALID_FILE_HEADER = "1f8b08083ed0675b000348656c6c6f2e7363616c6100cb4f"


@pytest.mark.parametrize(
    "input_stream,offset,expected",
    [
        (
            0b00001000 .to_bytes(1, "big"),
            4,
            BlockHeader(True, BlockType.NO_COMPRESSION),
        ),
        (
            0b10000000 .to_bytes(1, "big"),
            0,
            BlockHeader(True, BlockType.NO_COMPRESSION),
        ),
        (
            0b01000000 .to_bytes(1, "big"),
            0,
            BlockHeader(False, BlockType.DYNAMIC_HUFFMAN_COMPRESSION),
        ),
        (
            0b00000001 .to_bytes(1, "big") + 0b01000000 .to_bytes(1, "big"),
            7,
            BlockHeader(True, BlockType.FIXED_HUFFMAN_COMPRESSION),
        ),
        (
            0b00000001 .to_bytes(1, "big") + 0b10000000 .to_bytes(1, "big"),
            6,
            BlockHeader(False, BlockType.RESERVED_ERROR),
        ),
    ],
)
def test_get_block_header(input_stream, offset, expected):
    assert get_block_header(BytesIO(input_stream), offset) == expected


@pytest.mark.parametrize("offset", [-1, 8, 10])
def test_get_block_header_invalid(offset):
    with pytest.raises(ValueError):
        get_block_header(BytesIO(0b00001000 .to_bytes(1, "big")), offset)


def test_get_file_header_valid():
    hello_dot_scala = bytes.fromhex(VALID_FILE_HEADER)
    header = get_file_header(BytesIO(hello_dot_scala))
    assert header == FileHeader(
        os=OS.UNIX,
        mtime=datetime(2018, 8, 5, 23, 36, 14),
        filename="Hello.scala",
    )


def test_get_file_header_invalid_id():
    invalid_header = b"\x00" + bytes.fromhex(VALID_FILE_HEADER[2:])
    with pytest.raises(IOError, match="not a gzip file"):
        get_file_header(BytesIO(invalid_header))


def test_get_file_header_invalid_cm():
    invalid_header = (
        bytes.fromhex(VALID_FILE_HEADER[:4])
        + b"\x07"
        + bytes.fromhex(VALID_FILE_HEADER[6:])
    )
    with pytest.raises(IOError, match="unsupported compression method"):
        get_file_header(BytesIO(invalid_header))


def test_get_file_header_invalid_flags():
    invalid_header = (
        bytes.fromhex(VALID_FILE_HEADER[:6])
        + 0b10000000 .to_bytes(1, "big")
        + bytes.fromhex(VALID_FILE_HEADER[8:])
    )
    with pytest.raises(IOError, match="unknown gzip flag"):
        get_file_header(BytesIO(invalid_header))
