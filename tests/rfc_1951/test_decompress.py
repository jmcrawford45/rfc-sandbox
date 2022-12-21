import sys
from datetime import datetime
from io import BufferedReader, BytesIO
from struct import pack

import pkg_resources
import pytest

from rfc_1951.core import *
from rfc_1951.decompress import *

VALID_FILE_HEADER = "1f8b08083ed0675b000348656c6c6f2e7363616c6100cb4f"
VALID_FILE = "1f8b08083ed0675b000348656c6c6f2e7363616c6100cb4fca4a4d2e51f048cdc9c95748ad2849cd4b2956702c2850a8e6522828cacc2bc9c9d3482c4a2fd62b4a2d4b2d2a4ed5cbcd0e2e018aa76b282928696a72d5020021b8fcbe41000000"
VALID_FILE_DEVNULL = "1f8b080025fcfb62000303000000000000000000"
VALID_FILE_NEWLINE = "1f8b08008901fc620003e302009306d73201000000"


@pytest.mark.parametrize(
    "input_stream,expected",
    [
        (
            BitStream(BytesIO(0b00000001.to_bytes(1, "big"))),
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
        + 0b10000000.to_bytes(1, "big")
        + bytes.fromhex(VALID_FILE_HEADER[8:])
    )
    with pytest.raises(IOError, match="unknown gzip flag"):
        get_file_header(BitStream(invalid_header))


def test_unzip_empty():
    stream = BitStream(
        BufferedReader(BytesIO(bytes.fromhex(VALID_FILE_DEVNULL)))
    )
    assert gunzip(stream) == b""


def test_unzip():
    stream = BitStream(
        BufferedReader(BytesIO(bytes.fromhex(VALID_FILE_NEWLINE)))
    )
    assert gunzip(stream) == b"\n"


def test_unzip_file():
    name = "rfc_1951"
    with open(
        pkg_resources.resource_filename(__name__, f"data/{name}"), "rb"
    ) as f:
        expected = f.read()
    with open(
        pkg_resources.resource_filename(__name__, f"data/{name}.gz"), "rb"
    ) as out:
        in_file = out.read()
    assert gunzip(BitStream(in_file)) == expected
