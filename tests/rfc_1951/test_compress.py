from io import BufferedReader, BytesIO

import pkg_resources

from rfc_1951.compress import *
from rfc_1951.core import *
from rfc_1951.decompress import *


def test_zip_no_compression():
    content_in = b"hello, world"
    zipped = gzip(BytesIO(content_in), BlockType.NO_COMPRESSION)
    unzipped = gunzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_zip_literal_fixed_compression():
    content_in = b"hello, world"
    zipped = gzip(BytesIO(content_in), BlockType.FIXED_HUFFMAN_COMPRESSION)
    unzipped = gunzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_zip_literal_fixed_compression_long_match():
    content_in = b"a" * 100
    zipped = gzip(BytesIO(content_in), BlockType.FIXED_HUFFMAN_COMPRESSION)
    unzipped = gunzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_length_distance():
    assert get_length_distance("abaaba", 3, {"aba": [0]}) == (3, 3)
    assert get_length_distance("abaabac", 3, {"aba": [0]}) == (3, 3)
    assert get_length_distance("abaabaa", 3, {"aba": [0]}) == (4, 3)


def test_zip_unzip_file():
    name = "rfc_1951"
    with open(
        pkg_resources.resource_filename(__name__, f"data/{name}"), "rb"
    ) as f:
        expected = f.read()
    zipped = gzip(BytesIO(expected))
    unzipped = gunzip(BitStream(BytesIO(zipped)))
    assert unzipped == expected
