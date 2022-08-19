from rfc_1951.core import *
from rfc_1951.decompress import *
from rfc_1951.compress import *
from io import BytesIO, BufferedReader
import pkg_resources


def test_zip_no_compression():
    content_in = b"hello, world"
    zipped = zip(BytesIO(content_in), BlockType.NO_COMPRESSION)
    unzipped = unzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_zip_literal_fixed_compression():
    content_in = b"hello, world"
    zipped = zip(BytesIO(content_in), BlockType.FIXED_HUFFMAN_COMPRESSION)
    unzipped = unzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_zip_literal_fixed_compression_long_match():
    content_in = b"a" * 100
    zipped = zip(BytesIO(content_in), BlockType.FIXED_HUFFMAN_COMPRESSION)
    unzipped = unzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in


def test_length_distance():
    assert get_length_distance("aba", "abaaba", 3) == (3, 3)


def test_zip_unzip_file():
    name = "rfc_1951"
    with open(
        pkg_resources.resource_filename(__name__, f"data/{name}"), "rb"
    ) as f:
        expected = f.read()
    zipped = zip(BytesIO(expected))
    unzipped = unzip(BitStream(BytesIO(zipped)))
    assert unzipped == expected
