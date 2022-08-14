from rfc_1951.core import Distance, Length, HuffmanEncoding

import pytest


def test_deflate_huffman_encoding_from_code_lengths():
    huffman = HuffmanEncoding.from_alphabet_code_lengths([2, 1, 3, 3])
    assert huffman.encoding == [0b10, 0b0, 0b110, 0b111]


def test_deflate_huffman_encoding_from_code_lengths_invalid():
    with pytest.raises(ValueError):
        HuffmanEncoding.from_alphabet_code_lengths([2, 1, 0, 3])


@pytest.mark.parametrize(
    "code,extra_bits,min_length",
    [
        (257, 0, 3),
        (263, 0, 9),
        (268, 1, 17),
        (273, 3, 35),
        (284, 5, 227),
        (285, 0, 258),
    ],
)
def test_length(code, extra_bits, min_length):
    length = Length(code)
    assert length.code == code
    assert length.extra_bits == extra_bits
    assert length.min_length == min_length


@pytest.mark.parametrize(
    "code,extra_bits,min_distance",
    [
        (0, 0, 1),
        (2, 0, 3),
        (5, 1, 7),
        (15, 6, 193),
        (24, 11, 4097),
        (29, 13, 24577),
    ],
)
def test_distance(code, extra_bits, min_distance):
    distance = Distance(code)
    assert distance.code == code
    assert distance.extra_bits == extra_bits
    assert distance.min_distance == min_distance
