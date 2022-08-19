from rfc_1951.core import Distance, Length, HuffmanEncoding

import pytest


def test_deflate_huffman_encoding_from_code_lengths():
    huffman = HuffmanEncoding.from_alphabet_code_lengths([2, 1, 3, 3])
    assert huffman.encoding == ['10', '0', '110', '111']


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
    "length,code,additional_content",
    [
        (3, 257, 0),
        (9, 263, 0),
        (16, 267, 1),
        (37, 273, 2),
        (257, 284, 30),
        (258, 285, 0),
    ],
)
def test_from_length(length, code, additional_content):
    length_code = Length.from_length(length)
    assert length_code.code == code
    assert length_code.additional_content == additional_content


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

@pytest.mark.parametrize(
    "distance,code,additional_content",
    [
        (3, 2, None),
        (15, 7, 2),
        (32768, 29, 8191),
        (1000, 19, 231),
    ],
)
def test_from_distance(distance, code, additional_content):
    distance_code = Distance.from_distance(distance)
    assert distance_code.code == code
    assert distance_code.additional_content == additional_content
