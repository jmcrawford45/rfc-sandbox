from rfc_1951.core import *
from datetime import datetime

from binascii import crc32
from struct import pack

MAX_LOOKBACK = 2 ** 10
MAX_LOOKAHEAD = 200


def encode_no_compression(content_in: bytes, output: BitStream):
    output.flush_byte()
    block_len = len(content_in) & 0xFF
    output.write(16, pack("<H", block_len))
    output.write(16, pack("<H", ~block_len % (2 ** 16)))
    output.write(8 * len(content_in), content_in)


def get_length_distance(
    content_in: bytes, index: int, hash_chain_map: dict[bytes, list[int]]
) -> tuple[int, int]:
    """Return a length, distance pair representing the most recent match.
    :example: get_length_distance("abaaba", 3, {"aba": [0]}) -> (3, 3)
    """
    if index + Length.MIN_LENGTH > len(content_in):
        # not worth run encoding
        return 0, 0
    if content_in[index:index+Length.MIN_LENGTH] not in hash_chain_map:
        # no matches
        return 0, 0
    length_match = Length.MIN_LENGTH
    hash_matches = hash_chain_map[content_in[index:index+Length.MIN_LENGTH]]
    for match in reversed(hash_matches):  # prefer recent matches
        if index - match > MAX_LOOKBACK:
            # outside of window
            return 0, 0
        distance = index - match
        length = Length.MIN_LENGTH
        while index+length < len(content_in) and content_in[index+length] == content_in[match+length]:
            if length > length_match:
                length_match = length
                if length_match == Length.MAX_LENGTH:
                    return length_match, distance
            length += 1
    return length, distance


def encode_fixed_compression(content_in: bytes, output: BitStream):
    index = 0
    hash_chain_map = defaultdict(list)
    while index < len(content_in):
        if index-1 >= 0 and index+Length.MIN_LENGTH-1 < len(content_in):
            hash_chain_map[content_in[index-1:index+Length.MIN_LENGTH-1]].append(index-1)
        length, distance = get_length_distance(content_in, index, hash_chain_map)
        if not length and not distance:
            output.write_code(
                len(STATIC_LEN_CODES.encoding[content_in[index]]),
                int(
                    "".join(
                        reversed(STATIC_LEN_CODES.encoding[content_in[index]])
                    ),
                    2,
                ),
            )
            index += 1
        else:
            length_encoded = Length.from_length(length)
            output.write_code(
                len(STATIC_LEN_CODES.encoding[length_encoded.code]),
                int(
                    "".join(
                        reversed(
                            STATIC_LEN_CODES.encoding[length_encoded.code]
                        )
                    ),
                    2,
                ),
            )
            if length_encoded.extra_bits:
                output.write_code(
                    length_encoded.extra_bits,
                    length_encoded.additional_content,
                )
            distance_encoded = Distance.from_distance(distance)
            output.write_code(
                len(STATIC_DIST_CODES.encoding[distance_encoded.code]),
                int(
                    "".join(
                        reversed(
                            STATIC_DIST_CODES.encoding[distance_encoded.code]
                        )
                    ),
                    2,
                ),
            )
            if distance_encoded.extra_bits:
                output.write_code(
                    distance_encoded.extra_bits,
                    distance_encoded.additional_content,
                )
            index += length

    output.write(
        len(STATIC_LEN_CODES.encoding[CODE_END_OF_BLOCK]),
        int(
            "".join(reversed(STATIC_LEN_CODES.encoding[CODE_END_OF_BLOCK])), 2
        ),
    )


def encode(stream: BufferedIOBase, block_type: BlockType) -> bytes:
    output = BitStream(b"")
    content_in = stream.read()
    output.write(1, 1)
    output.write(2, block_type.value)
    if block_type == BlockType.NO_COMPRESSION:
        encode_no_compression(content_in, output)
    elif block_type == BlockType.FIXED_HUFFMAN_COMPRESSION:
        encode_fixed_compression(content_in, output)
    else:
        raise ValueError(f"requested unsupported block_type {block_type}")
    output.flush_byte()
    output.write(32, pack("<I", crc32(content_in)))
    output.write(32, pack("<I", len(content_in)))
    return output.underlying.getvalue()


def zip(
    stream: BufferedIOBase,
    block_type: BlockType = BlockType.FIXED_HUFFMAN_COMPRESSION,
) -> bytes:
    header = FileHeader(OS.UNKNOWN, datetime.now())
    header.crc = crc32(header.to_bytes()) & 0x0000FFFF
    return header.to_bytes() + encode(stream, block_type)
