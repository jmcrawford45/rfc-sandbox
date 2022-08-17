from rfc_1951.core import *
from datetime import datetime

from binascii import crc32
from struct import pack


def encode(stream: BufferedIOBase, block_type: BlockType) -> bytes:
    output = BitStream(b"")
    content_in = stream.read()
    output.write(1, 1)
    if block_type == BlockType.NO_COMPRESSION:
        output.write(2, BlockType.NO_COMPRESSION.value)  # final block, no compression
        output.flush_byte()
        block_len = len(content_in) & 0xff
        output.write(16, pack("<H", block_len))
        output.write(16, pack("<H", ~block_len % (2 ** 16)))
        output.write(8 * len(content_in), content_in)
    elif block_type == BlockType.FIXED_HUFFMAN_COMPRESSION:
        for c in content_in:
            output.write(len(STATIC_LEN_CODES[c]), int(STATIC_LEN_CODES[c], 2))
        output.write(len(STATIC_LEN_CODES[CODE_END_OF_BLOCK]), STATIC_LEN_CODES[CODE_END_OF_BLOCK])
    else:
        raise ValueError(f"requested unsupported block_type {block_type}")
    # output.flush_byte()
    output.write(32, pack("<I", crc32(content_in)))
    output.write(32, pack("<I", len(content_in)))
    return output.underlying.getvalue()

def zip(stream: BufferedIOBase, block_type: BlockType = BlockType.NO_COMPRESSION) -> bytes:
    header = FileHeader(OS.UNKNOWN, datetime.now())
    header.crc = crc32(header.to_bytes()) & 0x0000FFFF
    return header.to_bytes() + encode(stream, block_type)
