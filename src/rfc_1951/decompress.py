from rfc_1951.core import *

from io import BytesIO
from struct import unpack
from binascii import crc32
from datetime import datetime

MAX_BIT_OFFSET = 7


def get_block_header(stream: BitStream) -> BlockHeader:
    is_final = bool(stream.read(1))  # next bit from offset
    block_type = BlockType(stream.read(2))
    return BlockHeader(is_final, block_type)


def ones_complement(x: int, y: int) -> bool:
    base = x ^ y
    return base != 0 and ((base + 1) & base) == 0


def decode(stream: BitStream, output: BytesIO):
    block_header = BlockerHeader(False, BlockType.NO_COMPRESSION)
    while True:
        block_header = get_block_header(stream, offset=0)
        if block_header.block_type == BlockType.NO_COMPRESSION:
            block_len, ones_complement = unpack("<HH", stream.read(16))
            if not ones_complement(block_len, ones_complement):
                raise ValueError(
                    f"Invalid LEN, NLEN pair: {ones_complement} is not the ones-complement of {block_len}"
                )
            output.write(stream.read(block_len * 8))
        elif (
            block_header.block_type == BlockType.DYNAMIC_HUFFMAN_COMPRESSION
            or block_header.block_type == BlockType.DYNAMIC_HUFFMAN_COMPRESSION
        ):
            if (
                block_header.block_type
                == BlockType.DYNAMIC_HUFFMAN_COMPRESSION
            ):
                # read code trees
                pass
            else:
                huffman = HuffmanEncoding([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
            while True:
                value = ...
                if value < 256:
                    output.write(value)
                elif value == CODE_END_OF_BLOCK:
                    break
                else:
                    # decode distance from input stream
                    # move backwards in output stream
                    # copy length bytes from this position to output stream
                    pass

        else:
            raise ValueError(
                f"Encountered invalid block {block_header.block_type}"
            )
        if block_header.is_final:
            break


def get_null_terminated_string(stream: BitStream):
    out = b""
    while True:
        byte = stream.read(8)
        if byte == b"\x00":
            return out.decode("latin-1")
        out += byte


def get_file_header(stream: BitStream):
    file_id = stream.read(16)
    if file_id != GZIP_FILE_ID:
        raise IOError("given stream is not a gzip file")
    compression_method = stream.read(8)
    if compression_method != COMPRESSION_METHOD:
        raise IOError("gzip file uses unsupported compression method")
    raw_flags = stream.read(8)
    flags = unpack("B", raw_flags)[0]
    if flags >= 0b100000:
        raise IOError("unknown gzip flag set")
    # We ignore FTEXT flag since there aren't different file formats for ascii and binary for my system
    is_crc = bool(flags & 0b10)
    is_extra = bool(flags & 0b100)
    is_name = bool(flags & 0b1000)
    is_comment = bool(flags & 0b10000)
    mtime_raw = stream.read(32)
    mtime = datetime.fromtimestamp(unpack("<i", mtime_raw)[0])
    # we ignore xfl since it's useful for diagnostics only
    xfl = stream.read(8)
    raw_os = stream.read(8)
    os = OS(int.from_bytes(raw_os, "big"))
    header = (
        file_id + compression_method + raw_flags + mtime_raw + xfl + raw_os
    )
    extra_data = filename = comment = crc = None
    if is_extra:
        len_raw = stream.read(16)
        extra_data = stream.read(unpack("<H", len_raw)[0] * 8)
        header += len_raw + extra_data
    if is_name:
        filename = get_null_terminated_string(stream)
        header += filename.encode("latin-1") + b"\x00"
    if is_comment:
        comment = get_null_terminated_string(stream)
        header += comment.encode("latin-1") + b"\x00"
    if is_crc:
        crc = unpack("<H", stream.read(16))[0]
        actual_crc = crc32(header) & 0x0000FFFF  # gzip uses crc16
        if actual_crc != crc:
            raise IOError("gzip header CRC did not match")
    return FileHeader(os, mtime, extra_data, filename, comment, crc)


def unzip(stream: BitStream):
    """
    :param stream: a stream of a gzip file
    """
    get_file_header(stream)
    output = BytesIO()
    decode(stream, output)
    if crc32(output.read()) != unpack("<H", stream.read(16)):
        raise IOError("CRC of uncompressed did not match for gzip file")
    if unpack("<H", stream.read(16)) != len(output):
        raise IOError("uncompressed data size did not match for gzip file")
