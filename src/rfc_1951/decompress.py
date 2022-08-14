from rfc_1951.core import *

from io import BufferedIOBase, BytesIO
from struct import unpack
from binascii import crc32
from datetime import datetime

MAX_BIT_OFFSET = 7


def get_block_header(stream: BufferedIOBase, offset: int) -> BlockHeader:
    if not (0 <= offset <= MAX_BIT_OFFSET):
        raise ValueError(f"Cannot offset {offset} bits into next byte")
    # since a block header can begin within a byte, we sometimes need to read 2 bytes
    header_len = 2 if offset + 2 > MAX_BIT_OFFSET else 1
    header = stream.read(header_len)
    bit_len = header_len * 8  # 8 bits per byte
    is_final = bool(
        header[0] >> (MAX_BIT_OFFSET - offset) & 0b1
    )  # next bit from offset
    offset += 1
    if offset == 8:
        block_type = BlockType(
            header[1] >> (MAX_BIT_OFFSET - 1) & 0b11
        )  # 2 bits for header
    elif offset == 7:
        first_bit = header[0] & 0b1
        last_bit = (header[1] >> MAX_BIT_OFFSET) & 0b1
        block_type = BlockType((first_bit << 1) + last_bit)
    else:
        block_type = BlockType(
            header[0] >> (MAX_BIT_OFFSET - offset - 1) & 0b11
        )
    return BlockHeader(is_final, block_type)


def ones_complement(x: int, y: int) -> bool:
    base = x ^ y
    return base != 0 and ((base + 1) & base) == 0


def decode(stream: BufferedIOBase, output: BytesIO):
    block_header = BlockerHeader(False, BlockType.NO_COMPRESSION)
    while True:
        block_header = get_block_header(stream, offset=0)
        if block_header.block_type == BlockType.NO_COMPRESSION:
            block_len, ones_complement = unpack("<HH", stream.read(2))
            if not ones_complement(block_len, ones_complement):
                raise ValueError(
                    f"Invalid LEN, NLEN pair: {ones_complement} is not the ones-complement of {block_len}"
                )
            output.write(stream.read(block_len))
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


def get_null_terminated_string(stream: BufferedIOBase):
    out = b""
    while True:
        byte = stream.read(1)
        if byte == b"\x00":
            return out.decode("latin-1")
        out += byte


def get_file_header(stream: BufferedIOBase):
    file_id = stream.read(2)
    if file_id != GZIP_FILE_ID:
        raise IOError("given stream is not a gzip file")
    compression_method = stream.read(1)
    if compression_method != COMPRESSION_METHOD:
        raise IOError("gzip file uses unsupported compression method")
    raw_flags = stream.read(1)
    flags = unpack("B", raw_flags)[0]
    if flags >= 0b100000:
        raise IOError("unknown gzip flag set")
    # We ignore FTEXT flag since there aren't different file formats for ascii and binary for my system
    is_crc = bool(flags & 0b10)
    is_extra = bool(flags & 0b100)
    is_name = bool(flags & 0b1000)
    is_comment = bool(flags & 0b10000)
    mtime_raw = stream.read(4)
    mtime = datetime.fromtimestamp(unpack("<i", mtime_raw)[0])
    # we ignore xfl since it's useful for diagnostics only
    xfl = stream.read(1)
    raw_os = stream.read(1)
    os = OS(int.from_bytes(raw_os, "big"))
    header = (
        file_id + compression_method + raw_flags + mtime_raw + xfl + raw_os
    )
    extra_data = filename = comment = crc = None
    if is_extra:
        len_raw = stream.read(2)
        extra_data = stream.read(unpack("<H", len_raw)[0])
        header += len_raw + extra_data
    if is_name:
        filename = get_null_terminated_string(stream)
        header += filename.encode("latin-1") + b"\x00"
    if is_comment:
        comment = get_null_terminated_string(stream)
        header += comment.encode("latin-1") + b"\x00"
    if is_crc:
        crc = unpack("<H", stream.read(2))[0]
        actual_crc = crc32(header) & 0x0000FFFF  # gzip uses crc16
        if actual_crc != crc:
            raise IOError("gzip header CRC did not match")
    return FileHeader(os, mtime, extra_data, filename, comment, crc)


def unzip(stream: BufferedIOBase):
    """
    :param stream: a stream of a gzip file
    """
    get_file_header(stream)
    output = BytesIO()
    decode(stream, output)
    if crc32(output.read()) != unpack("<H", stream.read(2)):
        raise IOError("CRC of uncompressed did not match for gzip file")
    if unpack("<H", stream.read(2)) != len(output):
        raise IOError("uncompressed data size did not match for gzip file")
