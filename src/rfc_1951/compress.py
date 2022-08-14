from rfc_1951.core import *


def write_file_header(
    in_stream: BufferedIOBase, stream: BufferedIOBase = BytesIO
):
    stream.write(GZIP_FILE_ID)
    stream.write(COMPRESSION_METHOD)
    # TODO: consider supporting optional flags, xfl, mtime, and OS
    stream.write(bytes(7))
    ecode(in_stream, stream)
    # TODO: write crc32 and size


def encode(in_stream: BufferedIOBase, stream: BufferedIOBase = BytesIO):
    pass
