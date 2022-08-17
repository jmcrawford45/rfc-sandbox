from rfc_1951.core import *
from rfc_1951.decompress import *
from rfc_1951.compress import *
from io import BytesIO, BufferedReader



def test_zip_no_compression():
    content_in = b"hello, world"
    zipped = zip(BytesIO(content_in), BlockType.NO_COMPRESSION)
    unzipped = unzip(BitStream(BytesIO(zipped)))
    assert unzipped == content_in
