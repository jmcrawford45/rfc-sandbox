from rfc_1928 import *
from io import BytesIO
from struct import pack

import pytest


def test_method_request_serde():
    start = MethodRequest.create(list(Method.__members__.values()))
    assert MethodRequest.unpack(BytesIO(MethodRequest.pack(start))) == start


def test_method_response_serde():
    start = MethodResponse.create(Method.NO_AUTH)
    assert MethodResponse.unpack(BytesIO(MethodResponse.pack(start))) == start


def test_basic_auth_request_serde():
    start = BasicAuthRequest.create(b"jcrawford", b"password")
    assert (
        BasicAuthRequest.unpack(BytesIO(BasicAuthRequest.pack(start))) == start
    )


@pytest.mark.parametrize(
    "item",
    [
        Request.create(Command.CONNECT, AddressType.IP_V4, b"0" * 4, 0x1234),
        Request.create(Command.BIND, AddressType.IP_V6, b"0" * 16, 0x1234),
        Request.create(
            Command.UDP_ASSOCIATE, AddressType.DOMAIN_NAME, b"0" * 8, 0x1234
        ),
    ],
)
def test_request_serde(item):
    assert Request.unpack(BytesIO(Request.pack(item))) == item


@pytest.mark.parametrize(
    "item",
    [
        Reply.create(
            ReplyStatus.SUCCEEDED, AddressType.IP_V4, b"0" * 4, 0x1234
        ),
        Reply.create(
            ReplyStatus.NETWORK_UNREACHABLE,
            AddressType.IP_V6,
            b"0" * 16,
            0x1234,
        ),
        Reply.create(
            ReplyStatus.CONNECTION_REFUSED,
            AddressType.DOMAIN_NAME,
            b"0" * 8,
            0x1234,
        ),
    ],
)
def test_reply_serde(item):
    assert Reply.unpack(BytesIO(Reply.pack(item))) == item
