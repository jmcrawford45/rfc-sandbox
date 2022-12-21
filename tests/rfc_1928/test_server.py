from rfc_1928.server import SocksProxy
from rfc_1928 import *
from unittest.mock import patch, Mock

import pytest


def _mock_client(stream: BytesIO) -> Mock:
    return Mock(read=stream.read, sendall=Mock())


@pytest.mark.parametrize(
    "methods,selected",
    [
        ([Method.GSS_API, Method.NO_AUTH, Method.BASIC], Method.NO_AUTH),
        ([Method.BASIC], Method.BASIC),
        ([Method.GSS_API], Method.NO_ACCEPTABLE),
    ],
)
def test_select_auth(methods, selected):
    assert (
        SocksProxy.select_auth(BytesIO(MethodRequest.create(methods).pack()))
        == selected
    )


def test_handle_basic_auth_valid():
    client = _mock_client(
        BytesIO(BasicAuthRequest.create(b"jcrawford", b"password").pack())
    )
    assert SocksProxy.handle_basic_auth(client, SocksProxy.AUTH)
    client.sendall.assert_called_once_with(
        MethodResponse.create(Method.NO_AUTH).pack()
    )


def test_handle_basic_auth_valid():
    client = _mock_client(
        BytesIO(BasicAuthRequest.create(b"jcrawford", b"hacker").pack())
    )
    assert not SocksProxy.handle_basic_auth(client, SocksProxy.AUTH)
    client.sendall.assert_called_once_with(
        MethodResponse.create(Method.NO_ACCEPTABLE).pack()
    )


@pytest.mark.parametrize(
    "addr_request,address",
    [
        (
            Request.create(
                Command.CONNECT, AddressType.IP_V4, b"0" * 4, 0x1234
            ),
            "0.0.0.0",
        ),
        (
            Request.create(
                Command.CONNECT, AddressType.DOMAIN_NAME, b"google.com", 0x1234
            ),
            b"google.com",
        ),
    ],
)
def test_parse_address(addr_request, address):
    with patch("rfc_1928.server.inet_ntoa", return_value=address):
        assert SocksProxy.parse_address(addr_request) == address


@patch("rfc_1928.server.inet_aton", return_value="1.2.3.4")
@patch(
    "rfc_1928.server.socket",
    return_value=Mock(connect=Mock(side_effect=IOError("failed"))),
)
def test_handle_connect_failure(mock_socket, mock_aton):
    request = Request.create(
        Command.CONNECT, AddressType.IP_V4, 0x01020304, 0x1234
    )
    remote, reply = SocksProxy.handle_connect("localhost", request)
    assert not remote
    assert reply.reply == ReplyStatus.CONNECTION_REFUSED


@patch("rfc_1928.server.inet_aton", return_value="1.2.3.4")
@patch(
    "rfc_1928.server.socket",
    return_value=Mock(getsockname=Mock(return_value=("1.2.3.4", 1234))),
)
def test_handle_connect(mock_socket, mock_aton):
    request = Request.create(
        Command.CONNECT, AddressType.IP_V4, 0x01020304, 0x1234
    )
    remote, reply = SocksProxy.handle_connect("localhost", request)
    assert remote
    assert reply.reply == ReplyStatus.SUCCEEDED
