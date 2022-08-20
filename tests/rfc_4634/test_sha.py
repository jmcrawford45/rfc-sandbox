import hashlib

import pytest

from rfc_4634.sha import *


def test_sha224_256_pad():
    message = Sha224256.pad(bytes.fromhex("6162636465"))
    assert message == bytes.fromhex(
        "6162636465800000" + (("0" * 8) * 13) + "00000028"
    )
    assert len(message) == Sha224256.BLOCK_BYTE_LEN


def test_sha384_512_pad():
    message = Sha384512.pad(bytes.fromhex("6162636465"))
    assert message.startswith(bytes.fromhex("6162636465"))
    assert message.endswith(bytes.fromhex("28"))
    assert len(message) == Sha384512.BLOCK_BYTE_LEN


@pytest.mark.parametrize(
    "algorithm,message,reference",
    [
        (Sha224, b"hello world", hashlib.sha224()),
        (Sha256, b"hello world", hashlib.sha256()),
        (Sha384, b"hello world", hashlib.sha384()),
        (Sha512, b"hello world", hashlib.sha512()),
    ],
)
def test_sha(algorithm, message, reference):
    reference.update(message)
    assert algorithm.digest(message) == reference.digest()
