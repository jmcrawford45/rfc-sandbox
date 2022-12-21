from struct import pack, unpack

from dataclasses import dataclass
from io import BytesIO

from collections import namedtuple
from enum import Enum
from struct import *
from socket import socket


PORT = 1080
VERSION = 0x05


class Method(Enum):
    NO_AUTH = 0
    GSS_API = 1
    BASIC = 2
    NO_ACCEPTABLE = 0xFF


class Command(Enum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class AddressType(Enum):
    IP_V4 = 1
    DOMAIN_NAME = 3
    IP_V6 = 4


class ReplyStatus(Enum):
    SUCCEEDED = 0
    GENERAL = 1
    NOT_ALLOWED = 2
    NETWORK_UNREACHABLE = 3
    HOST_UNREACHABLE = 4
    CONNECTION_REFUSED = 5
    TTL_EXPIRED = 6
    UNSUPPORTED_COMMAND = 7
    UNSUPPORTED_ADDRESS_TYPE = 8


@dataclass
class BasicAuthRequest:
    version: int
    username: bytes
    password: bytes

    def pack(self) -> bytes:
        base = pack("!B", self.version)
        base += pack("!B", len(self.username)) + self.username
        base += pack("!B", len(self.password)) + self.password
        return base

    @classmethod
    def unpack(cls, stream: BytesIO | socket) -> "MethodRequest":
        if hasattr(stream, "read"):
            reader = stream.read
        else:
            reader = stream.recv
        version = unpack_from("!B", reader(1))[0]
        username = reader(unpack_from("!B", reader(1))[0])
        password = reader(unpack_from("!B", reader(1))[0])
        return cls(version, username, password)

    @classmethod
    def create(cls, username: bytes, password: bytes) -> "MethodRequest":
        return cls(VERSION, username, password)


@dataclass
class MethodRequest:
    version: int
    num_methods: int
    methods: list[Method]

    def pack(self) -> bytes:
        base = pack("!BB", self.version, self.num_methods)
        for method in self.methods:
            base += pack("B", method.value)
        return base

    @classmethod
    def unpack(cls, stream: BytesIO | socket) -> "MethodRequest":
        if hasattr(stream, "read"):
            reader = stream.read
        else:
            reader = stream.recv
        version, num_methods = unpack_from("!BB", reader(2))
        methods = []
        for _ in range(num_methods):
            methods.append(Method(unpack_from("B", reader(1))[0]))
        return cls(version, num_methods, methods)

    @classmethod
    def create(cls, methods: list[Method]) -> "MethodRequest":
        return cls(VERSION, len(methods), methods)


@dataclass
class MethodResponse:
    version: int
    method: Method

    def pack(self) -> bytes:
        return pack("!BB", self.version, self.method.value)

    @classmethod
    def unpack(cls, stream: BytesIO | socket) -> "MethodResponse":
        if hasattr(stream, "read"):
            reader = stream.read
        else:
            reader = stream.recv
        version, method_raw = unpack_from("!BB", reader(2))
        return cls(version, Method(method_raw))

    @classmethod
    def create(cls, method: Method) -> "MethodResponse":
        return cls(VERSION, method)


@dataclass
class Request:
    version: int
    command: Command
    reserved: int
    address_type: AddressType
    dest_addr: bytes
    port: int  # network byte order

    def pack(self) -> bytes:
        base = pack(
            "!BBBB",
            self.version,
            self.command.value,
            self.reserved,
            self.address_type.value,
        )
        if self.address_type == AddressType.DOMAIN_NAME:
            base += pack("!B", len(self.dest_addr))
        base += self.dest_addr + pack("!H", self.port)
        return base

    @classmethod
    def unpack(cls, stream: BytesIO | socket) -> "Request":
        if hasattr(stream, "read"):
            reader = stream.read
        else:
            reader = stream.recv
        version, command_raw, reserved, address_type_raw = unpack_from(
            "!BBBB", reader(4)
        )
        command, address_type = Command(command_raw), AddressType(
            address_type_raw
        )
        dest_addr = b""
        if address_type == AddressType.IP_V4:
            dest_addr = reader(4)
        elif address_type == AddressType.IP_V6:
            dest_addr = reader(16)
        elif address_type == AddressType.DOMAIN_NAME:
            dest_addr = reader(unpack_from("!B", reader(1))[0])
        else:
            raise ValueError(f"Unknown address type {address_type}")
        port = unpack_from("!H", reader(2))[0]
        return cls(version, command, reserved, address_type, dest_addr, port)

    @classmethod
    def create(
        cls,
        command: Command,
        address_type: AddressType,
        dest_addr: bytes,
        port: int,
    ) -> "Request":
        return cls(VERSION, command, 0x00, address_type, dest_addr, port)


@dataclass
class Reply:
    version: int
    reply: ReplyStatus
    address_type: AddressType
    dest_addr: bytes
    port: int  # network byte order

    def pack(self) -> bytes:
        base = pack(
            "!BBB", self.version, self.reply.value, self.address_type.value
        )
        if self.address_type == AddressType.DOMAIN_NAME:
            base += pack("!B", len(self.dest_addr))
        base += self.dest_addr + pack("!H", self.port)
        return base

    @classmethod
    def unpack(cls, stream: BytesIO | socket) -> "Reply":
        if hasattr(stream, "read"):
            reader = stream.read
        else:
            reader = stream.recv
        version, reply_raw, address_type_raw = unpack_from("!BBB", reader(3))
        reply_status, address_type = ReplyStatus(reply_raw), AddressType(
            address_type_raw
        )
        dest_addr = b""
        if address_type == AddressType.IP_V4:
            dest_addr = reader(4)
        elif address_type == AddressType.IP_V6:
            dest_addr = reader(16)
        elif address_type == AddressType.DOMAIN_NAME:
            dest_addr = reader(unpack_from("!B", reader(1))[0])
        else:
            raise ValueError(f"Unknown address type {address_type}")
        port = unpack_from("!H", reader(2))[0]
        return cls(version, reply_status, address_type, dest_addr, port)

    @classmethod
    def create(
        cls,
        reply_status: ReplyStatus,
        address_type: AddressType,
        dest_addr: bytes,
        port: int,
    ) -> "Reply":
        return cls(VERSION, reply_status, address_type, dest_addr, port)
