from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from socket import AF_INET, SOCK_STREAM, inet_aton, inet_ntoa, socket
from rfc_1928 import *
from select import select


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):
    AUTH = {b"jcrawford": b"password"}

    def proxy(self, client, remote):
        while True:
            read, _, _ = select([client, remote], [], [])
            if client in read:
                print("client selected")
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break
            if remote in read:
                print("remote selected")
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

    @staticmethod
    def select_auth(client) -> Method:
        method_request = MethodRequest.unpack(client)
        if Method.NO_AUTH in method_request.methods:
            return Method.NO_AUTH
        elif Method.BASIC in method_request.methods:
            return Method.BASIC
        else:
            # TODO
            return Method.NO_ACCEPTABLE

    @staticmethod
    def handle_basic_auth(client, auth: dict[bytes, bytes]) -> bool:
        auth_request = BasicAuthRequest.unpack(client)
        if auth.get(auth_request.username) != auth_request.password:
            client.sendall(MethodResponse.create(Method.NO_ACCEPTABLE).pack())
            return False
        client.sendall(MethodResponse.create(Method.NO_AUTH).pack())
        return True

    @staticmethod
    def parse_address(request: Request) -> str | None:
        if request.address_type == AddressType.IP_V4:
            return inet_ntoa(request.dest_addr)
        elif request.address_type == AddressType.DOMAIN_NAME:
            return request.dest_addr
        else:
            # TODO
            return

    @staticmethod
    def handle_connect(
        address: str, request: Request
    ) -> tuple[socket | None, Reply]:
        try:
            remote = socket(AF_INET, SOCK_STREAM)
            remote.connect((address, request.port))
            dest_addr, port = remote.getsockname()
            dest_addr = inet_aton(dest_addr)
            reply = Reply.create(
                ReplyStatus.SUCCEEDED, request.address_type, dest_addr, port
            )
            return remote, reply
        except Exception:
            reply = Reply.create(
                ReplyStatus.CONNECTION_REFUSED,
                AddressType.IP_V4,
                0x00000000,
                0x0000,
            )
            return None, reply

    def handle(self):
        selected_auth = SocksProxy.select_auth(self.connection)
        self.connection.sendall(MethodResponse.create(selected_auth).pack())
        if selected_auth == Method.NO_ACCEPTABLE:
            self.server.close_request(self.request)
            return
        if selected_auth == Method.BASIC and not SocksProxy.handle_basic_auth(
            self.connection, self.AUTH
        ):
            self.server.close_request(self.request)
            return
        request = Request.unpack(self.connection)
        if request.command != Command.CONNECT:
            # TODO
            self.server.close_request(self.request)
            return
        address = SocksProxy.parse_address(request)
        if not address:
            self.server.close_request(self.request)
            return
        remote, reply = SocksProxy.handle_connect(address, request)
        self.connection.sendall(reply.pack())
        if reply.reply == ReplyStatus.SUCCEEDED:
            self.proxy(self.connection, remote)
        self.server.close_request(self.request)


if __name__ == "__main__":
    with ThreadingTCPServer(("127.0.0.1", 9998), SocksProxy) as server:
        server.serve_forever()
