import socketserver

from rfc_1939.core import *


class MyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.session = Session()
        self.state = State.GREETING
        response = f"{POSITIVE_INDICATOR} POP3 server ready{COMMAND_END}"
        self.wfile.write(response.encode())
        print(f"Server sent: {response}")
        self.state = State.AUTHORIZATION
        # wait for auth until maildrop established
        while not self.session.maildrop:
            command = b""
            while not command.endswith(COMMAND_END.encode()):
                command += self.rfile.readline()
            print(f"Server received: {command}")
            command = command[: -len(COMMAND_END)].decode()
            response = Command(command).respond(
                self.state, self.session, MAILBOX
            )
            self.wfile.write(response.encode())
            print(f"Server sent: {response}")
            if command == "QUIT" and response.startswith(POSITIVE_INDICATOR):
                return
        self.state = State.TRANSACTION
        # wait for resources to be released
        while self.session.maildrop:
            command = b""
            while not command.endswith(COMMAND_END.encode()):
                command += self.rfile.readline()
            print(f"Server received: {command}")
            command = command[: -len(COMMAND_END)].decode()
            response = Command(command).respond(
                self.state, self.session, MAILBOX
            )
            self.wfile.write(response.encode())
            print(f"Server sent: {response}")
            if command == "QUIT" and response.startswith(POSITIVE_INDICATOR):
                return


if __name__ == "__main__":
    HOST = "localhost"

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, 9998), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
