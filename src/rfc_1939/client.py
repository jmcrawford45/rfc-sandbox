import socket
import sys

from rfc_1939.core import *

if __name__ == "__main__":

    def command_ended(command: str, received: str) -> bool:
        if command in ["LIST", "RETR"]:
            return received.endswith(MULTILINE_END)
        return received.endswith(COMMAND_END)

    HOST = "localhost"

    # Create a socket (SOCK_STREAM means a TCP socket)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, 9998))
        command_method = None
        while command_method != "QUIT":
            print(f"Prev command: {command_method}")
            # Receive data from the server and shut down
            received = ""
            while not command_ended(command_method, received):
                received += str(sock.recv(1), "utf-8")
            print(f"Client received: {received}")
            command = input().rstrip("\n") + COMMAND_END
            command_method = command.split()[0]
            if command_method == "LIST" and command != f"LIST{COMMAND_END}":
                command_method = "LIST_SINGLE"
            sock.sendall(bytes(command, "utf-8"))
            print(f"Client sent: {command}")
        # Receive data from the server and shut down
        received = ""
        while not received.endswith(COMMAND_END):
            received += str(sock.recv(1), "utf-8")
        print(f"Client received: {received}")
