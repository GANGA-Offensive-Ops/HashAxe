import socket
import sys
import threading
import traceback

import paramiko

# Create a local ECDSA key for the server (avoids 'no acceptable host key' for deprecated ssh-rsa)
host_key = paramiko.ECDSAKey.generate(bits=256)


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Return success for our known test cases
        if username == "testadmin" and password == "mock_ssh_fixture_pwd_9a":
            return paramiko.AUTH_SUCCESSFUL
        if username == "root" and password == "mock_ssh_root_pwd_5z":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"


def client_handler(client_socket):
    try:
        t = paramiko.Transport(client_socket)
        # Using simple local key
        t.add_server_key(host_key)
        server = Server()
        try:
            t.start_server(server=server)
        except paramiko.SSHException:
            return

        # wait for auth
        chan = t.accept(20)
        if chan is None:
            return

        server.event.wait(10)
        if not server.event.is_set():
            chan.close()

    except Exception as e:
        pass
    finally:
        if "t" in locals():
            t.close()


def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 2222))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    try:
        sock.listen(100)
        print("Mock SSH server listening on port 2222")
        while True:
            client, addr = sock.accept()
            print("Incoming connection from", addr)
            threading.Thread(target=client_handler, args=(client,), daemon=True).start()
    except Exception as e:
        pass


if __name__ == "__main__":
    main()
