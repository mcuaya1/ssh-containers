#!/usr/bin/env python

import socket
import sys
import threading
import traceback
import time

import paramiko

import docker

# Initialize Docker client
docker_client = docker.from_env()

# setup logging
paramiko.util.log_to_file("paramiko_server.log")

try:
    host_key = paramiko.Ed25519Key.from_private_key_file(filename=f'{sys.argv[1]}')
except Exception as e:
    print("*** No host key found: " + str(e))
    traceback.print_exc()
    sys.exit(1)


class Server(paramiko.ServerInterface):

    def __init__(self, auth_mode="cyber", auth_dict=None):
        self.event = threading.Event()
        self.auth_mode = auth_mode
        if auth_mode == "auth-dict":
            self.auth_dict = auth_dict

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        match self.auth_mode:
            case "cyber":
                if (username == "user") and (password == "cyber"):
                    return paramiko.AUTH_SUCCESSFUL
            case "auth-dict":
                if(self.auth_dict[username] == password):
                    return paramiko.AUTH_SUCCESSFUL
            case "no-auth":
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

def start_server(_server, LISTEN_PORT=2222):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", LISTEN_PORT))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)
    # now connect
    try:
        sock.listen(100)
        print(f"Listening for connections on {LISTEN_PORT}...")
        while True:
            client_socket, addr = sock.accept()
            print(f"Connection from {addr}")
            #setup_ssh_channel(client_socket)
            threading.Thread(target=setup_ssh_channel, args=(client_socket, _server)).start()
    except Exception as e:
        print("*** Listen/accept failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

def setup_ssh_channel(client, _server):
    transport = paramiko.Transport(client)
    print("Starting SSH server")
    print("Loading moduli")
    try:
        transport.load_server_moduli()
    except:
        print("(Failed to load moduli -- gex will be unsupported.)")
        raise
    print("Added host key")
    transport.add_server_key(host_key)
    server = _server # Server()
    print("Attempting to start server")
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)
    print("Waiting for auth")
    # wait for auth
    chan = transport.accept(20)
    if chan is None:
        print("*** No channel.")
        sys.exit(1)
    print("Authenticated!")
    print("Waiting for client to request a shell")
    # wait for client to request a shell
    server.event.wait(10)
    if not server.event.is_set():
        print("*** Client never asked for a shell.")
        sys.exit(1)
    # start container
    print("Starting container")
    docker_container_shell(chan,transport)

def docker_container_shell(chan,transport):
    # kill by name if it exists
    try:
        container = docker_client.containers.get(transport.get_username())
        container.remove(force=True)
    except:
        pass
    # Start Docker container (run a basic bash container)
    container = docker_client.containers.run(
        "ubuntu:latest", #replace it with any Docker image
        "/bin/bash",
        detach=True,
        tty=True,
        stdin_open=True,
        name=transport.get_username(),
        cpu_count=1,
        mem_limit="700m",
    )
    print(f"Started Docker container: {container.id} for {transport.get_username()}")

    try:
        # Attach to the container
        container_exec = docker_client.api.exec_create(container.id, "/bin/bash", stdin=True, tty=True)
        socket_io = docker_client.api.exec_start(container_exec['Id'], detach=False, tty=True, socket=True)
        
        # Forward data between SSH channel and container shell
        def forward_ssh_to_container():
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                socket_io._sock.send(data)

        def forward_container_to_ssh():
            while True:
                data = socket_io._sock.recv(1024)
                if not data:
                    break
                chan.send(data)

        # Run both threads to handle bidirectional communication
        socket_io._sock.settimeout(172800) # 2 days
        chan.settimeout(172800) # 2 days
        thread_ssh_to_container = threading.Thread(target=forward_ssh_to_container)
        thread_container_to_ssh = threading.Thread(target=forward_container_to_ssh)

        thread_ssh_to_container.start()
        thread_container_to_ssh.start()

        # Wait for both threads to finish
        thread_ssh_to_container.join()
        thread_container_to_ssh.join()
        
        chan.send(f"Shutting down {container.id}\r\n\r\n")

        # Clean up: remove the container when the SSH session ends
        clean(container,chan,transport)
    except Exception as e:
        print(f"Error after creating container: {e}")
        clean(container,chan,transport)

def clean(container, chan, transport):
    try:
        container.remove(force=True)
    except Exception as e:
        print(f"Error removing container {container.id}: {e}")
    print(f"Container {container.id} removed.")
    try:
        chan.close()
    except Exception as e:
        print(f"Error closing channel: {e}")
    try:
        transport.close()
    except Exception as e:
        print(f"Error closing transport: {e}")


AUTH_DICT = {}
def update_auth_dict(file):
    with open(file, 'r') as f:
        while not time.sleep(5): # time returns void
            f.seek(0)
            lines = f.readlines()
            for line in lines:
                up = line.split(":")
                #print(up)
                try:
                    AUTH_DICT[up[0].strip()] = up[1].strip()
                except:
                    pass
            #print(AUTH_DICT)

if __name__ == "__main__":
    server = Server(auth_mode="no-auth")
    #server = Server(auth_mode="auth-dict", auth_dict=AUTH_DICT)
    #threading.Thread(target=update_auth_dict,args=("auth.txt",)).start()
    start_server(server, 2222)


