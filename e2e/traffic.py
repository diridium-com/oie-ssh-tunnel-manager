# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""Traffic through the tunnels, seen from the machine the engine runs on."""

import socket
import threading
import time
import uuid


class Listener:
    """A TCP service on 127.0.0.1 that sends one line, its marker, to every client: the destination of
    the remote forwards, which the engine connects to when a client on the SSH server uses the forward."""

    def __init__(self):
        self.marker = "ssh-e2e-" + uuid.uuid4().hex[:12]
        self.connections = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            with conn:
                try:
                    conn.sendall((self.marker + "\n").encode())
                except OSError:
                    pass

    def close(self):
        self.sock.close()


def read_line(port, timeout=10):
    """The first line served on 127.0.0.1:port, or None if nothing answers."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            return s.makefile("rb").readline(256).decode("ascii", "replace").strip() or None
    except OSError:
        return None


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            return True
    except OSError:
        return False


def wait_closed(port, timeout=20):
    """True once nothing accepts connections on 127.0.0.1:port."""
    end = time.time() + timeout
    while time.time() < end:
        if not port_open(port):
            return True
        time.sleep(1)
    return False
