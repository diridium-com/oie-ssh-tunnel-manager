# SPDX-FileCopyrightText: Copyright 2026 Diridium Technologies Inc.
# SPDX-License-Identifier: MPL-2.0

"""The SSH server the tunnels connect to: OpenSSH on Alpine, in Docker, one per run.

One user, USER, who logs in with PASSWORD or with the public key given to start(). The container is
named E2E_NAME_PREFIX-sshd and labelled like the database container (databases.run_container).
"""

import base64
import hashlib
import socket
import time

from databases import docker, run_container

# Pinned by digest: Alpine 3.24 as of 2026-10-18. OpenSSH is installed from Alpine's 3.24 repository
# when the container starts, so its version can move with Alpine's security updates; the run prints it.
IMAGE = "alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
USER = "tunnel"
PASSWORD = "Ssh-e2e-tunnel-1"   # throwaway test server only

# Alpine's sshd_config sets AllowTcpForwarding no, and sshd keeps the first value it reads for a
# setting. Its Include of sshd_config.d comes first, so the drop-in's "yes" wins; start() checks that.
# PerSourcePenalties (OpenSSH 9.8 and later) blocks a client address for 15 seconds or more once its
# failed logins and unauthenticated disconnects add up, and the controls cause both on purpose: with it
# on, the wrong-host-key control got "connection is closed by foreign host" instead of a key mismatch.
SETUP = r"""set -e
apk add --no-cache openssh-server >/dev/null
ssh-keygen -A >/dev/null
adduser -D -s /bin/sh tunnel
echo "tunnel:$TUNNEL_PASSWORD" | chpasswd
mkdir -p /home/tunnel/.ssh
printf '%s\n' "$TUNNEL_KEY" > /home/tunnel/.ssh/authorized_keys
chown -R tunnel:tunnel /home/tunnel/.ssh
chmod 700 /home/tunnel/.ssh
chmod 600 /home/tunnel/.ssh/authorized_keys
printf 'AllowTcpForwarding yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\nPerSourcePenalties no\n' > /etc/ssh/sshd_config.d/00-e2e.conf
exec /usr/sbin/sshd -D -e
"""


def fingerprint(public_key_b64):
    """OpenSSH's SHA256 fingerprint of a base64 public key blob."""
    digest = hashlib.sha256(base64.b64decode(public_key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class SshServer:
    def __init__(self):
        self.container = None
        self.port = None
        self.banner = None
        self._next_port = 7000

    def start(self, public_key, timeout=300):
        self.container, self.port = run_container(
            "sshd", "22", ["-e", f"TUNNEL_PASSWORD={PASSWORD}", "-e", f"TUNNEL_KEY={public_key}"],
            IMAGE, ["sh", "-c", SETUP])
        end = time.time() + timeout
        while time.time() < end:
            self.banner = self._banner()
            if self.banner:
                break
            if docker("inspect", "-f", "{{.State.Running}}", self.container, check=False).stdout.strip() != "true":
                raise RuntimeError("the SSH server container exited: " + self.logs())
            time.sleep(2)
        else:
            raise RuntimeError(f"the SSH server did not answer within {timeout} seconds: " + self.logs())
        effective = docker("exec", self.container, "/usr/sbin/sshd", "-T").stdout
        for setting in ("allowtcpforwarding yes", "passwordauthentication yes", "pubkeyauthentication yes",
                        "persourcepenalties no"):
            if setting not in effective.splitlines():
                raise RuntimeError(f"the SSH server's effective configuration lacks '{setting}'")

    def _banner(self):
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
                line = s.makefile("rb").readline(256).decode("ascii", "replace").strip()
                return line if line.startswith("SSH-2.0-") else None
        except OSError:
            return None

    def logs(self):
        result = docker("logs", self.container, check=False)
        return (result.stdout + result.stderr).strip()[-1500:]

    def host_keys(self):
        """The server's host keys: {key type: base64 public key blob}."""
        out = docker("exec", self.container, "sh", "-c", "cat /etc/ssh/ssh_host_*_key.pub").stdout
        keys = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                keys[parts[0]] = parts[1]
        return keys

    def next_port(self):
        """A port for a remote forward to bind inside the container. Each one is used once per run."""
        self._next_port += 1
        return self._next_port

    def read_from(self, port):
        """What a client inside the container reads from 127.0.0.1:port, or None if it can't connect."""
        result = docker("exec", self.container, "nc", "-w", "5", "127.0.0.1", str(port), check=False, timeout=30)
        return result.stdout.strip() if result.returncode == 0 else None

    def drop_sessions(self):
        """Ends every client session, the way a server restart or network cut would. sshd itself keeps
        listening. True if there was a session to end."""
        # Run pkill directly, not under sh -c, whose own command line would match the pattern.
        return docker("exec", self.container, "pkill", "-f", "sshd-session", check=False).returncode == 0

    def stop(self):
        if self.container:
            docker("rm", "-f", "-v", self.container, check=False)
            self.container = None
