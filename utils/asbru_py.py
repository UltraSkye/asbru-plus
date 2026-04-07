"""
asbru_py — Python helper for Ásbrú Plus scripts.

When a Python script is launched from the Ásbrú Plus Scripts manager,
the running connection's details are exposed via environment variables.
This module wraps them in a friendly API and offers a one-liner SSH
client (paramiko) for the most common automation use cases:

    import asbru_py as asbru

    print(f"Running on {asbru.connection.name} ({asbru.connection.host})")

    # Quick: execute one command, return (stdout, stderr, exit_code)
    out, err, rc = asbru.run("uptime")
    print(out)

    # Streaming: yield lines as they come
    for line in asbru.stream("tail -f /var/log/syslog"):
        print(line)

    # Manual paramiko handle if you need full control
    ssh = asbru.client()
    sftp = ssh.open_sftp()
    sftp.put("local.txt", "/tmp/remote.txt")
    sftp.close()
    ssh.close()

The selected connection in Ásbrú is exposed via environment variables:
    ASBRU_HOST, ASBRU_PORT, ASBRU_USER, ASBRU_PASS, ASBRU_KEY,
    ASBRU_NAME, ASBRU_UUID, ASBRU_METHOD
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple


@dataclass
class Connection:
    """Selected connection metadata, populated from env vars."""

    name: str = ""
    uuid: str = ""
    host: str = ""
    port: int = 22
    user: str = ""
    password: str = ""
    key: str = ""
    method: str = "SSH"

    @classmethod
    def from_env(cls) -> "Connection":
        e = os.environ
        return cls(
            name=e.get("ASBRU_NAME", ""),
            uuid=e.get("ASBRU_UUID", ""),
            host=e.get("ASBRU_HOST", ""),
            port=int(e.get("ASBRU_PORT", "22") or 22),
            user=e.get("ASBRU_USER", ""),
            password=e.get("ASBRU_PASS", ""),
            key=e.get("ASBRU_KEY", ""),
            method=e.get("ASBRU_METHOD", "SSH"),
        )

    def __bool__(self) -> bool:
        return bool(self.host)


# Lazy-populated singleton — read once on import
connection: Connection = Connection.from_env()


def _require_paramiko():
    try:
        import paramiko  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "ERROR: paramiko is not installed.\n"
            "Install with: pip install --user paramiko\n"
            "or: sudo apt install python3-paramiko\n"
        )
        sys.exit(2)
    return __import__("paramiko")


def client():
    """Return a connected paramiko.SSHClient using the selected connection."""
    if not connection:
        raise RuntimeError(
            "No connection selected. Run this script from Ásbrú Plus with a connection in focus."
        )
    paramiko = _require_paramiko()
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": connection.host,
        "port": connection.port,
        "username": connection.user,
    }
    if connection.key:
        kwargs["key_filename"] = connection.key
    elif connection.password:
        kwargs["password"] = connection.password
    ssh.connect(**kwargs)
    return ssh


def run(command: str, timeout: Optional[float] = None) -> Tuple[str, str, int]:
    """Execute one command and return (stdout, stderr, exit_code)."""
    ssh = client()
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc
    finally:
        ssh.close()


def stream(command: str, timeout: Optional[float] = None) -> Iterator[str]:
    """Yield stdout lines as they arrive. Useful for tail-f style commands."""
    ssh = client()
    try:
        _, stdout, _ = ssh.exec_command(command, timeout=timeout, get_pty=True)
        for raw in stdout:
            yield raw.rstrip("\n")
    finally:
        ssh.close()


def upload(local_path: str, remote_path: str) -> None:
    """Upload a local file to the selected connection via SFTP."""
    ssh = client()
    try:
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_path)
        sftp.close()
    finally:
        ssh.close()


def download(remote_path: str, local_path: str) -> None:
    """Download a remote file from the selected connection via SFTP."""
    ssh = client()
    try:
        sftp = ssh.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
    finally:
        ssh.close()


def info() -> None:
    """Print the selected connection details (debug aid)."""
    if not connection:
        print("No connection selected (no ASBRU_HOST env var).")
        return
    print(f"name:   {connection.name}")
    print(f"uuid:   {connection.uuid}")
    print(f"host:   {connection.host}")
    print(f"port:   {connection.port}")
    print(f"user:   {connection.user}")
    print(f"method: {connection.method}")
    if connection.key:
        print(f"key:    {connection.key}")
    if connection.password:
        print("auth:   password")
    elif connection.key:
        print("auth:   key")
    else:
        print("auth:   none configured")


if __name__ == "__main__":
    info()
