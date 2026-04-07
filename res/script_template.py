#!/usr/bin/env python3
"""
Ásbrú Plus Python script template.

The selected connection is exposed via env vars and the asbru_py helper:
    ASBRU_HOST, ASBRU_PORT, ASBRU_USER, ASBRU_PASS, ASBRU_KEY, ASBRU_NAME

Quick API:
    asbru_py.run(cmd)        -> (stdout, stderr, exit_code)
    asbru_py.stream(cmd)     -> iterator of lines
    asbru_py.upload(l, r)    -> SFTP put
    asbru_py.download(r, l)  -> SFTP get
    asbru_py.client()        -> raw paramiko.SSHClient
    asbru_py.connection      -> Connection dataclass

Requires: pip install paramiko (or apt install python3-paramiko)
"""

import sys
import asbru_py as asbru


def main() -> int:
    if not asbru.connection:
        sys.stderr.write("Select a connection in Ásbrú Plus first.\n")
        return 1

    print(f"=== {asbru.connection.name} ({asbru.connection.host}) ===")

    out, err, rc = asbru.run("uname -a && uptime")
    if rc != 0:
        sys.stderr.write(err)
        return rc
    print(out.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
