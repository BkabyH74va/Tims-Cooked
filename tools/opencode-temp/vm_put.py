"""Copy a local file to the Debian VM (198.51.100.1) over SFTP."""
import os
import sys

import paramiko

HOST = "198.51.100.1"
USER = "serv"
PASSWORD = os.environ["PASSWORD"]


def put(local: str, remote: str) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=15)
    try:
        sftp = client.open_sftp()
        sftp.put(local, remote)
        sftp.close()
    finally:
        client.close()
    print(f"copied {local} -> {remote}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: vm_put.py <local> <remote>")
    put(sys.argv[1], sys.argv[2])
