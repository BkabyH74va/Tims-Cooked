"""Run a command on the Debian VM (198.51.100.1) as serv, using the password from the environment.

Usage:  python vm_exec.py "command"
"""
import os
import sys

import paramiko

HOST = "198.51.100.1"
PORT = 22
USER = "serv"
PASSWORD = os.environ[\"PASSWORD\"]


def run(command: str, timeout: int = 120) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASSWORD, timeout=15)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    if err.strip():
        out += "\n--- stderr ---\n" + err
    return out + f"\n[exit {code}]"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: vm_exec.py 'command'")
    print(run(sys.argv[1], timeout=int(os.environ.get("VM_TIMEOUT", "120"))))
