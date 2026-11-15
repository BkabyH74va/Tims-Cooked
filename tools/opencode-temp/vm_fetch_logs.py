"""Pull the server's chat logs to the local machine so they can be built into a dataset."""
import os
import posixpath
import sys

import paramiko

HOST = "198.51.100.1"
USER = "serv"
PASSWORD = os.environ[\"PASSWORD\"]
REMOTE_ROOT = "/home/serv/Desktop/Discord bot/data/chatlogs"
LOCAL_ROOT = r"E:\Discord bot\data\chatlogs"


def walk(sftp, remote_dir, local_dir):
    os.makedirs(local_dir, exist_ok=True)
    for entry in sftp.listdir_attr(remote_dir):
        remote_path = posixpath.join(remote_dir, entry.filename)
        local_path = os.path.join(local_dir, entry.filename)
        if entry.st_mode & 0o40000:  # directory
            walk(sftp, remote_path, local_path)
        else:
            sftp.get(remote_path, local_path)
            print(f"  {local_path}  {entry.st_size}")


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=15)
    try:
        sftp = client.open_sftp()
        walk(sftp, REMOTE_ROOT, LOCAL_ROOT)
        sftp.close()
    finally:
        client.close()
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
