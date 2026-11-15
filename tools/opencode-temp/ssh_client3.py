import sys
sys.path.insert(0, "/Users/USER/tw_push/pylib")
import asyncio
import asyncssh

host = sys.argv[1] if len(sys.argv) > 1 else "198.51.100.1"

async def main():
    conn = await asyncssh.connect(host, 2222,
                                  username="root", password="alpine",
                                  known_hosts=None)
    print("connected to", host)
    res = await conn.run("pwd\necho MARKER-USB-OK\nneofetch --stdout\nhead -5 /etc/hosts", check=False)
    print("exit:", res.exit_status)
    print(res.stdout)
    if res.stderr:
        print("stderr:", res.stderr)
    conn.close()

asyncio.run(main())
