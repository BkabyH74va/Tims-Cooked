import sys
sys.path.insert(0, "/Users/USER/tw_push/pylib")
import asyncio
import asyncssh

async def main():
    conn = await asyncssh.connect("198.51.100.1", 2222,
                                  username="root", password="alpine",
                                  known_hosts=None)
    print("connected")
    for cmd in ("pwd", "neofetch --stdout", "ls /", "echo MARKER-DONE"):
        res = await conn.run(cmd, check=False)
        print("=== %r exit=%d" % (cmd, res.exit_status))
        print(res.stdout)
        if res.stderr:
            print("stderr:", res.stderr)
    conn.close()

asyncio.run(main())
