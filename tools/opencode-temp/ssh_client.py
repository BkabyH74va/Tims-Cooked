import sys
sys.path.insert(0, "/Users/USER/tw_push/pylib")
import asyncio
import asyncssh

async def main():
    try:
        conn = await asyncssh.connect("198.51.100.1", 2222,
                                      username="root", password="alpine",
                                      known_hosts=None)
        print("connected")
        res = await conn.run("id; pwd; ls /; echo MARKER-DONE", check=False)
        print("exit:", res.exit_status)
        print("stdout:", res.stdout)
        print("stderr:", res.stderr)
        conn.close()
    except Exception as e:
        print("FAIL:", type(e).__name__, e)

asyncio.run(main())
