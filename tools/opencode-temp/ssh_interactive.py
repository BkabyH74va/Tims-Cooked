import sys
sys.path.insert(0, "/Users/USER/tw_push/pylib")
import asyncio
import asyncssh

host = sys.argv[1] if len(sys.argv) > 1 else "198.51.100.1"

async def main():
    conn = await asyncssh.connect(host, 2222, username="root", password="alpine", known_hosts=None)
    stdin, stdout, stderr = await conn.open_session()
    async def wr(cmd):
        sys.stdout.write(">>> %r\n" % cmd)
        sys.stdout.flush()
        stdin.write(cmd)
        try:
            await stdin.drain()
        except Exception:
            pass
    async def rd():
        data = await stdout.read(4096)
        sys.stdout.write("<<< %r\n" % (data,))
        sys.stdout.flush()
        return data
    await wr("pwd\n")
    await rd()
    await wr("neofetch --stdout\n")
    await rd()
    await wr("echo goodbye\n")
    await rd()
    await wr("exit\n")
    try:
        data = await asyncio.wait_for(stdout.read(4096), 3)
        sys.stdout.write("<<< %r\n" % (data,))
    except asyncio.TimeoutError:
        sys.stdout.write("<<< (timed out waiting for exit)\n")
    conn.close()
    sys.stdout.write("done\n")

asyncio.run(main())
