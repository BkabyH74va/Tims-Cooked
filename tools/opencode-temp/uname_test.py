import os
u = os.uname()
for field in ["sysname", "nodename", "release", "version", "machine"]:
    print(f"{field} = {getattr(u, field)}")
