import os
u = os.uname()
print("sysname:", u.sysname)
print("release:", u.release)
print("version:", u.version[:80])
print("machine:", u.machine)
print("cpu_count:", os.cpu_count())
