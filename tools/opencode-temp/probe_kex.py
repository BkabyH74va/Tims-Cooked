import socket, time

s = socket.create_connection(("198.51.100.1", 2222), 8)
s.settimeout(8)
banner = b""
while b"\r\n" not in banner:
    chunk = s.recv(64)
    if not chunk:
        break
    banner += chunk
print("banner:", banner.strip())
s.sendall(b"SSH-2.0-OpenSSH_9.7 probe\r\n")
time.sleep(0.5)
try:
    data = s.recv(400)
except socket.timeout:
    data = b"<timeout>"
print("after client version:", data[:120])
s.close()
