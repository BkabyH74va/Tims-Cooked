import socket

s = socket.socket()
s.settimeout(4)
try:
    s.connect(("198.51.100.1", 2222))
    s.sendall(b"SSH-2.0-x\r\n")
    try:
        print("banner:", s.recv(80))
    except socket.timeout:
        print("banner: <timeout>")
    s.close()
except Exception as e:
    print("connect failed:", e)
