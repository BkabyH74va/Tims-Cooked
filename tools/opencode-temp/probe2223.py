import socket, time

for label, port in (("ssh", 2222), ("raw", 2223)):
    try:
        s = socket.create_connection(("198.51.100.1", port), 6)
        s.settimeout(8)
        if label == "ssh":
            s.sendall(b"SSH-2.0-probe_1.0\r\n")
        time.sleep(0.3)
        try:
            data = s.recv(300)
        except socket.timeout:
            data = b"<timeout>"
        print(label, "recv:", data)
        s.close()
    except Exception as e:
        print(label, "failed:", e)
