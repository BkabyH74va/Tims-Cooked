import socket, time

for attempt in range(2):
    try:
        s = socket.create_connection(("198.51.100.1", 2222), 6)
        s.settimeout(8)
        if attempt == 1:
            s.sendall(b"SSH-2.0-probe_1.0\r\n")
        time.sleep(0.5)
        try:
            data = s.recv(200)
        except socket.timeout:
            data = b"<timeout>"
        print("attempt", attempt, "recv:", data)
        s.close()
    except Exception as e:
        print("attempt", attempt, "failed:", e)
