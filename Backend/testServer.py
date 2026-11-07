import socket

HOST = "0.0.0.0"
PORT = 5050

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(100)

print(f"Test server running on port {PORT}...")

while True:
    conn, addr = server.accept()

    print(f"Connection from {addr[0]}:{addr[1]}")

    conn.close()