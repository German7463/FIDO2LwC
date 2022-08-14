import socket

HOST = "127.0.0.1"

PORT = 8801

sckt1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sckt1.bind((HOST,PORT))
sckt1.listen()
conn, addr = sckt1.accept()
with conn:
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)
        print(data)        
        conn.sendall(data)
        break