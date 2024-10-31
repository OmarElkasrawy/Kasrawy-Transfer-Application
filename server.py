import socket

# Server settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 57329

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_HOST, SERVER_PORT))
server_socket.listen()

print(f"Server started at {SERVER_HOST}:{SERVER_PORT}")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Connection from {client_address}")

    while True:
        # Receive messages from the client
        message = client_socket.recv(1024).decode()
        if not message:
            break
        print("Received:", message)
    
    client_socket.close()
    print(f"Connection closed from {client_address}")
