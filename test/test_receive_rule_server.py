import socket
import threading


class ServerConnection():

    clients = []

    def handle_client(client_socket):
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                print(f"Received data: {data.decode('utf-8')}")
            except ConnectionResetError:
                break
        client_socket.close()
        clients.remove(client_socket)
        print("Client disconnected")

    def accept_connections(server_socket):
        while True:
            client_sock, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            clients.append(client_sock)
            client_thread = threading.Thread(target=handle_client,
                                             args=(client_sock,))
            client_thread.start()

    def send_data_to_all_clients(data):
        for client in clients:
            client.sendall(data.encode('utf-8'))

    def start_server():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(('localhost', 12345))
        server_sock.listen()
        print("Server listening on port 12345")
        accept_thread = threading.Thread(target=accept_connections,
                                         args=(server_sock,))
        accept_thread.start()
        return server_sock

    server_sock = start_server()

    import time
    time.sleep(10)
    send_data_to_all_clients("Hello from server")
