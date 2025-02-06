import socket
import json
import struct
import threading

clients = {}

def add_client(id, conn):
    clients[id] = conn

def send_message(id, data):
    conn = clients[id]
    json_data = json.dumps(data).encode('utf-8')
    conn.send(struct.pack('>I', len(json_data)) + json_data)

# Handle Client Function
def handle_client(conn, addr):

    while True:
        try:
            # Reading message's length
            raw_msglen = conn.recv(4)
            if not raw_msglen:
                break

            # Unpack length
            msglen = struct.unpack('>I', raw_msglen)[0]

            # Read JSON data
            data = conn.recv(msglen).decode('utf-8')
            json_data = json.loads(data)
            print(f"Recieved {addr}: {json_data}")

            sender = json_data.get('from')
            recipient = json_data.get('to')
            if recipient == 0:
                add_client(sender, conn)
            else:
                send_message(recipient, json_data)
        except Exception as e:
            print(f"Error {addr}: {e}")

    conn.close()
    print(f"Connection with {addr} closed")

# Setting up server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12345))
server_socket.listen(5)
print("Waiting connection...")

while True:
    conn, addr = server_socket.accept()

    # New thread to handle client connection
    client_thread = threading.Thread(target=handle_client, args=(conn, addr))
    client_thread.start()

server_socket.close()

