import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
import socket
import json
import struct
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import threading
import time

root = tk.Tk()
root.title("Chatter")

# Recieving server IP
def get_server_ip():
    dialog = tk.Toplevel()
    dialog.title("Enter Server IP")
    dialog.geometry("300x120")
    dialog.grab_set()  # Focus on the window
    dialog.transient(root)

    # Without server IP won't work, so we have to recieve it
    dialog.protocol("WM_DELETE_WINDOW", lambda: None)

    tk.Label(dialog, text="Enter Server IP:", padx=10, pady=10).pack()
    server_ip_entry = tk.Entry(dialog, width=30)
    server_ip_entry.pack(pady=5)

    server_ip = tk.StringVar()

    def confirm():
        if server_ip_entry.get().strip():
            server_ip.set(server_ip_entry.get())
            dialog.destroy()
        else:
            messagebox.showwarning("Error", "IP can not be empty!")

    tk.Button(dialog, text="OK", command=confirm).pack(pady=10)
    dialog.wait_window()  # Wait until closing

    return server_ip.get()

server_ip = None
server_ip = get_server_ip()
# Setting up
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, 12345))
user_id = None
current_client = None
aes_keys = {}  # AES keys dictionary
pause_event = threading.Event()


# Selecting client function
def select_client(event):
    global current_client
    selection = client_listbox.curselection()  # Recieving indexes
    if selection:
        current_client = client_listbox.get(selection[0])  # Getting text from index
    else:
        current_client = None

def send_message_to_server(recipient_id, message, message_type="", nonce=""):
    data = {"from": user_id, "to": recipient_id, "message": message, "type": message_type, "nonce": nonce}
    json_data = json.dumps(data).encode('utf-8')
    # Including length
    client_socket.send(struct.pack('>I', len(json_data)) + json_data)

def register():
    send_message_to_server(0, "", "Registration")

last_rsa_key = None

def listen():
    while True:
        try:
            # Reading length of the received message
            raw_msglen = client_socket.recv(4)
            if not raw_msglen:
                continue
            msglen = struct.unpack('>I', raw_msglen)[0]
            # Receiving message by its size
            response = client_socket.recv(msglen).decode('utf-8')
            json_response = json.loads(response)

            sender_id = json_response.get("from")
            msg_content = json_response.get("message")
            message_type = json_response.get("type")
            if message_type == "RSA":
                global last_rsa_key
                last_rsa_key = msg_content
            if msg_content == "initiate_chat":
                # Generating RSA keypair
                rsa_key = RSA.generate(2048)
                private_key = rsa_key.export_key()
                public_key = rsa_key.publickey().export_key()
                aes_keys[sender_id] = {"private": private_key}

                send_message_to_server(sender_id, public_key.decode('utf-8'), "RSA")
                # Waiting encrypted AES key
                while True:
                    raw_msglen = client_socket.recv(4)
                    if not raw_msglen:
                        continue
                    if raw_msglen:
                        msglen = struct.unpack('>I', raw_msglen)[0]
                        response = client_socket.recv(msglen).decode('utf-8')
                        json_data = json.loads(response)
                        encrypted_aes_key = json_data.get("message")
                        target_id = json_data.get("from")

                        private_key = RSA.import_key(aes_keys[sender_id]["private"])
                        cipher_rsa = PKCS1_OAEP.new(private_key)
                        aes_key = cipher_rsa.decrypt(bytes.fromhex(encrypted_aes_key))
                        aes_keys[sender_id] = aes_key  # Saving chat key
                        client_listbox.insert(tk.END, target_id)
                        break

            elif sender_id in aes_keys:
                # AES decryption
                aes_key = aes_keys[sender_id]
                cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=bytes.fromhex(json_response.get("nonce")))
                decrypted_message = cipher_aes.decrypt(bytes.fromhex(msg_content)).decode('utf-8')

                history_text.config(state=tk.NORMAL)
                history_text.insert(tk.END, f"{sender_id}: {decrypted_message}\n")
                history_text.config(state=tk.DISABLED)

        except Exception as e:
            print(f"Error: {e}")

# Adding clients
def add_client():
    target_id = simpledialog.askstring("Add Client", "Enter client ID:")
    if target_id:
        client_listbox.insert(tk.END, target_id)
        # Sending initiate_chat
        send_message_to_server(target_id, "initiate_chat")

        rsa_public_key = None

        while True:
            global last_rsa_key
            if last_rsa_key:
                rsa_public_key = last_rsa_key
                last_rsa_key = None
                break

        if rsa_public_key:
            rsa_key = RSA.import_key(rsa_public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            aes_key = get_random_bytes(32)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            aes_keys[target_id] = aes_key

            send_message_to_server(target_id, encrypted_aes_key.hex())

# Sending message
def send_message():
    message = message_entry.get()
    if current_client and current_client in aes_keys:
        aes_key = aes_keys[current_client]
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        nonce = cipher_aes.nonce
        ciphertext = cipher_aes.encrypt(message.encode('utf-8'))

        history_text.config(state=tk.NORMAL)
        history_text.insert(tk.END, f"You: {message}\n")
        history_text.config(state=tk.DISABLED)
        message_entry.delete(0, tk.END)
        send_message_to_server(current_client, ciphertext.hex(), "MSG", nonce.hex())

# Getting user id
def get_user_id():
    dialog = tk.Toplevel()
    dialog.title("Введите ваш ID")
    dialog.geometry("300x120")
    dialog.grab_set()
    dialog.transient(root)

    dialog.protocol("WM_DELETE_WINDOW", lambda: None)

    tk.Label(dialog, text="Enter your ID:", padx=10, pady=10).pack()
    user_id_entry = tk.Entry(dialog, width=30)
    user_id_entry.pack(pady=5)

    user_id = tk.StringVar()

    def confirm():
        if user_id_entry.get().strip():
            user_id.set(user_id_entry.get().strip())
            dialog.destroy()
        else:
            messagebox.showwarning("Erroe", "ID can not be empty!")

    tk.Button(dialog, text="OK", command=confirm).pack(pady=10)
    dialog.wait_window()

    return user_id.get()


def __main__():
    global root, client_listbox, history_text, message_entry, user_id
    user_id = get_user_id()
    if not user_id:
        messagebox.showinfo("Exit", "ID not specified")
        root.destroy()
        return

    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)

    main_frame = tk.Frame(root)
    main_frame.grid(row=0, column=0, sticky="nsew")
    main_frame.rowconfigure(0, weight=1)
    main_frame.columnconfigure(1, weight=1)

    frame_left = tk.Frame(main_frame, bg="lightgray", padx=5, pady=5)
    frame_left.grid(row=0, column=0, sticky="nsew")
    frame_left.rowconfigure(0, weight=1)

    client_listbox = tk.Listbox(frame_left)
    client_listbox.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
    client_listbox.bind("<<ListboxSelect>>", select_client)

    add_button = tk.Button(frame_left, text="Add client", command=add_client)
    add_button.grid(row=1, column=0, sticky="ew")

    frame_right = tk.Frame(main_frame, padx=5, pady=5)
    frame_right.grid(row=0, column=1, sticky="nsew")
    frame_right.rowconfigure(0, weight=1)
    frame_right.columnconfigure(0, weight=1)

    history_text = tk.Text(frame_right, state=tk.DISABLED, wrap="word")
    history_text.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=(0, 5))

    message_entry = tk.Entry(frame_right)
    message_entry.grid(row=1, column=0, sticky="ew", pady=(5, 0))

    send_button = tk.Button(frame_right, text="Send", command=send_message)
    send_button.grid(row=1, column=1, sticky="ew", pady=(5, 0))

    frame_left.columnconfigure(0, weight=1)
    frame_right.columnconfigure(0, weight=1)

    history_text.config(state=tk.NORMAL)
    history_text.insert(tk.END, f"Your ID: {user_id}\n")
    history_text.config(state=tk.DISABLED)

    threading.Thread(target=listen, daemon=True).start()
    register()

    root.mainloop()

__main__()
