import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
from tkinter.scrolledtext import ScrolledText
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64
import os


class SecureChatManager:
    def __init__(self):
        self.private_key = None
        self.shared_keys = {}
        self.pending_key_exchanges = {}

    def initialize_dh(self):
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )
        return self.get_public_bytes()

    def get_public_bytes(self):
        public_key = self.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_key(self, peer_public_bytes):
        peer_public_key = serialization.load_pem_public_key(
            peer_public_bytes,
            backend=default_backend()
        )
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    def encrypt_message(self, message, shared_key):
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_message, shared_key):
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        decryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext).decode() + decryptor.finalize().decode()


class ChatClient:
    def __init__(self):
        # Main window setup
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)

        self.connected = False
        self.username = None
        self.client_socket = None  # Initialize as None but don't create socket yet

        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Initialize frames
        self.setup_login_frame()
        self.setup_chat_frame()

        # Show login frame initially
        self.show_login_frame()
        self.private_chat_windows = {}

        self.secure_chat = SecureChatManager()
        self.secure_chat_ready = {}

    def setup_login_frame(self):
        self.login_frame = ttk.Frame(self.main_container)

        # Login form
        login_form = ttk.LabelFrame(self.login_frame, text="Login/Register", padding="20")
        login_form.pack(expand=True)

        # Username field
        ttk.Label(login_form, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(login_form, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        # Password field
        ttk.Label(login_form, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(login_form, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Buttons frame
        buttons_frame = ttk.Frame(login_form)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=20)

        ttk.Button(buttons_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=10)
        ttk.Button(buttons_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=10)

    def setup_chat_frame(self):
        self.chat_frame = ttk.Frame(self.main_container)

        # Split into left (chat) and right (users) panels
        left_panel = ttk.Frame(self.chat_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        right_panel = ttk.Frame(self.chat_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))

        # Chat area
        self.chat_display = ScrolledText(left_panel, wrap=tk.WORD, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Configure tags for message formatting
        self.chat_display.tag_config('timestamp', foreground='gray')
        self.chat_display.tag_config('sender', foreground='blue')
        self.chat_display.tag_config('message', foreground='black')

        # Message input area
        input_frame = ttk.Frame(left_panel)
        input_frame.pack(fill=tk.X, pady=(0, 10))

        self.message_entry = ttk.Entry(input_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        ttk.Button(input_frame, text="Send", command=self.send_message).pack(side=tk.LEFT)

        # Action buttons
        actions_frame = ttk.Frame(left_panel)
        actions_frame.pack(fill=tk.X)

        ttk.Button(actions_frame, text="Start New Chat", command=self.start_chat).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Send File", command=self.send_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Logout", command=self.logout).pack(side=tk.RIGHT, padx=5)

        # Online users panel
        ttk.Label(right_panel, text="Online Users").pack(pady=(0, 5))
        self.users_listbox = tk.Listbox(right_panel, width=20, height=20)
        self.users_listbox.pack(fill=tk.BOTH, expand=True)
        self.users_listbox.bind("<Double-Button-1>", lambda e: self.start_chat())

    def show_login_frame(self):
        self.chat_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)

    def show_chat_frame(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill=tk.BOTH, expand=True)

    def connect_to_server(self):
        try:
            # Create a new socket for each connection attempt
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("localhost", 5555))
            self.connected = True
            return True
        except Exception as e:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            self.connected = False
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            return False

    def listen_for_messages(self):
        while self.connected:
            try:
                message = self.client_socket.recv(1024).decode()
                if message:
                    print(f"Received message: {message[:50]}...")  # Debug print
                    if message == "HISTORY_START":
                        self.update_chat_display("=== Past Broadcast Messages ===")
                    elif message == "HISTORY_END":
                        self.update_chat_display("=== End of Broadcast Messages ===")
                    elif message.startswith("HISTORY_MSG\n"):
                        # Remove the HISTORY_MSG prefix
                        historical_message = message[11:]
                        self.update_chat_display(historical_message)
                    elif message.startswith("ONLINE_USERS:"):
                        self.update_online_users(message[13:].split(","))
                    elif message.startswith("CHAT_REQUEST:"):
                        sender = message.split(":")[1]
                        self.root.after(0, lambda s=sender: self.handle_chat_request(s))
                    elif message.startswith("CHAT_RESPONSE:"):
                        parts = message.split(":")
                        recipient = parts[1]
                        response = parts[2]
                        if response == "accept":
                            self.root.after(0, lambda r=recipient: self.open_private_chat(r))
                        else:
                            messagebox.showinfo("Chat Request", f"{recipient} refused the chat request.")
                    elif message.startswith("PRIVATE_MESSAGE:"):
                        parts = message.split(":")
                        sender = parts[1]
                        private_message = ":".join(parts[2:])
                        self.display_private_message(sender, private_message)

                    elif message.startswith("PRIVATE_FILE_NOTIFICATION\n"):
                        _, sender, file_name, file_path = message.split("\n")
                        self.handle_private_file_notification(sender, file_name, file_path)


                    if message.startswith("DH_INIT|"):
                        _, sender, public_key = message.split("|")
                        self.handle_dh_init(sender, public_key)
                    elif message.startswith("DH_REPLY|"):
                        _, sender, public_key = message.split("|")
                        self.handle_dh_reply(sender, public_key)
                    elif message.startswith("SECURE_MESSAGE|"):
                        _, sender, encrypted_message = message.split("|")
                        self.handle_secure_message(sender, encrypted_message)

                    else:
                        self.update_chat_display(message)
            except:
                self.connected = False
                break

    def update_online_users(self, users):
        self.users_listbox.delete(0, tk.END)
        for user in users:
            if user.strip() and user.strip() != self.username:
                self.users_listbox.insert(tk.END, user.strip())

    def update_chat_display(self, message):
        self.chat_display.configure(state='normal')

        # If it's a broadcast message with timestamp
        if message.startswith('[20'):  # This checks if the message starts with a timestamp
            # Insert with special formatting
            self.chat_display.tag_config('timestamp', foreground='gray')
            self.chat_display.tag_config('sender', foreground='blue')
            self.chat_display.tag_config('message', foreground='black')

            # Split the message into its components
            timestamp_end = message.find(']')
            if timestamp_end != -1:
                timestamp = message[0:timestamp_end + 1]
                rest = message[timestamp_end + 2:]  # Skip the space after ]
                sender_end = rest.find(':')
                if sender_end != -1:
                    sender = rest[0:sender_end]
                    msg_content = rest[sender_end + 2:]  # Skip the space after :

                    # Insert each part with its own formatting
                    self.chat_display.insert(tk.END, f"{timestamp} ", 'timestamp')
                    self.chat_display.insert(tk.END, f"{sender}: ", 'sender')
                    self.chat_display.insert(tk.END, f"{msg_content}\n", 'message')
                else:
                    self.chat_display.insert(tk.END, message + "\n")
            else:
                self.chat_display.insert(tk.END, message + "\n")
        else:
            # For system messages or other types of messages
            self.chat_display.insert(tk.END, message + "\n")

        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def login(self):
        if not self.connect_to_server():
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        try:
            # Send login command
            self.client_socket.send("login".encode())
            self.root.after(100)  # Small delay

            # Send credentials
            self.client_socket.send(username.encode())
            self.root.after(100)  # Small delay

            self.client_socket.send(password.encode())

            # Wait for response
            response = self.client_socket.recv(1024).decode()

            if "successful" in response.lower():
                self.username = username
                self.show_chat_frame()
                self.update_chat_display("Successfully logged in!")

                # Create a separate thread for receiving messages
                Thread(target=self.listen_for_messages, daemon=True).start()
            else:
                messagebox.showerror("Login Failed", response)
                if self.client_socket:
                    self.client_socket.close()
                    self.client_socket = None
                self.connected = False

        except Exception as e:
            messagebox.showerror("Error", f"Login failed: {e}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            self.connected = False

    def register(self):
        if not self.connect_to_server():
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        try:
            # Send registration command
            self.client_socket.send("register".encode())
            self.root.after(100)  # Small delay

            # Send credentials
            self.client_socket.send(username.encode())
            self.root.after(100)  # Small delay

            self.client_socket.send(password.encode())

            # Wait for response
            response = self.client_socket.recv(1024).decode()
            messagebox.showinfo("Registration", response)

        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            self.connected = False

    def send_message(self):
        message = self.message_entry.get().strip()
        if message:
            self.client_socket.send(f"MESSAGE\n{message}".encode())
            self.message_entry.delete(0, tk.END)

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                file_size = os.path.getsize(file_path)
                if file_size > 10_000_000:  # 10MB limit
                    messagebox.showerror("Error", "File is too large. Maximum size is 10MB.")
                    return

                file_name = os.path.basename(file_path)
                self.client_socket.send(f"FILE\n{file_name}\n{file_size}".encode())

                with open(file_path, 'rb') as file:
                    self.client_socket.sendall(file.read())

                self.update_chat_display(f"File sent: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send file: {e}")

    def start_chat(self):
        selected = self.users_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select a user from the online users list")
            return

        recipient = self.users_listbox.get(selected[0])

        # Check if we already have a shared key
        if recipient in self.secure_chat.shared_keys:
            self.open_private_chat(recipient)
            return

        # Initialize DH and send public key
        public_key = self.secure_chat.initialize_dh()
        self.client_socket.send(f"DH_INIT|{recipient}|{public_key.decode()}".encode())
        print(f"Sent DH_INIT to {recipient}")

    def handle_chat_request(self, sender):
        # Show a dialog to accept or refuse the chat request
        response = messagebox.askyesno("Chat Request",f"{sender} wants to start a private chat. Accept?")

        # Send response back to server
        if response:
            self.client_socket.send(f"CHAT_RESPONSE\n{sender}\naccept".encode())
            # Open a new window or tab for private chat
            self.open_private_chat(sender)
        else:
            self.client_socket.send(f"CHAT_RESPONSE\n{sender}\nrefuse".encode())

    def open_private_chat(self, with_user):
        # Create a new top-level window for private chat
        private_chat_window = tk.Toplevel(self.root)
        private_chat_window.title(f"Secure Chat with {with_user}")
        private_chat_window.geometry("500x400")

        chat_display = ScrolledText(private_chat_window, wrap=tk.WORD, height=20)
        chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        input_frame = ttk.Frame(private_chat_window)
        input_frame.pack(fill=tk.X, pady=(0, 5))

        message_entry = ttk.Entry(input_frame)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        def send_secure_message():
            message = message_entry.get().strip()
            if message:
                if with_user in self.secure_chat.shared_keys:
                    shared_key = self.secure_chat.shared_keys[with_user]
                    try:
                        encrypted_message = self.secure_chat.encrypt_message(message, shared_key)
                        self.client_socket.send(f"SECURE_MESSAGE|{with_user}|{encrypted_message}".encode())
                        # Display sent message in chat window
                        chat_display.configure(state='normal')
                        chat_display.insert(tk.END, f"You: {message}\n")
                        chat_display.configure(state='disabled')
                        chat_display.see(tk.END)
                        message_entry.delete(0, tk.END)
                    except Exception as e:
                        print(f"Encryption error: {e}")
                        messagebox.showerror("Error", "Failed to encrypt message")
                else:
                    messagebox.showerror("Error", "Secure chat not established")

        send_button = ttk.Button(input_frame, text="Send", command=send_secure_message)
        send_button.pack(side=tk.LEFT)
        message_entry.bind("<Return>", lambda e: send_secure_message())

        # Store the chat display widget for this conversation
        private_chat_window.chat_display = chat_display
        self.private_chat_windows[with_user] = private_chat_window

        return private_chat_window

    def display_private_message(self, sender, message):
        # Find or create private chat window
        private_window = self.open_private_chat(sender)

        # Use the append_message method we added
        if hasattr(private_window, 'append_message'):
            private_window.append_message(f"{sender}: {message}")

    def handle_private_file_notification(self, sender, file_name, file_path):
        # Find or create private chat window
        private_window = self.open_private_chat(sender)

        if hasattr(private_window, 'append_message'):
            private_window.append_message(f"{sender} sent file: {file_name}")

        # Ask user if they want to save the file
        if messagebox.askyesno("File Received",
                               f"Received file '{file_name}' from {sender}. Would you like to save it?"):
            save_path = filedialog.asksaveasfilename(
                defaultextension=os.path.splitext(file_name)[1],
                initialfile=file_name
            )
            if save_path:
                try:
                    # Copy file from server's upload directory to user's chosen location
                    import shutil
                    shutil.copy2(file_path, save_path)
                    messagebox.showinfo("Success", "File saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file: {e}")

    def handle_dh_init(self, sender, public_key_str):
        try:
            print(f"Received DH_INIT from {sender}")
            our_public_key = self.secure_chat.initialize_dh()
            peer_public_key = public_key_str.encode()

            # Compute shared key
            shared_key = self.secure_chat.compute_shared_key(peer_public_key)
            self.secure_chat.shared_keys[sender] = shared_key
            print(f"Computed shared key for {sender}")

            # Send our public key back
            self.client_socket.send(f"DH_REPLY|{sender}|{our_public_key.decode()}".encode())
            print(f"Sent DH_REPLY to {sender}")

            # Open chat window after key exchange
            self.root.after(0, lambda: self.open_private_chat(sender))
        except Exception as e:
            print(f"Error in handle_dh_init: {e}")

    def handle_dh_reply(self, sender, public_key_str):
        try:
            print(f"Received DH_REPLY from {sender}")
            peer_public_key = public_key_str.encode()
            shared_key = self.secure_chat.compute_shared_key(peer_public_key)
            self.secure_chat.shared_keys[sender] = shared_key
            print(f"Computed shared key for {sender}")

            # Open chat window after key exchange
            self.root.after(0, lambda: self.open_private_chat(sender))
        except Exception as e:
            print(f"Error in handle_dh_reply: {e}")

    def display_private_message(self, sender, message):
        if sender not in self.private_chat_windows:
            self.open_private_chat(sender)

        window = self.private_chat_windows[sender]
        if hasattr(window, 'chat_display'):
            window.chat_display.configure(state='normal')
            window.chat_display.insert(tk.END, f"{sender}: {message}\n")
            window.chat_display.configure(state='disabled')
            window.chat_display.see(tk.END)
            window.lift()  # Bring window to front

    def handle_secure_message(self, sender, encrypted_message):
        try:
            if sender in self.secure_chat.shared_keys:
                shared_key = self.secure_chat.shared_keys[sender]
                decrypted_message = self.secure_chat.decrypt_message(encrypted_message, shared_key)
                print(f"Decrypted message from {sender}")
                self.display_private_message(sender, decrypted_message)
            else:
                print(f"No shared key for {sender}")
                messagebox.showerror("Error", "Received message without encryption key")
        except Exception as e:
            print(f"Error handling secure message: {e}")


    def logout(self):
        if self.connected:
            self.client_socket.send("logout".encode())
            self.client_socket.close()
            self.connected = False
        self.username = None
        self.show_login_frame()
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    client = ChatClient()
    client.run()