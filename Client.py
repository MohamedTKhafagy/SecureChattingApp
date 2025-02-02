import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
from tkinter.scrolledtext import ScrolledText
from rsa_utility import *

from KeyManagement import *
import time
import datetime
from Hashing import *

# Client
class ChatClient:
    def __init__(self):
        # Main window setup
        self.root = tk.Tk()
        self.root.title("Chat Application")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)

        self.connected = False
        self.username = None
        self.client_socket = None

        # Create main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Initialize frames
        self.setup_login_frame()
        self.setup_chat_frame()

        # Show login frame initially
        self.show_login_frame()

        # Track chat windows and states
        self.private_chat_windows = {}
        self.pending_chat_requests = set()  # Track pending requests
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
        self.message_entry.bind("<Return>", lambda e: self.send_broadcast_message())

        ttk.Button(input_frame, text="Send", command=self.send_broadcast_message).pack(side=tk.LEFT)

        # Action buttons
        actions_frame = ttk.Frame(left_panel)
        actions_frame.pack(fill=tk.X)

        ttk.Button(actions_frame, text="Start New Chat", command=self.start_chat).pack(side=tk.LEFT, padx=5)
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
                    #print(f"Received message: {message[:50]}...")  # Debug print
                    if message.startswith("BROADCAST_MESSAGE\n"):
                        encrypted_message = message[len("BROADCAST_MESSAGE\n"):]
                        try:
                            print("Hello")
                            keyManager = KeyManagement()
                            private_key = keyManager.load_private_key(self.username)
                            decrypted_message = decrypt_message(private_key, encrypted_message)
                            # Log the encrypted and decrypted messages
                            print(f"Received (Encrypted): {encrypted_message}")
                            print(f"Decrypted Broadcast: {decrypted_message}")
                            self.update_chat_display(decrypted_message)
                        except Exception as e:
                            print(f"Error decrypting broadcast message: {e}")
                    elif message == "HISTORY_START":
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
                    elif message.startswith("DH_INIT|"):
                        _, sender, public_key = message.split("|")
                        self.handle_dh_init(sender, public_key)
                    elif message.startswith("DH_REPLY|"):
                        _, sender, public_key = message.split("|")
                        self.handle_dh_reply(sender, public_key)
                    elif message.startswith("SECURE_MESSAGE|"):
                        _, sender, encrypted_message = message.split("|")
                        self.handle_secure_message(sender, encrypted_message)
                    elif message.startswith("SECURE_FILE|"):
                        _, sender, file_name, file_size = message.split("|")
                        self.handle_secure_file(sender, file_name, int(file_size))
                    else:
                        self.update_chat_display(message)
            except:
                self.connected = False
                break

    def send_broadcast_message(self):
        message = self.message_entry.get().strip()
        if message:
            keyManager = KeyManagement()
            server_public_key =  keyManager.load_server_public_key()
            print(server_public_key)
            message_hash = Hashing.hash_content(message)
            encrypted_message = encrypt_messageByPublic(message, server_public_key)
            self.client_socket.send(f"BROADCAST_MESSAGE\n{encrypted_message}\nHASH:{message_hash}".encode())
            try:
                server_response = self.client_socket.recv(1024).decode()
                if server_response.startswith("ERROR:"):
                    messagebox.showerror("Message Error", server_response)
                else:
                    self.message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send message: {e}")
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

    def save_user_keys(self, username, private_key, public_key):
        """
        Saves RSA keys to files named after the username.
        """
        # Create a keys directory if it doesn't exist
        keys_dir = "user_keys"
        os.makedirs(keys_dir, exist_ok=True)

        # Generate filenames based on username
        private_key_file = os.path.join(keys_dir, f"{username}_private.pem")
        public_key_file = os.path.join(keys_dir, f"{username}_public.pem")

        # Save private key (expects bytes)
        with open(private_key_file, 'wb') as f:
            f.write(private_key)

        # Save public key (expects bytes)
        with open(public_key_file, 'wb') as f:
            f.write(public_key)

        return private_key_file, public_key_file

    def login(self):
        if not self.connect_to_server():
            return

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        try:
            hashed_password = Hashing.hash_content(password)
            # Send login command
            self.client_socket.send("login".encode())
            self.root.after(100)  # Small delay

            # Send credentials
            self.client_socket.send(username.encode())
            self.root.after(100)  # Small delay

            self.client_socket.send(hashed_password.encode())

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
            hashed_password = Hashing.hash_content(password)
            # Send registration command
            self.client_socket.send("register".encode())
            self.root.after(100)  # Small delay

            # Send credentials
            self.client_socket.send(username.encode())
            self.root.after(100)  # Small delay

            self.client_socket.send(hashed_password.encode())

            # Wait for response
            response = self.client_socket.recv(1024).decode()
            messagebox.showinfo("Registration", response)

            if "successfully" in response.lower():
                # Generate and save keys
                KeyManager = KeyManagement()
                private_key, public_key = KeyManager.generate_rsa_keys()  # Now returns bytes
                self.save_user_keys(username, private_key, public_key)  # Pass bytes

                # Send public key to server
                self.client_socket.send("register_key".encode())
                self.client_socket.send(public_key)  # Send bytes directly, no need to encode

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
            # test valid and invalid hash

            message_hash = Hashing.hash_content(message)
            # altered_hash = "INVALID_HASH"  # Replace the correct hash with an invalid one
            # self.client_socket.send(f"MESSAGE\n{message}\nHASH:{altered_hash}".encode())
            self.client_socket.send(f"MESSAGE\n{message}\nHASH:{message_hash}".encode())

            try:
                server_response = self.client_socket.recv(1024).decode()
                if server_response.startswith("ERROR:"):
                    messagebox.showerror("Message Error", server_response)
                else:
                    self.message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send message: {e}")

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

        # Check if chat is already pending or window exists
        if recipient in self.pending_chat_requests:
            messagebox.showinfo("Info", "Chat request already pending")
            return

        if recipient in self.private_chat_windows and self.private_chat_windows[recipient].winfo_exists():
            self.private_chat_windows[recipient].lift()
            return

        # Send chat request and mark as pending
        self.client_socket.send(f"START_CHAT\n{recipient}".encode())
        self.pending_chat_requests.add(recipient)

    def handle_chat_request(self, sender):
        # If we already have a chat window with this user, just focus it
        if sender in self.private_chat_windows and self.private_chat_windows[sender].winfo_exists():
            self.private_chat_windows[sender].lift()
            return

        # If we have a pending request to this user, handle as automatic accept
        # to avoid duplicate requests
        if sender in self.pending_chat_requests:
            self.client_socket.send(f"CHAT_RESPONSE\n{sender}\naccept".encode())
            public_key = self.secure_chat.initialize_dh()
            self.client_socket.send(f"DH_INIT|{sender}|{public_key.decode()}".encode())
            return

        # Otherwise, show the request dialog
        response = messagebox.askyesno("Chat Request",
                                       f"{sender} wants to start a secure private chat. Accept?")

        if response:
            self.client_socket.send(f"CHAT_RESPONSE\n{sender}\naccept".encode())
            public_key = self.secure_chat.initialize_dh()
            self.client_socket.send(f"DH_INIT|{sender}|{public_key.decode()}".encode())
        else:
            self.client_socket.send(f"CHAT_RESPONSE\n{sender}\nrefuse".encode())

    def handle_secure_file(self, sender, file_name, file_size):
        try:
            if sender not in self.secure_chat.shared_keys:
                print(f"No shared key for {sender}")
                return

            # Receive encrypted file data
            encrypted_data = b""
            remaining = file_size
            while remaining > 0:
                chunk = self.client_socket.recv(min(remaining, 8192))
                if not chunk:
                    break
                encrypted_data += chunk
                remaining -= len(chunk)

            # Decrypt file
            shared_key = self.secure_chat.shared_keys[sender]
            decrypted_data = self.secure_chat.decrypt_file(encrypted_data, shared_key)

            # Save file
            os.makedirs("downloads", exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            save_path = os.path.join("downloads", f"{timestamp}_{file_name}")

            with open(save_path, 'wb') as file:
                file.write(decrypted_data)

            # Display notification in chat window
            if sender in self.private_chat_windows:
                window = self.private_chat_windows[sender]
                if hasattr(window, 'chat_display'):
                    window.chat_display.configure(state='normal')
                    window.chat_display.insert(tk.END, f"{sender} sent file: {file_name} (saved to {save_path})\n")
                    window.chat_display.configure(state='disabled')
                    window.chat_display.see(tk.END)
                    window.lift()

        except Exception as e:
            print(f"Error handling secure file: {e}")

    def open_private_chat(self, with_user):
        # Check for existing window
        if with_user in self.private_chat_windows:
            window = self.private_chat_windows[with_user]
            if window.winfo_exists():
                window.lift()
                return window

        # Create new window
        private_chat_window = tk.Toplevel(self.root)
        private_chat_window.title(f"Secure Chat with {with_user}")
        private_chat_window.geometry("500x400")

        # Add close handler
        private_chat_window.protocol("WM_DELETE_WINDOW",
                                     lambda: self.handle_chat_window_close(with_user, private_chat_window))

        chat_display = ScrolledText(private_chat_window, wrap=tk.WORD, height=20)
        chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        def send_secure_message():
            message = message_entry.get().strip()
            if message and with_user in self.secure_chat.shared_keys:
                try:
                    shared_key = self.secure_chat.shared_keys[with_user]
                    encrypted_message = self.secure_chat.encrypt_message(message, shared_key)
                    self.client_socket.send(f"SECURE_MESSAGE|{with_user}|{encrypted_message}".encode())

                    chat_display.configure(state='normal')
                    chat_display.insert(tk.END, f"You: {message}\n")
                    chat_display.configure(state='disabled')
                    chat_display.see(tk.END)
                    message_entry.delete(0, tk.END)
                except Exception as e:
                    print(f"Error sending message: {e}")
                    messagebox.showerror("Error", "Failed to send message")
            elif not with_user in self.secure_chat.shared_keys:
                messagebox.showinfo("Info", "Secure chat connection not yet established")

        input_frame = ttk.Frame(private_chat_window)
        input_frame.pack(fill=tk.X, pady=(0, 5))

        message_entry = ttk.Entry(input_frame)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        # Add send file button
        def send_secure_file():
            if with_user not in self.secure_chat.shared_keys:
                messagebox.showinfo("Info", "Secure chat connection not yet established")
                return

            file_path = filedialog.askopenfilename()
            if not file_path:
                return

            try:
                file_size = os.path.getsize(file_path)
                if file_size > 10_000_000:  # 10MB limit
                    messagebox.showerror("Error", "File is too large. Maximum size is 10MB.")
                    return

                shared_key = self.secure_chat.shared_keys[with_user]
                file_name = os.path.basename(file_path)

                # Read and encrypt file
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                encrypted_data = self.secure_chat.encrypt_file(file_data, shared_key)

                # Send encrypted file
                self.client_socket.send(f"SECURE_FILE|{with_user}|{file_name}|{len(encrypted_data)}".encode())
                time.sleep(0.1)  # Small delay to ensure header is processed
                self.client_socket.sendall(encrypted_data)

                chat_display.configure(state='normal')
                chat_display.insert(tk.END, f"You sent file: {file_name}\n")
                chat_display.configure(state='disabled')
                chat_display.see(tk.END)

            except Exception as e:
                messagebox.showerror("Error", f"Failed to send file: {e}")

        send_button = ttk.Button(input_frame, text="Send", command=send_secure_message)
        send_button.pack(side=tk.LEFT)

        file_button = ttk.Button(input_frame, text="Send File", command=send_secure_file)
        file_button.pack(side=tk.LEFT, padx=(5, 0))

        message_entry.bind("<Return>", lambda e: send_secure_message())

        # Store window and display
        private_chat_window.chat_display = chat_display
        self.private_chat_windows[with_user] = private_chat_window

        # Remove from pending requests if exists
        if with_user in self.pending_chat_requests:
            self.pending_chat_requests.remove(with_user)

        return private_chat_window

    def handle_dh_init(self, sender, public_key_str):
        try:
            print(f"Received DH_INIT from {sender}")
            if sender not in self.secure_chat.shared_keys:
                our_public_key = self.secure_chat.initialize_dh()
                peer_public_key = public_key_str.encode()

                # Compute shared key
                shared_key = self.secure_chat.compute_shared_key(peer_public_key)
                self.secure_chat.shared_keys[sender] = shared_key

                # Send our public key back
                self.client_socket.send(f"DH_REPLY|{sender}|{our_public_key.decode()}".encode())

                # Open chat window if needed
                self.root.after(0, lambda: self.open_private_chat(sender))
        except Exception as e:
            print(f"Error in DH init: {e}")

    def handle_dh_reply(self, sender, public_key_str):
        try:
            print(f"Received DH_REPLY from {sender}")
            if sender not in self.secure_chat.shared_keys:
                peer_public_key = public_key_str.encode()
                shared_key = self.secure_chat.compute_shared_key(peer_public_key)
                self.secure_chat.shared_keys[sender] = shared_key

                # Open chat window if needed
                self.root.after(0, lambda: self.open_private_chat(sender))
        except Exception as e:
            print(f"Error in DH reply: {e}")

    def display_private_message(self, sender, message):
        if sender not in self.private_chat_windows or not self.private_chat_windows[sender].winfo_exists():
            self.open_private_chat(sender)

        window = self.private_chat_windows[sender]
        if hasattr(window, 'chat_display'):
            window.chat_display.configure(state='normal')
            window.chat_display.insert(tk.END, f"{sender}: {message}\n")
            window.chat_display.configure(state='disabled')
            window.chat_display.see(tk.END)
            window.lift()

    def handle_chat_window_close(self, with_user, window):
        if with_user in self.private_chat_windows:
            del self.private_chat_windows[with_user]
        if with_user in self.secure_chat.shared_keys:
            del self.secure_chat.shared_keys[with_user]
        if with_user in self.pending_chat_requests:
            self.pending_chat_requests.remove(with_user)
        window.destroy()

    def handle_secure_message(self, sender, encrypted_message):
        try:
            if sender in self.secure_chat.shared_keys:
                shared_key = self.secure_chat.shared_keys[sender]
                decrypted_message = self.secure_chat.decrypt_message(encrypted_message, shared_key)
                self.display_private_message(sender, decrypted_message)
            else:
                print(f"No shared key for {sender}")
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