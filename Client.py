import socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
from tkinter.scrolledtext import ScrolledText
import os
from Hashing import Hashing


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
                    elif "HASH:" in message:
                        content, received_hash = message.split("\nHASH:", 1)
                        if Hashing.verify_content(content, received_hash):
                            self.update_chat_display(content)
                        else:
                            self.update_chat_display("Message verification failed!")
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

        except Exception as e:
            messagebox.showerror("Error", f"Registration failed: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            self.connected = False

    #actual without altered hash test
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
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                file_hash = Hashing.hash_content(file_data)
                self.client_socket.send(f"FILE\n{file_name}\n{file_size}\nHASH:{file_hash}".encode())
                self.client_socket.sendall(file_data)

                self.update_chat_display(f"File sent: {file_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to send file: {e}")

    def start_chat(self):
        selected = self.users_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select a user from the online users list")
            return

        recipient = self.users_listbox.get(selected[0])

        # Check if a private chat window already exists
        if recipient in self.private_chat_windows:
            try:
                if self.private_chat_windows[recipient].winfo_exists():
                    self.private_chat_windows[recipient].lift()
                    return
            except:
                pass

        # If no existing window, send chat request
        self.client_socket.send(f"START_CHAT\n{recipient}".encode())

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
        # Check if a window for this user already exists
        if with_user in self.private_chat_windows and self.private_chat_windows[with_user]:
            try:
                # Check if window is still valid
                if self.private_chat_windows[with_user].winfo_exists():
                    return self.private_chat_windows[with_user]
            except:
                pass

        # Create a new top-level window for private chat
        private_chat_window = tk.Toplevel(self.root)
        private_chat_window.title(f"Private Chat with {with_user}")
        private_chat_window.geometry("500x400")

        # Chat display area with more advanced text widget
        chat_display = tk.Text(
            private_chat_window,
            wrap=tk.WORD,
            height=20,
            state='disabled',  # Start in disabled state
            padx=10,
            pady=10
        )
        chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Configure tags for different message types
        chat_display.tag_configure('sender', foreground='blue')
        chat_display.tag_configure('you', foreground='green')
        chat_display.tag_configure('system', foreground='gray', font=('Arial', 10, 'italic'))

        # Scrollbar for text widget
        scrollbar = tk.Scrollbar(private_chat_window, command=chat_display.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        chat_display.config(yscrollcommand=scrollbar.set)
        input_frame = ttk.Frame(private_chat_window)
        input_frame.pack(fill=tk.X ,padx=(0,5))

        #message_entry = ttk.Entry(input_frame)
        #message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        def send_private_file():
            file_path = filedialog.askopenfilename()
            if file_path:
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 10_000_000:  # 10MB limit
                        messagebox.showerror("Error", "File is too large. Maximum size is 10MB.")
                        return

                    file_name = os.path.basename(file_path)
                    with open(file_path, 'rb') as file:
                        file_data = file.read()

                    # test valid/invalid hash
                    file_hash = Hashing.hash_content(file_data)
                    # altered_hash= "INVALID_HASH"
                    self.client_socket.send(
                        f"PRIVATE_FILE\n{with_user}\n{file_name}\n{file_size}\nHASH:{file_hash}".encode())

                    # Send the actual file data
                    self.client_socket.sendall(file_data)

                    # Notify the chat window
                    append_message(f"You sent file: {file_name}", 'you')
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to send file: {e}")
        # Add Send File button

        # Add a method to safely append messages
        def append_message(message, tag='sender'):
            def _append():
                chat_display.configure(state='normal')
                chat_display.tag_config(tag)
                chat_display.tag_add(tag, tk.END)
                chat_display.tag_add('all', tk.END)

                # Append message with specific tag
                chat_display.insert(tk.END, message + '\n', tag)

                # Auto-scroll to the end
                chat_display.see(tk.END)
                chat_display.configure(state='disabled')

            # Use after to ensure thread-safety
            private_chat_window.after(0, _append)

        # Store the append_message method with the window for later use
        private_chat_window.append_message = append_message

        # Message input area
        input_frame = ttk.Frame(private_chat_window)
        input_frame.pack(fill=tk.X, pady=(0, 5))

        message_entry = ttk.Entry(input_frame)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        def send_private_message():
            message = message_entry.get().strip()
            if message:
                # altered_hash = "INVALID_HASH"
                # self.client_socket.send(f"PRIVATE_MESSAGE\n{with_user}\n{message}\nHASH:{altered_hash}".encode())

                # Compute the hash of the message
                message_hash = Hashing.hash_content(message)

                # Send the message with the hash
                self.client_socket.send(f"PRIVATE_MESSAGE\n{with_user}\n{message}\nHASH:{message_hash}".encode())

                # Display the message in the chat window
                append_message(f"You: {message}", 'you')
                message_entry.delete(0, tk.END)

        ttk.Button(input_frame, text="Send", command=send_private_message).pack(side=tk.LEFT)
        ttk.Button(input_frame, text="Send File", command=send_private_file).pack(side=tk.LEFT)
        message_entry.bind("<Return>", lambda e: send_private_message())

        # Handle window close event
        def on_window_close():
            if with_user in self.private_chat_windows:
                del self.private_chat_windows[with_user]
            private_chat_window.destroy()

        private_chat_window.protocol("WM_DELETE_WINDOW", on_window_close)

        # Store the window
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

