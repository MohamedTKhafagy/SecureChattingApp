import socket
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from threading import Thread
import os


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
        self.chat_display = scrolledtext.ScrolledText(left_panel, wrap=tk.WORD, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

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
                    if message.startswith("ONLINE_USERS:"):
                        self.update_online_users(message[13:].split(","))
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
        self.client_socket.send(f"START_CHAT\n{recipient}".encode())

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