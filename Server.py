import socket
import sqlite3
from threading import Thread, Lock
import time
import os
from datetime import datetime


class ChatServer:
    def __init__(self, host="0.0.0.0", port=5555):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)

        self.active_users = {}
        self.active_users_lock = Lock()
        self.active_chats = {}
        self.active_chats_lock = Lock()

        print(f"Server running on port {port}")
        self.initialize_database()

    def initialize_database(self):
        conn = sqlite3.connect("ChatApp.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT,
                message_type TEXT NOT NULL,
                content TEXT NOT NULL,
                file_path TEXT,
                sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender) REFERENCES users (username),
                FOREIGN KEY (receiver) REFERENCES users (username)
            )
        """)

        conn.commit()
        conn.close()
        print("Database initialized successfully.")

    def handle_client(self, client_socket, addr):
        username = None

        while True:
            try:
                # Wait for initial command
                command = client_socket.recv(1024).decode().strip()
                #print(f"Received command: {command}")  # Debug print

                if command == "register":
                    try:
                        # Receive registration details
                        username = client_socket.recv(1024).decode().strip()
                        password = client_socket.recv(1024).decode().strip()
                        print(f"Registration attempt for username: {username}")  # Debug print

                        # Check if username already exists
                        conn = sqlite3.connect("ChatApp.db")
                        cursor = conn.cursor()
                        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                        if cursor.fetchone():
                            client_socket.send("Username already exists!".encode())
                            conn.close()
                            continue

                        # Register new user
                        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                                       (username, password))
                        conn.commit()
                        conn.close()

                        client_socket.send("Account created successfully!".encode())
                        print(f"Registration successful for username: {username}")  # Debug print

                    except Exception as e:
                        error_msg = f"Registration failed: {str(e)}"
                        print(error_msg)  # Debug print
                        client_socket.send(error_msg.encode())

                elif command == "login":

                    username = client_socket.recv(1024).decode().strip()

                    password = client_socket.recv(1024).decode().strip()

                    conn = sqlite3.connect("ChatApp.db")

                    cursor = conn.cursor()

                    cursor.execute("SELECT username FROM users WHERE username = ? AND password = ?",

                                   (username, password))

                    if cursor.fetchone():

                        with self.active_users_lock:

                            if username in self.active_users:
                                client_socket.send("Already logged in from another location".encode())

                                conn.close()

                                continue

                            self.active_users[username] = client_socket

                        # Send login success message

                        client_socket.send("Login successful!".encode())

                        # Small delay to ensure login message is received

                        time.sleep(0.1)

                        # Send historical messages marker

                        client_socket.send("HISTORY_START".encode())

                        time.sleep(0.1)

                        # Load and send historical messages

                        historical_messages = self.load_historical_messages()

                        for msg in historical_messages:
                            sender, content, sent_at = msg

                            formatted_msg = f"HISTORY_MSG\n[{sent_at}] {sender}: {content}"

                            client_socket.send(formatted_msg.encode())

                            time.sleep(0.05)  # Small delay between messages

                        # Send end of history marker

                        time.sleep(0.1)

                        client_socket.send("HISTORY_END".encode())

                        conn.close()

                        break

                    else:

                        client_socket.send("Invalid username or password".encode())

                        conn.close()

                elif command == "quit":
                    break

            except Exception as e:
                print(f"Error in command handling: {e}")
                break

        # Main message loop after successful login
        while username in self.active_users:
            try:
                self.broadcast_online_users()
                data = client_socket.recv(1024).decode().strip()
                if not data:
                    break


                if data.startswith("DH_INIT|"):
                    _, recipient, public_key = data.split("|")
                    print(public_key)
                    if recipient in self.active_users:
                        recipient_socket = self.active_users[recipient]
                        recipient_socket.send(f"DH_INIT|{username}|{public_key}".encode())

                elif data.startswith("DH_REPLY|"):
                    _, recipient, public_key = data.split("|")
                    if recipient in self.active_users:
                        recipient_socket = self.active_users[recipient]
                        recipient_socket.send(f"DH_REPLY|{username}|{public_key}".encode())

                elif data.startswith("SECURE_MESSAGE|"):
                    _, recipient, encrypted_message = data.split("|")
                    print("Encrypted: ",encrypted_message)
                    if recipient in self.active_users:
                        recipient_socket = self.active_users[recipient]
                        recipient_socket.send(f"SECURE_MESSAGE|{username}|{encrypted_message}".encode())

                if data.startswith("PRIVATE_FILE\n"):
                    self.handle_private_file_transfer(username, client_socket, data)

                if data.startswith("MESSAGE\n"):
                    message = data[8:]
                    print(f"Broadcasting message from {username}: {message}")  # Debug print
                    self.broadcast_message(username, message)

                elif data.startswith("FILE\n"):
                    self.handle_file_transfer(client_socket, username)

                elif data == "show_online_users":
                    self.broadcast_online_users()

                elif data == "logout":
                    break

                elif data.startswith("START_CHAT\n"):
                    recipient = data.split("\n")[1]
                    self.handle_private_chat_request(username, recipient)

                elif data.startswith("CHAT_RESPONSE\n"):
                    parts = data.split("\n")
                    recipient = parts[1]
                    response = parts[2]  # "accept" or "refuse"
                    self.handle_chat_response(username, recipient, response)

                    # Add private message handling
                elif data.startswith("PRIVATE_MESSAGE\n"):
                    parts = data.split("\n")
                    recipient = parts[1]
                    message = parts[2]
                    self.send_private_message(username, recipient, message)

            except Exception as e:
                print(f"Error in message loop: {e}")
                break

        # Cleanup
        print(f"Client disconnected: {username}")
        if username in self.active_users:
            with self.active_users_lock:
                del self.active_users[username]
            self.broadcast_online_users()
        client_socket.close()

    def broadcast_online_users(self):
        with self.active_users_lock:
            users_list = ",".join(self.active_users.keys())
            message = f"ONLINE_USERS:{users_list}"
            for user_socket in self.active_users.values():
                try:
                    user_socket.send(message.encode())
                except:
                    continue

    def broadcast_message(self, sender, message):
        timestamp = datetime.now()
        formatted_message = f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {sender}: {message}"

        # Store message in database
        try:
            conn = sqlite3.connect("ChatApp.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO broadcast_messages (sender, content, sent_at)
                VALUES (?, ?, ?)
            """, (sender, message, timestamp))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error storing broadcast message: {e}")

        # Send to all active users
        with self.active_users_lock:
            for username, sock in self.active_users.items():
                    try:
                        sock.send(formatted_message.encode())
                    except:
                        continue

    def load_historical_messages(self):
        try:
            conn = sqlite3.connect("ChatApp.db")
            cursor = conn.cursor()
            # Get messages from the last 24 hours
            cursor.execute("""
                SELECT sender, content, sent_at 
                FROM broadcast_messages 
                ORDER BY sent_at DESC 
                LIMIT 50
            """)
            messages = cursor.fetchall()
            conn.close()
            return messages
        except Exception as e:
            print(f"Error loading historical messages: {e}")
            return []

    def handle_file_transfer(self, client_socket, username):
        try:
            file_name = client_socket.recv(1024).decode().strip()
            file_size = int(client_socket.recv(1024).decode().strip())

            os.makedirs("uploads", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_filename = f"uploads/{timestamp}_{username}_{file_name}"

            received_data = 0
            with open(unique_filename, 'wb') as file:
                while received_data < file_size:
                    data = client_socket.recv(min(file_size - received_data, 8192))
                    if not data:
                        break
                    file.write(data)
                    received_data += len(data)

            self.broadcast_message(username, f"shared a file: {file_name}")

        except Exception as e:
            print(f"File transfer error: {e}")
            client_socket.send(f"File transfer failed: {str(e)}".encode())

    def handle_private_chat_request(self, sender, recipient):
        # Check if recipient is online
        with self.active_users_lock:
            if recipient in self.active_users:
                recipient_socket = self.active_users[recipient]
                try:
                    # Send chat request to recipient
                    recipient_socket.send(f"CHAT_REQUEST:{sender}".encode())
                except Exception as e:
                    print(f"Error sending chat request: {e}")
                    return False
            else:
                return False
        return True

    def handle_private_file_transfer(self, sender, client_socket, data):
        try:
            _, recipient, file_name, file_size = data.split("\n")
            file_size = int(file_size)

            # Check if recipient is online
            with self.active_users_lock:
                if recipient not in self.active_users:
                    client_socket.send(f"Error: User {recipient} is not online.".encode())
                    return

                recipient_socket = self.active_users[recipient]

            # Create uploads directory if it doesn't exist
            os.makedirs("uploads", exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_filename = f"uploads/{timestamp}_{sender}_{file_name}"

            # Receive and save file
            received_data = 0
            with open(unique_filename, 'wb') as file:
                while received_data < file_size:
                    data = client_socket.recv(min(file_size - received_data, 8192))
                    if not data:
                        break
                    file.write(data)
                    received_data += len(data)

            # Notify recipient about the file
            try:
                notification = f"PRIVATE_FILE_NOTIFICATION\n{sender}\n{file_name}\n{unique_filename}"
                recipient_socket.send(notification.encode())
            except:
                print(f"Failed to notify recipient {recipient} about file")

        except Exception as e:
            print(f"Error in private file transfer: {e}")
            try:
                client_socket.send(f"File transfer failed: {str(e)}".encode())
            except:
                pass

    def handle_chat_response(self, sender, recipient, response):
        with self.active_users_lock:
            if recipient in self.active_users and sender in self.active_users:
                sender_socket = self.active_users[sender]
                recipient_socket = self.active_users[recipient]
                try:
                    # Forward response to sender
                    sender_socket.send(f"CHAT_RESPONSE:{recipient}:{response}".encode())
                except Exception as e:
                    print(f"Error sending chat response: {e}")

    def send_private_message(self, sender, recipient, message):
        with self.active_users_lock:
            if recipient in self.active_users:
                recipient_socket = self.active_users[recipient]
                try:
                    print(f"PRIVATE_MESSAGE:{sender}:{message}")
                    recipient_socket.send(f"PRIVATE_MESSAGE:{sender}:{message}".encode())
                except Exception as e:
                    print(f"Error sending private message: {e}")
    def run(self):
        print("Server is running and waiting for connections...")
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"New connection from {addr}")
                client_thread = Thread(target=self.handle_client,
                                       args=(client_socket, addr))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
                continue


if __name__ == "__main__":
    server = ChatServer()
    server.run()