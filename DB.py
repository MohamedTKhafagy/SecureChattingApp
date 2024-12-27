import sqlite3

def initialize_database():
    # Connect to SQLite database (or create it if it doesn't exist)
    conn = sqlite3.connect("ChatApp.db")
    cursor = conn.cursor()

    # Create the users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender) REFERENCES users (username)
        )
    """)

    # Commit changes and close the connection
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

#
# def add_hash_column():
#     try:
#         conn = sqlite3.connect("ChatApp.db")
#         cursor = conn.cursor()
#
#         # Add hash column to the broadcast_messages table
#         cursor.execute("ALTER TABLE broadcast_messages ADD COLUMN hash TEXT")
#         conn.commit()
#         print("Hash column added successfully.")
#     except sqlite3.OperationalError as e:
#         if "duplicate column name: hash" in str(e).lower():
#             print("Hash column already exists.")
#         else:
#             print(f"Error adding hash column: {e}")
#     finally:
#         conn.close()


if __name__ == "__main__":
    initialize_database()
    # add_hash_column()