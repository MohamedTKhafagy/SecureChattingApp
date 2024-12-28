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

    # Create the public_keys table
    cursor.execute("""
           CREATE TABLE IF NOT EXISTS public_keys (
               username TEXT PRIMARY KEY,
               public_key TEXT NOT NULL
           )
       """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            hash TEXT,
            FOREIGN KEY (sender) REFERENCES users (username)
        )
    """)
    # Commit changes and close the connection
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    initialize_database()