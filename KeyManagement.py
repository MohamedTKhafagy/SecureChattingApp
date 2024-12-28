
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from AES import *
from Crypto.PublicKey import RSA
class SecureChatManager:
    #Class that performs diffie Hellman and handles calls symmetric encryption functions
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
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    def encrypt_message(self, message, shared_key):
        aes = AES()
        return aes.encrypt_message(message, shared_key)

    def decrypt_message(self, encrypted_message, shared_key):
        aes = AES()
        return aes.decrypt_message(encrypted_message, shared_key)

    def encrypt_file(self, file_data, shared_key):
        aes = AES()
        return aes.encrypt_file(file_data, shared_key)

    def decrypt_file(self, encrypted_data, shared_key):
        aes = AES()
        return aes.decrypt_file(encrypted_data, shared_key)

class KeyManagement:
    def __init__(self, db_path="ChatApp.db"):
        self.db_path = db_path

    def generate_rsa_keys(self):
        """
        Generate an RSA key pair (private and public keys).
        Returns the keys in bytes format.
        """
        key = RSA.generate(2048)
        private_key = key.export_key()  # Already returns bytes
        public_key = key.publickey().export_key()  # Already returns bytes
        return private_key, public_key  # Return bytes directly, don't decode

    def store_user_keys(self, username, public_key):
        """Store a user's public key in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE public_keys SET public_key = ? WHERE username = ?", (public_key, username))
        conn.commit()
        conn.close()

    def retrieve_public_key(self, username):
        """Retrieve a user's public key."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM public_keys WHERE username = ?", (username,))
        public_key = cursor.fetchone()
        conn.close()
        return public_key[0] if public_key else None

    def load_server_private_key(self):
        """
        Retrieves the private RSA key from file for a given username.
        """
        import os

        keys_dir = "user_keys"
        private_key_file = os.path.join(keys_dir, f"Server_private.pem")

        if not os.path.exists(private_key_file):
            raise FileNotFoundError(f"Private key file not found for username: server")

        with open(private_key_file, 'rb') as f:
            private_key = f.read()

        return private_key

    def load_server_public_key(self):
        """
        Retrieves the public RSA key from file for a given username.
        """
        import os

        keys_dir = "user_keys"
        public_key_file = os.path.join(keys_dir, f"Server_public.pem")

        if not os.path.exists(public_key_file):
            raise FileNotFoundError(f"Public key file not found for username: server")

        with open(public_key_file, 'rb') as f:
            public_key = f.read()

        return public_key


    def load_private_key(self, username):
        """
        Retrieves the private RSA key from file for a given username.
        """
        import os

        keys_dir = "user_keys"
        private_key_file = os.path.join(keys_dir, f"{username}_private.pem")

        if not os.path.exists(private_key_file):
            raise FileNotFoundError(f"Private key file not found for username: {username}")

        with open(private_key_file, 'rb') as f:
            return RSA.import_key(f.read())

        return private_key

    def load_public_key(self, username):
        """
        Retrieves the public RSA key from file for a given username.
        """
        import os

        keys_dir = "user_keys"
        public_key_file = os.path.join(keys_dir, f"{username}_public.pem")

        if not os.path.exists(public_key_file):
            raise FileNotFoundError(f"Public key file not found for username: {username}")

        with open(public_key_file, 'rb') as f:
            return RSA.import_key(f.read())

        return public_key