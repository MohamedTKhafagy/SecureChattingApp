import os
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

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
            algorithm=SHA256(),
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

    def encrypt_file(self, file_data, shared_key):
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(file_data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_file(self, encrypted_data, shared_key):
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        decryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()

class KeyManagement:
    def __init__(self, db_path="MailSecurity.db"):
        self.db_path = db_path

    #def generate_symmetric_key(self):
     #   """Generate a random 256-bit symmetric key."""
      #  return base64.urlsafe_b64encode(os.urandom(32)).decode()

    def generate_asymmetric_keys(self):
        """Generate RSA public and private keys."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem.decode(), public_pem.decode()

    def store_user_keys(self, username, public_key):
        """Store a user's public key in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET PublicKey = ? WHERE username = ?", (public_key, username))
        conn.commit()
        conn.close()

    def retrieve_public_key(self, username):
        """Retrieve a user's public key."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT PublicKey FROM users WHERE username = ?", (username,))
        public_key = cursor.fetchone()
        conn.close()
        return public_key[0] if public_key else None

class DiffieHellmanKeyExchange:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        """Return the public key serialized."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes):
        """Compute shared secret using the peer's public key."""
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
        shared_key = self.private_key.exchange(peer_public_key)

        # Derive a symmetric key from the shared secret
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,  # Optional: can include a salt for additional security
            info=b"secure key exchange",
            backend=default_backend()
        ).derive(shared_key)
        return derived_key
