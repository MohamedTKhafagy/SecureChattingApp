from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os

class AES:

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