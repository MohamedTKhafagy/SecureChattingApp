from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class BlockCipherHasher:
    def __init__(self):
        # Generate a random key and IV
        self.key = os.urandom(32)  # AES-256 key
        self.iv = os.urandom(16)   # AES block size is 16 bytes

    def encrypt(self, data):
        # Pad the data to be a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Create a Cipher object
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted_data
    
    def decrypt(self, encrypted_data):
        # Create a Cipher object
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def encrypt_text(self, text):
        return self.encrypt(text.encode())
    
    def decrypt_text(self, encrypted_text):
        return self.decrypt(encrypted_text).decode()


    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            file_data = file.read()
        return self.encrypt(file_data)
    
    def decrypt_file(self, encrypted_file_data, output_file_path):
        decrypted_data = self.decrypt(encrypted_file_data)
        with open(output_file_path, 'wb') as file:
            file.write(decrypted_data)

# Example usage
hasher = BlockCipherHasher()

# Encrypt a text message
encrypted_text = hasher.encrypt_text("Hello, World!")
print(f"Encrypted text: {encrypted_text}")

# Decrypt the text message
decrypted_text = hasher.decrypt_text(encrypted_text)
print(f"Decrypted text: {decrypted_text}")

# Encrypt a file
encrypted_file_data = hasher.encrypt_file("path/to/your/file.txt")
print(f"Encrypted file data: {encrypted_file_data}")


# Decrypt the file
hasher.decrypt_file(encrypted_file_data, "path/to/your/decrypted_file.txt")
print("File decrypted successfully")