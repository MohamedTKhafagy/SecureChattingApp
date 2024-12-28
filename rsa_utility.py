from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
#RSA
def generate_rsa_keys():
    """
    Generate an RSA key pair (private and public keys).
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode('utf-8'), public_key.decode('utf-8')


def ensure_key_format(key):
    """Ensure the key is in the correct format for PyCryptodome.

    Args:
    - key (bytes or str): The key to format

    Returns:
    - RSA key object
    """
    # If it's already a PyCryptodome key object, return it
    if hasattr(key, 'publickey'):
        return key

    # If it's bytes, try to decode
    if isinstance(key, bytes):
        try:
            key = key.decode('utf-8')
        except:
            pass

    # If it's a string, ensure it's a proper PEM format
    if isinstance(key, str):
        # Ensure PEM format
        if not key.startswith('-----BEGIN'):
            # Try to reconstruct PEM format
            key = f"-----BEGIN RSA PRIVATE KEY-----\n{key}\n-----END RSA PRIVATE KEY-----"

        try:
            return RSA.import_key(key)
        except Exception as e:
            print(f"Key import error: {e}")
            raise ValueError(f"Unable to import key: {e}")

    raise ValueError("Unsupported key format")

def encrypt_messageByPublic(message,public_key):

    try:
        # Ensure key is in the correct format
        #key = ensure_key_format(public_key)
        key = RSA.import_key(public_key)

        # Create a cipher using the public key
        cipher = PKCS1_OAEP.new(key)

        # Encrypt the message
        encrypted_message = cipher.encrypt(message.encode('utf-8'))

        # Base64 encode the encrypted message
        return base64.b64encode(encrypted_message).decode('utf-8')

    except Exception as e:
        print(f"Encryption error: {e}")
        raise

def decrypt_message(private_key, encrypted_message):
    """
    Decrypt an encrypted message using the private key.

    Args:
    - private_key (bytes or str): The private key
    - encrypted_message (str): The base64 encoded encrypted message
    """

    try:
        # Ensure key is in the correct format
        key = ensure_key_format(private_key)

        # Create a cipher using the private key
        cipher = PKCS1_OAEP.new(key)

        # Decode the base64 encoded message
        encrypted_data = base64.b64decode(encrypted_message)

        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_data)

        return decrypted_message.decode('utf-8')

    except Exception as e:
        print(f"Decryption error: {e}")
        raise

if __name__ == "__main__":
    # Test the RSA utility functions
    print("Generating RSA keys...")
    private_key, public_key = generate_rsa_keys()
    print(f"Private Key:\n{private_key}\n")
    print(f"Public Key:\n{public_key}\n")

    # Test encryption and decryption
    message = "Hello, this is a test message!"
    print(f"Original Message: {message}\n")

    #encrypted = encrypt_message(public_key, message)
    #print(f"Encrypted Message: {encrypted}\n")

    #decrypted = decrypt_message(private_key, encrypted)
    #print(f"Decrypted Message: {decrypted}\n")
