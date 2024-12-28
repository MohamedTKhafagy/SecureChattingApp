import hashlib
#Hashing
class Hashing:
    @staticmethod
    def hash_content(content):
        """Generate SHA-256 hash of the content."""
        if isinstance(content, str):
            content = content.encode()
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def verify_content(content, hash_value):
        """Verify the hash of the content matches the provided hash."""
        return Hashing.hash_content(content) == hash_value
