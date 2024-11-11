import hashlib
import os

def hash_password(password: str) -> str:
    """Hash a password with SHA-256 and return the salt and hash."""
    # Generate a random 16-byte salt
    salt = os.urandom(16)
    # Combine the salt with the password and hash it using SHA-256
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    # Return the salt and hash as a combined string (hex encoded for storage)
    return salt.hex() + ":" + pwd_hash

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verify a password against the stored salt and hash."""
    # Split the stored password into salt and hash
    salt, pwd_hash = stored_password.split(':')
    # Convert the hex salt back to bytes
    salt_bytes = bytes.fromhex(salt)
    # Re-hash the provided password with the extracted salt
    provided_hash = hashlib.sha256(salt_bytes + provided_password.encode()).hexdigest()
    # Compare the hashes to verify password
    return pwd_hash == provided_hash
