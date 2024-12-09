from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # null
import base64

# AES_KEY must be consistent for both encryption and decryption
AES_KEY = b'\x02\xee\xa5\xc0\xbcv\xed;\xe7\x9f\x95\xc7\xeb&\xb94'  # 16 bytes (128 bits)

def encrypt_data(data: str) -> str:
    """Encrypts the data using AES CBC mode and returns it as a base64 string."""
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    iv = cipher.iv  # Initialization vector for CBC mode
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    # Return iv + encrypted data, base64 encoded for easy storage
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypts the base64-encoded data using AES CBC mode."""
    raw_data = base64.b64decode(encrypted_data)
    iv = raw_data[:16]  # First 16 bytes are the IV
    encrypted_data = raw_data[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()
