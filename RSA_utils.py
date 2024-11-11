from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate a new RSA key pair
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt data using the RSA public key
def encrypt_data_with_rsa(data: str, public_key: bytes) -> str:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_data = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted_data).decode()

# Decrypt data using the RSA private key
def decrypt_data_with_rsa(encrypted_data: str, private_key: bytes) -> str:
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    # Decode from base64, ensure it is bytes before decrypting
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
    return decrypted_data.decode('utf-8')