import base64
from RSA_utils import decrypt_data_with_rsa

# Paste your encrypted base64 data here
encrypted_data = "i6RMikTit4q/dLEk2Fmsx0pGvxcElGfdcdWcGI2m1qRpdxrqz32aGSUGT04LDly/VKKPP7VtpL8G8S6DrcAnk8DwXXudgN6G/PbutS2L7Zu7W5v8uSqdM1+ycD8rCBMCeyI72HF6306ODxz2Q9GDVePuWwfrDo+BLkGIJAP9szeB3JkIp2Pg+QOgNOu1Lo4r+8b3L2aeYj1700GHKxkcXNeK23mJF2WjNQWBr7Sjne8GD9V567HZ6A+P8UD0Ns1dbwCge9ppmVMG4Bv5PXnoP+OMs68reralcIoj9SC7J10VT6fFNq5KhJ3SCDOgYFBPxS1V6ITuvvxm9QUzlgmEnA=="

# Load the private key
with open("private_key.pem", "rb") as priv_file:
    private_key = priv_file.read()

# Attempt decryption
try:
    decrypted_data = decrypt_data_with_rsa(encrypted_data, private_key)
    print("Decrypted data:", decrypted_data)
except Exception as e:
    print("Decryption failed with error:", e)
