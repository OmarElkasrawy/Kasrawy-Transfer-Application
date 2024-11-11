from RSA_utils import generate_keys

# Generate the RSA key pair
private_key, public_key = generate_keys()

# Save the private key to a file
with open("private_key.pem", "wb") as priv_file:
    priv_file.write(private_key)

# Save the public key to a file
with open("public_key.pem", "wb") as pub_file:
    pub_file.write(public_key)
