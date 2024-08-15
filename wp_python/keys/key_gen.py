from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Generate a new RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save the private key (keep this secure!)
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

full_path = os.path.join(CURRENT_DIR, 'keys/private_key.pem')
with open(full_path, "wb") as key_file:
    key_file.write(pem_private_key)

# Extract and save the public key
public_key = private_key.public_key()
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

full_path = os.path.join(CURRENT_DIR, 'keys/public_key.pem')
with open(full_path, "wb") as key_file:
    key_file.write(pem_public_key)