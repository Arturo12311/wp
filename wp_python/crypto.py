import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

def import_RSA_key(x):
    if x == "public":
        full_path = os.path.join(CURRENT_DIR, 'keys/public_key.pem')
        with open(full_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key
    elif x == "private":
        full_path = os.path.join(CURRENT_DIR, 'keys/private_key.pem')
        with open(full_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None  
            )
        return private_key

def rsa_decrypt(encrypted, private_key):
    decrypted = private_key.decrypt(
            encrypted,
            asymmetric_padding.PKCS1v15()
        )
    return decrypted

def rsa_encrypt(data, public_key):
    encrypted = public_key.encrypt(
            data,
            asymmetric_padding.PKCS1v15()
        )
    return encrypted

def gen_master_key(client_random_bytes, server_random_bytes, clientkey):
    master_secret = b"master secret"
    master_key = master_secret + client_random_bytes + server_random_bytes

    c1 = hmac.new(clientkey, master_key, hashlib.sha1).digest()
    f1 = hmac.new(clientkey, c1 + master_key, hashlib.sha1).digest()
    c2 = hmac.new(clientkey, c1, hashlib.sha1).digest()
    f2 = hmac.new(clientkey, c2 + master_key, hashlib.sha1).digest()
    c3 = hmac.new(clientkey, c2, hashlib.sha1).digest()
    f3 = hmac.new(clientkey, c3 + master_key, hashlib.sha1).digest()

    combined = f1 + f2 + f3
    master_key = combined[:32]
    iv = combined[32:48]

    return master_key, iv
    
def decrypt_payload(payload, master_key, iv, stream):
    if stream == "send":
        cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    else:
        cipher = Cipher(algorithms.AES(master_key), modes.CTR(b'\x00' * 16), backend=default_backend())

    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(payload) + decryptor.finalize()
    return decrypted_data


def encrypt_payload(plaintext, master_key, iv):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext
