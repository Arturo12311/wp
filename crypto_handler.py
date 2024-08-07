"""IMPORTS"""
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac

import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


############################################################################


"""MAIN CODE"""
class Crypto():

    # rsa keys for mitm
    @staticmethod
    def import_RSA_key(x):

        # import pub key
        if x == "public":

            # read pub key file
            full_path = os.path.join(CURRENT_DIR, 'keys/public_key.pem')
            with open(full_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )

            # return pub key obj
            return public_key

        # import priv key
        elif x == "private":

            # read priv key file
            full_path = os.path.join(CURRENT_DIR, 'keys/private_key.pem')
            with open(full_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None  
                )

            # return priv key obj
            return private_key
    

    # decrypt premaster secret
    @staticmethod
    def rsa_decrypt(encrypted, private_key):

        # use private key to decrypt
        decrypted = private_key.decrypt(
                encrypted,
                asymmetric_padding.PKCS1v15()
            )
        
        # return decrypted value
        return decrypted


    # encrypt premaster secret
    @staticmethod
    def rsa_encrypt(data, public_key):

        # use public key to encrypt
        encrypted = public_key.encrypt(
                data,
                asymmetric_padding.PKCS1v15()
            )
        
        # return encrypted value
        return encrypted
    

    # generates master key 
    @staticmethod
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

        # return master_key and iv (aes cipher)
        return master_key, iv


    # decrypt payload with cipher 
    @staticmethod
    def decrypt_payload(payload, master_key, iv):
        try:
            cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(payload) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            # return decrypted payload
            return plaintext
        
        except Exception as e:
            print(f"Error decrypting payload: {str(e)}")
            raise
    

    # encrypt payload with cipher 
    @staticmethod
    def encrypt_payload(plaintext, master_key, iv):
        try:
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            # return encrypted payload
            return ciphertext

        except Exception as e:
            print(f"Error encrypting payload: {str(e)}")
            raise