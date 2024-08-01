import sys
import traceback
import logging
from asyncio import open_connection, create_task, gather, IncompleteReadError
from socket import inet_ntoa
from struct import unpack
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac
import os
from packet import Packet

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Connection:
    def __init__(self, client_reader, client_writer, proxy_host, proxy_port):
        self.proxy = {
            "host": proxy_host,
            "port": proxy_port,
            "public_key": self.import_RSA_key("public"),
            "private_key": self.import_RSA_key("private"),
            "master_key": b'',
            "iv": b''
        }
        
        self.client = {
            "reader": client_reader,
            "writer": client_writer,
            "host": client_writer.get_extra_info('peername')[0],
            "port": client_writer.get_extra_info('peername')[1],
        }
        
        self.server = {
            "reader": None,
            "writer": None,
            "host": None,
            "port": None,
        }

    def import_RSA_key(self, x):
        try:
            if x == "public":
                full_path = os.path.join(CURRENT_DIR, 'keys/public_key.pem')
                with open(full_path, "rb") as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
                return public_key
            elif x == "private":
                full_path = os.path.join(CURRENT_DIR, 'keys/private_key.pem')
                with open(full_path, "rb") as key_file:
                    private_key = serialization.load_pem_private_key(key_file.read(), password=None)
                return private_key
        except Exception as e:
            logger.error(f"Error importing RSA key: {e}")
            exit()
            raise

    async def start(self):
        try:
            await self.complete_proxify_handshake()
            logger.info("PROXIFY HANDSHAKE COMPLETE")
            logger.info(f"  client address = {self.client['host'], self.client['port']}")
            logger.info(f"  server address = {self.server['host'], self.server['port']}")

            await self.complete_tls_handshake()
            logger.info("TLS HANDSHAKE COMPLETE")
            logger.info(f"  client address = {self.client['host'], self.client['port']}")
            logger.info(f"  server address = {self.server['host'], self.server['port']}")

            await self.manage_conversation()
        except Exception as e:
            logger.error(f"Error in start method: {e}")
            logger.debug(traceback.format_exc())
            exit()
        finally:
            logger.info("Connection closed")

    async def read_message(self, reader):
        try:
            header = await reader.read(21)
            if not header:
                return None, None
            length = unpack("<I", header[4:8])[0]
            payload = await reader.readexactly(length)
            return header, payload
        except IncompleteReadError as e:
            logger.error(f"Incomplete read error: {e}")
            return None, None
        except Exception as e:
            logger.error(f"Error reading message: {e}")
            logger.debug(traceback.format_exc())
            exit()
            return None, None

    async def write_message(self, writer, header, payload):
        try:
            writer.write(header + payload)
            await writer.drain()
        except ConnectionResetError as e:
            logger.warning(f"Connection reset while writing message: {e}")
            return False
            exit()
        except Exception as e:
            logger.error(f"Error writing message: {e}")
            logger.debug(traceback.format_exc())
            return False
        return True

    def intercept(self, header, payload, decrypt=False):
        try:
            if decrypt:
                payload = self.decrypt_payload(payload)
            packet = Packet(header, payload)
            packet.print_to_console()
            packet.write_to_file()
        except Exception as e:
            logger.error(f"Error intercepting message: {e}")
            logger.debug(traceback.format_exc())
            exit()

    def decrypt_payload(self, payload):
        try:
            cipher = Cipher(algorithms.AES(self.proxy["master_key"]), modes.CBC(self.proxy["iv"]), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(payload) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext
        except Exception as e:
            logger.error(f"Error decrypting payload: {e}")
            logger.debug(traceback.format_exc())
            exit()
            raise

    async def complete_proxify_handshake(self):
        try:
            x = await self.client["reader"].read(3)
            logger.debug(f"Received from client: {x.hex()}")

            self.client["writer"].write(b'\x05\x00')
            await self.client["writer"].drain()
            logger.debug("Sent to client: 05 00")

            x = await self.client["reader"].read(10)
            logger.debug(f"Received from client: {x.hex()}")

            self.server["host"] = inet_ntoa(x[4:8])
            self.server["port"] = unpack("!H", x[8:10])[0]
            self.server["reader"], self.server["writer"] = await open_connection(self.server["host"], self.server["port"])
            logger.info(f"Connected to server: {self.server['host']}:{self.server['port']}")

            self.client["writer"].write(b'\x05\x00\x00\x01' + x[4:10])
            await self.client["writer"].drain()
            logger.debug(f"Sent to client: {b'05 00 00 01'.hex()} {x[4:10].hex()}")

        except Exception as e:
            logger.error(f"Error in proxify handshake: {e}")
            logger.debug(traceback.format_exc())
            exit()

    async def complete_tls_handshake(self):
        try:
            # Client Hello
            header, payload = await self.read_message(self.client["reader"])
            logger.debug("Client Hello received")
            self.intercept(header, payload)
            client_random_bytes = payload[10:]
            await self.write_message(self.server["writer"], header, payload)

            # Server Hello
            header, payload = await self.read_message(self.server["reader"])
            logger.debug("Server Hello received")
            self.intercept(header, payload)
            server_random_bytes = payload[10:-269]
            server_modulus = int.from_bytes(payload[-256:], byteorder='big')
            server_public_numbers = rsa.RSAPublicNumbers(65537, server_modulus)
            server_key = server_public_numbers.public_key(backend=default_backend())
            
            proxy_public_key = self.proxy["public_key"]
            proxy_public_numbers = proxy_public_key.public_numbers()
            proxy_modulus = proxy_public_numbers.n
            proxy_modulus_bytes = proxy_modulus.to_bytes((proxy_modulus.bit_length() + 7) // 8, byteorder='big')
            payload = payload[:-256] + proxy_modulus_bytes
            await self.write_message(self.client["writer"], header, payload)

            # Client Key Exchange
            header, payload = await self.read_message(self.client["reader"])
            logger.debug("Client Key Exchange received")
            self.intercept(header, payload)
            decrypted_secret = self.rsa_decrypt(payload[10:], self.proxy["private_key"])
            encrypted_for_server = self.rsa_encrypt(decrypted_secret, server_key)
            self.gen_master_key(client_random_bytes, server_random_bytes, decrypted_secret)
            adjusted_payload = payload[:10] + encrypted_for_server
            await self.write_message(self.server["writer"], header, adjusted_payload)

            # Server Finished
            header, payload = await self.read_message(self.server["reader"])
            logger.debug("Server Finished received")
            self.intercept(header, payload)
            await self.write_message(self.client["writer"], header, payload)

        except Exception as e:
            logger.error(f"Error in TLS handshake: {e}")
            logger.debug(traceback.format_exc())
            exit()

    def rsa_decrypt(self, encrypted, private_key):
        try:
            decrypted = private_key.decrypt(encrypted, asymmetric_padding.PKCS1v15())
            return decrypted
        except Exception as e:
            logger.error(f"Error in RSA decryption: {e}")
            logger.debug(traceback.format_exc())
            raise

    def rsa_encrypt(self, data, public_key):
        try:
            encrypted = public_key.encrypt(data, asymmetric_padding.PKCS1v15())
            return encrypted
        except Exception as e:
            logger.error(f"Error in RSA encryption: {e}")
            logger.debug(traceback.format_exc())
            raise

    def gen_master_key(self, client_random_bytes, server_random_bytes, clientkey):
        try:
            master_secret = b"master secret"
            master_key = master_secret + client_random_bytes + server_random_bytes

            c1 = hmac.new(clientkey, master_key, hashlib.sha1).digest()
            f1 = hmac.new(clientkey, c1 + master_key, hashlib.sha1).digest()
            c2 = hmac.new(clientkey, c1, hashlib.sha1).digest()
            f2 = hmac.new(clientkey, c2 + master_key, hashlib.sha1).digest()
            c3 = hmac.new(clientkey, c2, hashlib.sha1).digest()
            f3 = hmac.new(clientkey, c3 + master_key, hashlib.sha1).digest()

            combined = f1 + f2 + f3
            self.proxy["master_key"] = combined[:32]
            self.proxy["iv"] = combined[32:48]
            logger.debug("Master key and IV generated")
        except Exception as e:
            logger.error(f"Error generating master key: {e}")
            logger.debug(traceback.format_exc())
            exit()

    async def manage_conversation(self):
        try:
            client_to_server = create_task(self.transfer_message(self.client["reader"], self.server["writer"]))
            server_to_client = create_task(self.transfer_message(self.server["reader"], self.client["writer"]))
            await gather(client_to_server, server_to_client)
        except Exception as e:
            logger.error(f"Error managing conversation: {e}")
            logger.debug(traceback.format_exc())
            exit()
        finally:
            logger.info("Conversation ended")

    async def transfer_message(self, reader, writer):
        try:
            while True:
                header, payload = await self.read_message(reader)
                if header is None:
                    logger.info("End of stream reached")
                    break
                success = await self.write_message(writer, header, payload)
                self.intercept(header, payload, decrypt=True)
                if not success:
                    logger.info("Failed to write message, ending transfer")
                    exit()
                    break
        except Exception as e:
            logger.error(f"Error transferring message: {e}")
            logger.debug(traceback.format_exc())
            exit()
        finally:
            logger.info("Closing connection")
            writer.close()
            await writer.wait_closed()