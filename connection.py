from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends   import default_backend
from asyncio import open_connection, create_task, gather, IncompleteReadError, get_event_loop
from socket  import inet_ntoa
from struct  import unpack, pack
from packet  import Packet
import hashlib
import hmac
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

filter_list = []


"""CONNECTION CLASS"""
class Connection:
    def __init__(self, client_reader, client_writer, proxy_host, proxy_port):

        self.proxy = {
                      "host"       : proxy_host,
                      "port"       : proxy_port,
                      "public_key" : self.import_RSA_key("public"),
                      "private_key": self.import_RSA_key("private"),
                      "master_key" : b'',
                      "iv"         : b''
                      }
        
        self.client = {
                       "reader"     : client_reader,
                       "writer"     : client_writer,
                       "host"       : client_writer.get_extra_info('peername')[0],
                       "port"       : client_writer.get_extra_info('peername')[1],
                       }
        
        self.server = {
                       "reader"     : None,
                       "writer"     : None,
                       "host"       : None,
                       "port"       : None,
                       }
        
        self.injection_buffer = []
    
    # called by proxy
    async def start(self):
        try:
            await self.complete_proxify_handshake()
            await self.complete_tls_handshake()
            await self.manage_conversation()
        except Exception as e:
            print(f"Error occurred: {str(e)}")
            exit(1)

    """INJECTION"""
    async def listen_for_command(self):
        while True:
            # Wait for user input
            command = await get_event_loop().run_in_executor(None, input)
            # inject the packet
            if command.upper() == "INJECT":
                self.inject_ping()

    def inject_ping(self):     
        # payload to inject
        op = bytes([0, 141, 76, 212, 177])
        encoded_1337 = pack('<Q', 1337)
        injection_packet = bytes(op) + encoded_1337
        # encrypt 
        encrypted_payload = self.encrypt_payload(injection_packet)

        # header
        header = bytes([84, 79, 90, 32, 16, 0, 0, 0, 255, 255, 255, 255, 0, 13, 0, 0, 0, 141, 76, 212, 177])
        packet = header + encrypted_payload

        # update buffer
        self.injection_buffer.append(packet)
        print("\n---")
        print("added to injection buffer")


    """CONVERSATION"""
    async def manage_conversation(self):     
        # listeners
        client_to_server = create_task(self.server_communication_stream(self.client["reader"], self.server["writer"], "send"))
        server_to_client = create_task(self.client_communication_stream(self.server["reader"], self.client["writer"], "recv"))
        command_listener = create_task(self.listen_for_command())
        await gather(client_to_server, server_to_client, command_listener) #start 

    async def server_communication_stream(self, reader, writer, type):
        state = 0
        processed_count = 0
        try:
            while True:
                if self.injection_buffer:  # inject packet if available
                    inject = True
                    injection_packet = self.injection_buffer.pop(0)
                    header = bytearray(injection_packet[:21])
                    payload = injection_packet[21:]

                    # Increment state for non-ping packets
                    if header[17:21] != bytes([141, 76, 212, 177]):
                        state += 1
                        header[8:12] = pack('<I', state)

                else: 
                    inject = False
                    try:
                        header, payload = await self.read_message(reader)
                        # Update state for all read packets
                        state += 1
                        header = bytearray(header)
                        header[8:12] = pack('<I', state)
                    except IncompleteReadError:
                        break  # End loop if socket closes

                # Process and forward the packet
                await self.intercept(bytes(header), payload, type, inject)
                await self.write_message(writer, bytes(header), payload)

        finally:
            # Cleanup
            writer.close()
            await writer.wait_closed()

    async def client_communication_stream(self, reader, writer, type):
        try:
            while True:
                # read
                try:
                    header, payload = await self.read_message(reader)
                except IncompleteReadError:
                    break
                # intercept
                await self.intercept(header, payload, type, False)
                # write
                await self.write_message(writer, header, payload)
        finally:
            # cleanup
            writer.close()
            await writer.wait_closed()
    
    async def read_message(self, reader):
        try:
            # header
            header = await reader.readexactly(21)
            # payload
            length = unpack("<I", header[4:8])[0]
            payload = await reader.readexactly(length)
            # return message
            return header, payload
        # marks end of stream
        except IncompleteReadError:
            raise
                
    async def write_message(self, writer, header, payload):
        try:
            writer.write(header + payload)
            await writer.drain()  # ensure entire message sent
        except Exception as e:
            print(f"Error writing message: {str(e)}")
            raise
    
    async def intercept(self, header, payload, type, inject):
        try:
            # get packet info
            payload = self.decrypt_payload(payload)
            packet = Packet(header, payload, type, self.client["port"], inject)
            # filter
            # if packet.header_data["name"] not in filter_list:
                # await packet.print_to_console()
            # await packet.write_to_file("log.txt")
        except Exception as e:
            print(f"Error intercepting packet: {str(e)}")
            raise
    
    def decrypt_payload(self, payload):
        try:
            cipher = Cipher(algorithms.AES(self.proxy["master_key"]), modes.CBC(self.proxy["iv"]), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(payload) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext
        except Exception as e:
            print(f"Error decrypting payload: {str(e)}")
            raise
    
    def encrypt_payload(self, plaintext):
        try:
            # Create a padder
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_plaintext = padder.update(plaintext) + padder.finalize()

            # Create the cipher
            cipher = Cipher(algorithms.AES(self.proxy["master_key"]), 
                            modes.CBC(self.proxy["iv"]), 
                            backend=default_backend())
            
            # Create an encryptor
            encryptor = cipher.encryptor()

            # Encrypt the padded plaintext
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            return ciphertext
        except Exception as e:
            print(f"Error encrypting payload: {str(e)}")
            raise


    """PROXIFY HANDSHAKE"""
    async def complete_proxify_handshake(self):
        # client -> proxy
        x = await self.client["reader"].read(3)
        if x != b'\x05\01\x00':
            return False

        # proxy -> client
        self.client["writer"].write(b'\x05\x00')
        await self.client["writer"].drain()

        # client -> proxy
        x = await self.client["reader"].read(10)
        self.server["host"] = inet_ntoa(x[4:8])
        self.server["port"] = unpack("!H", x[8:10])[0]
        self.server["reader"], self.server["writer"] = await open_connection(self.server["host"],self.server["port"])
        
        # proxy -> client
        self.client["writer"].write(b'\x05\x00\x00\x01' + x[4:10])
        await self.client["writer"].drain()


    """TLS HANDSHAKE"""
    async def complete_tls_handshake(self):
        # client -> server
        header, payload = await self.read_message(self.client["reader"]) #read
        client_random_bytes = payload[10:]                               
        await self.write_message(self.server["writer"], header, payload) #write

        # server -> client
        header, payload = await self.read_message(self.server["reader"])  # read
        # randoms
        server_random_bytes = payload[10:-269]
        # server key
        server_modulus = int.from_bytes(payload[-256:], byteorder='big')
        server_public_numbers = rsa.RSAPublicNumbers(65537, server_modulus)
        server_key = server_public_numbers.public_key(backend=default_backend())
        # proxy key
        proxy_public_key = self.proxy["public_key"]
        proxy_public_numbers = proxy_public_key.public_numbers()
        proxy_modulus = proxy_public_numbers.n
        proxy_modulus_bytes = proxy_modulus.to_bytes(
            (proxy_modulus.bit_length() + 7) // 8, byteorder='big')
        # adjust payload
        payload = payload[:-256] + proxy_modulus_bytes
        await self.write_message(self.client["writer"], header, payload)  # write

        # client -> server
        header, payload = await self.read_message(self.client["reader"]) #read
        decrypted_secret   = self.rsa_decrypt(                           
                                              payload[10:], 
                                              self.proxy["private_key"]
                                             )
        encrypted_for_server = self.rsa_encrypt(
                                                decrypted_secret, 
                                                server_key 
                                               )
        self.gen_master_key(                        
                            client_random_bytes, 
                            server_random_bytes, 
                            decrypted_secret
                           )
        adjusted_payload = payload[:10] + encrypted_for_server
        await self.write_message(self.server["writer"], header, adjusted_payload) #write

        # server -> client
        header, payload = await self.read_message(self.server["reader"]) #read 
        await self.write_message(self.client["writer"], header, payload) #write

    def rsa_decrypt(self, encrypted, private_key):
        decrypted = private_key.decrypt(
                encrypted,
                asymmetric_padding.PKCS1v15()
            )
        return decrypted

    def rsa_encrypt(self, data, public_key):
        encrypted = public_key.encrypt(
                data,
                asymmetric_padding.PKCS1v15()
            )
        return encrypted
   
    def gen_master_key(self, client_random_bytes, server_random_bytes, clientkey):
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
        

    """HELPERS"""
    def import_RSA_key(self, x):
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
    