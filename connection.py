from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from asyncio import open_connection, create_task, gather
from socket  import inet_ntoa
from struct  import unpack
from packet  import Packet
import hashlib
import hmac

import os 
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


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
                       "port"       : client_writer.get_extra_info('peername')[0],
                       }
        
        self.server = {
                       "reader"     : None,
                       "writer"     : None,
                       "host"       : None,
                       "port"       : None,
                       }
        

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
    
    async def start(self):
        await self.complete_proxify_handshake()
        print("\n---")
        print("PROXIFY HANDSHAKE COMPLETE")
        print(f"  client address = {self.client["host"], self.client["port"]}")
        print(f"  server address = {self.server["host"], self.server["port"]}")
        print("---\n")

        await self.complete_tls_handshake()
        print("\n---")
        print("TLS HANDSHAKE COMPLETE")
        print(f"  master key = {self.proxy["master_key"]}")
        print("---\n")

        await self.manage_conversation()
        print("CONVERSATION ENDED")
        print(f"  client address = {self.client["host"], self.client["port"]}")
        print(f"  server address = {self.server["host"], self.server["port"]}")
        print("---\n")
    
    async def read_message(self, reader):       
        header = await reader.readexactly(21)
        if header is None: 
            return None 
        length  = unpack("<I", header[4:8])[0]
        payload = await reader.readexactly(length)
        return header, payload
                
    async def write_message(self, writer, header, payload):
        await writer.write(header + payload)
        await writer.drain()
    
    async def intercept(self, header, payload):
        packet = Packet(header, payload)
        packet.print_to_console()
        packet.write_to_file()


    """PROXIFY HANDSHAKE"""
    async def complete_proxify_handshake(self):
        # client -> server
        await self.client["reader"].read(3)

        # server -> client
        await self.client["writer"].write(b'\x05\x00')
        await self.client["writer"].drain()

        # client -> server
        x = await self.client["reader"].read(10)
        self.server["host"] = inet_ntoa(x[4:8])
        self.server["port"] = unpack("!H", x[8:10])[0]
        self.server["reader"], self.server["writer"] = await open_connection(self.server["host"],self.server["port"])
        
        # server -> client
        await self.client["writer"].write(b'\x05\x00\x00\x01' + x[4:10])
        await self.client["writer"].drain()


    """TLS HANDSHAKE"""
    async def complete_tls_handshake(self):
        # client -> server
        header, payload = await self.read_message(self.client["reader"]) #read
        self.intercept(header, payload)                                  #intercept
        client_random_bytes = payload[10:]                               
        await self.write_message(self.server["writer"], header, payload) #write

        # server -> client
        header, payload = await self.read_message(self.server["reader"]) #read
        self.intercept(header, payload)                                  #intercept
        server_random_bytes = payload[10:-269]                           
        server_key          = payload[-256:]                       
        payload             = payload[:-256] + self.proxy["public_key"]
        await self.write_message(self.client["writer"], header, payload) #write

        # client -> server
        header, payload = await self.read_message(self.client["reader"]) #read
        self.intercept(header, payload)                                  #intercept
        await self.write_message(self.server["writer"], header, payload) #write

        # server -> client
        header, payload = await self.read_message(self.server["reader"]) #read 
        self.intercept(header, payload)                                  #intercept                                     
        decrypted_secret   = self.rsa_decrypt(                           
                                              payload[10:], 
                                              self.proxy["private_key"]
                                             )
        encrypt_for_server = self.rsa_encrypt(
                                              decrypted_secret, 
                                              server_key
                                             )    
        self.gen_master_key(                        
                            client_random_bytes, 
                            server_random_bytes, 
                            decrypted_secret
                           )
        await self.write_message(self.client["writer"], header, payload) #write

    #HELPERS#
    def rsa_decrypt(self, encrypted, private_key):
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def rsa_encrypt(self, decrypted, public_key):
        encrypted = public_key.encrypt(
            decrypted.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
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


    """CONVERSATION"""
    async def manage_conversation(self):     
        # listeners
        client_to_server = create_task(self.transfer_message(self.client["reader"], self.server["writer"]))
        server_to_client = create_task(self.transfer_message(self.server["reader"], self.client["writer"]))
        await gather(client_to_server, server_to_client) #start 

    async def transfer_message(self, reader, writer):
        header, payload = await self.read_message(reader) #read
        await self.intercept(header, payload)             #intercept
        await self.write_message(writer, header, payload) #write




