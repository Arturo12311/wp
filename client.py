"""
todo 
    tls handshake with client
    tls handshake with server
    serialization with priv key

    file paths using os

    reference packet.py 
"""

import asyncio
from socket import inet_ntoa
from struct import unpack
from packet import Packet

"""CLIENT CLASS"""
class Client:
    """
    handles clients connected to proxy (
        1 complete proxify handshake
            - connect to server
        2 complete tls handshake
            - extract tls keys 
        3 manage tls connection
            - deserialize -> packet object -> serialize 
    )
    """
    def __init__(self, client_reader, client_writer):
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.server_writer = None
        self.server_reader = None


    async def handle_client(self):
        # SOCK5 handshake
        await self.SOCK5_handshake()
        print("\nsock5 handshake complete")

        # TLS config
        


        # manage convo
        await asyncio.gather(
            self.client_to_server(),
            self.server_to_client()
        )


    async def SOCK5_handshake(self):
        # client connection info
        client_addr = self.client_writer.get_extra_info('peername')
        print(f"\nCLIENT CONNECTED {client_addr}")

        # msg1
        await self.client_reader.read(3)

        # reply1
        self.client_writer.write(b'\x05\x00')
        await self.client_writer.drain()

        # msg2
        msg2 = await self.client_reader.read(10)
        server_host = inet_ntoa(msg2[4:8])
        server_port = unpack("!H", msg2[8:10])[0]
        # server connection info
        self.server_reader, self.server_writer = await asyncio.open_connection(server_host, server_port) 
        server_addr = self.server_writer.get_extra_info('peername')
        print(f"\nCONNECTED TO SERVER {server_addr}")

        # reply2
        self.client_writer.write(b'\x05\x00\x00\x01' + msg2[4:10])
        await self.client_writer.drain()
    

    async def perform_tls_handshake_as_server(self, client_writer):
        pass  # Define the async TLS handshake function


    async def perform_tls_handshake_as_client(self, server_address, server_port):
        pass  # Define the async TLS handshake function



    async def client_to_server(self):
        try:
            while True:
                # read header
                header_bytes = await self.client_reader.readexactly(21)
                if not header_bytes:
                    break
                # read payload
                payload_length = unpack("<I", header_bytes[4:8])[0]
                payload_bytes = await self.client_reader.readexactly(payload_length)

                # write header and payload to server
                self.server_writer.write(header_bytes + payload_bytes)
                await self.server_writer.drain()

                # log packet
                packet = Packet(header_bytes, payload_bytes, "send").log()
                packet.print_to_console()
                packet.write_to_file()
        finally:
            self.server_writer.close()

    async def server_to_client(self):
        try:
            while True:
                # read header
                header_bytes = await self.server_reader.readexactly(21)
                if not header_bytes:
                    break

                # read payload
                payload_length = unpack("<I", header_bytes[4:8])[0]
                payload_bytes = await self.server_reader.readexactly(payload_length)

                # write header and payload to client
                self.client_writer.write(header_bytes + payload_bytes)
                await self.client_writer.drain()

                # log packet
                packet = Packet(header_bytes, payload_bytes, "recv")
                packet.print_to_console()
                packet.write_to_file()
        finally:
            self.client_writer.close()

    def decrypt_aes256cbc(self, data, key, iv):
        pass  # Define the AES decryption function

    def encrypt_aes256cbc(self, data, key, iv):
        pass  # Define the AES encryption function