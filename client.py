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
        # client info
        self.client_addr = client_writer.get_extra_info('peername')
        self.client_reader = client_reader
        self.client_writer = client_writer

        # server info
        self.server_addr = None
        self.server_reader = None
        self.server_writer = None

        # tls info
        self.client_tls_key = None
        self.server_tls_key = None


    async def handle_client(self):
        # proxify handshake 
        await self.complete_proxify_handshake(self.client_reader, self.client_writer)
        print("\n---")
        print("PROXIFY HANDSHAKE COMPLETE")
        print(f"  client address = {self.client_addr}")
        print(f"  server address = {self.server_addr}")
        print("---\n")

        # tls handshakes
        await self.client_tls_handshake()
        await self.server_tls_handshake()
        print("\n---")
        print("TLS HANDSHAKES COMPLETE")
        print(f"  client_tls_key = {self.client_tls_key}")
        print(f"  server_tls_key = {self.server_tls_key}")
        print("---\n")

        # manage tls connection
        await asyncio.gather(
            self.manage_tls_connection(endpoint="client"),
            self.manage_tls_connection(endpoint="server")
        )


    async def complete_proxify_handshake(self, client_reader, client_writer):
        # msg1
        await client_reader.read(3)
        # reply1
        client_writer.write(b'\x05\x00')
        await client_writer.drain()
        # msg2
        msg2 = await self.client_reader.read(10)
        server_host = inet_ntoa(msg2[4:8])
        server_port = unpack("!H", msg2[8:10])[0]
        server_addr = (server_host, server_port)
        server_reader, server_writer = await asyncio.open_connection(server_addr)
        # reply2
        client_writer.write(b'\x05\x00\x00\x01' + msg2[4:10])
        await client_writer.drain()

        # update class variables
        self.server_addr = server_addr
        self.server_reader = server_reader
        self.server_writer = server_writer


    async def client_tls_handshake(self):
        # msg1
        ## reply1
        # msg2
        # #reply2
        pass

    async def server_tls_handshake(self):
        ## msg1
        # reply1
        ## msg2
        # reply2
        pass




    async def manage_tls_connection(self, endpoint):
        pass



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