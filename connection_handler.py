from asyncio import open_connection, create_task, gather, IncompleteReadError, get_event_loop
from struct  import unpack, pack
from packet  import Packet
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
from handsakes import complete_proxify_handshake, complete_tls_handshake
from crypto import encrypt_payload, decrypt_payload


# UTILS
async def read_message(reader):
    try:
        header = await reader.readexactly(21)
        length = unpack("<I", header[4:8])[0]
        payload = await reader.readexactly(length)
        return header, payload
    except IncompleteReadError:
        raise #marks end of stream
            
async def write_message(writer, header, payload):
    writer.write(header + payload)
    await writer.drain()  


"""CONNECTION CLASS"""
class Connection:
    def __init__(self, client_reader, client_writer, proxy_port):

        self.port = proxy_port

        self.client_reader = client_reader
        self.client_writer = client_writer
        self.server_reader = None
        self.server_writer = None

        self.master_key = None
        self.iv = None
        
        self.injection_buffer = []

    
    async def start(self):
        # proxify handshake
        server_host, server_port = await complete_proxify_handshake(self.client_reader, self.client_writer)
        self.server_reader, self.server_writer = await open_connection(server_host, server_port)

        # tls handshake
        self.master_key, self.iv = await complete_tls_handshake(self.client_reader, self.client_writer, self.server_reader, self.server_writer)

        # manage convo
        await self.manage_conversation()

        # cleanup
        self.client_writer.close()
        self.client_writer.wait_close()
        self.server_writer.close()
        self.server_writer.wait_close()


    """CONVO HANDLER"""
    async def manage_conversation(self):     
        send_stream = create_task(self.send_stream())
        recv_stream = create_task(self.recv_stream())     
        inject_listener = create_task(inject_listener())
        await gather(send_stream, recv_stream) 
        inject_listener.cancel()
        await inject_listener

    async def send_stream(self):
        count = 0
        while True:

            # Inject packet if available
            if self.injection_buffer:  
                injection_packet = self.injection_buffer.pop(0)
                header = bytearray(injection_packet[:21])
                payload = injection_packet[21:]
                # Increment state for non-ping packets
                if header[17:21] != bytes([141, 76, 212, 177]):
                    count += 1
                    header[8:12] = pack('<I', count)

            else: 
                try:
                    header, payload = await read_message(self.client_reader)
                    count += 1
                    header = bytearray(header)
                    header[8:12] = pack('<I', count)
                except IncompleteReadError:
                    break  

            # Intercept and forward the packet
            await intercept(header, payload, "send")
            await write_message(self.server_writer, header, payload)

    async def recv_stream(self):
        while True:
            try:
                header, payload = await read_message(self.server_reader)
            except IncompleteReadError:
                break

            # Intercept and forward the packet
            await self.intercept(header, payload, "recv")
            await write_message(self.client_writer, header, payload)


    """INTERCEPT"""
    async def intercept(self, header, payload, stream):
        # get packet info
        payload = decrypt_payload(payload)
        packet = Packet(header, payload, stream)
        # filter
        # if packet.header_data["name"] not in filter_list:
            # await packet.print_to_console()
        # await packet.write_to_file("log.txt")
   

   """INJECT"""
    async def inject_listener(self):
        while True:
            command = await get_event_loop().run_in_executor(None, input)
            if command.upper() == "INJECT":
                self.inject_ping()

    def inject_ping(self):     
        # header
        header = bytes([84, 79, 90, 32, 16, 0, 0, 0, 255, 255, 255, 255, 0, 13, 0, 0, 0, 141, 76, 212, 177])
        packet = header + encrypted_payload
        # payload to inject
        op = bytes([0, 141, 76, 212, 177])
        encoded_1337 = pack('<Q', 1337)
        injection_packet = bytes(op) + encoded_1337
        encrypted_payload = encrypt_payload(injection_packet, self.master_key, self.iv)
        # update buffer
        self.injection_buffer.append(packet)
        print("\n---")
        print("added to injection buffer")

    