"""IMPORTS"""
from asyncio import IncompleteReadError, get_event_loop, wait_for
from injection_handler import Injector
from crypto_handler import Crypto
from packet import Packet
from struct import pack
from utils import Utils


############################################################################


"""MAIN CODE"""
class Convo():
    def __init__(self, master_key, iv):
        # params for cypher
        self.master_key = master_key
        self.iv = iv

        # for terminating cmd injector
        self.client_socket_open = True
        self.server_socket_open = True

        # stores packets to inject
        self.injection_buffer = []


    # server -> client convo stream
    async def server_to_client_convo_stream(self, reader, writer):
        try:    
            # until socket closes
            while True:

                try:
                    # read message from client
                    header, payload = await Utils.read_message(reader)

                # close communication stream if socket closed
                except IncompleteReadError:
                    break

                # put together packet metadata
                metadata = {
                    "address": writer.get_extra_info('peername'),
                    "direction": "recv"
                }

                # pass to intercept function to potentially modify or just log
                payload = await self.intercept(header, payload, metadata)

                # write to server
                await Utils.write_message(writer, header, payload)

        # cleanup
        finally:
            writer.close()
            await writer.wait_closed()
            self.client_socket_open = False


    # client -> server convo stream
    async def client_to_server_convo_stream(self, reader, writer):

        # keeps track of count
        count_state = 0

        try:
            # until socket closes
            while True:

                # inject packet if available
                if self.injection_buffer:  
                    is_inject = True

                    # packet to inject
                    injection_packet = self.injection_buffer.pop(0)
                    header = bytearray(injection_packet[:21])
                    payload = injection_packet[21:]

                # treat as regular packet
                else: 
                    is_inject = False
                    try:
                        # read message from server
                        header, payload = await Utils.read_message(reader)
                        header = bytearray(header)
                    
                    # close communication stream if socket closed
                    except IncompleteReadError:
                        break  

                # Increment state for non-ping packets
                if header[17:21] != bytes([141, 76, 212, 177]):

                    # increment count_state by 1
                    count_state += 1

                    # pack the count_state into header
                    header[8:12] = pack('<I', count_state)

                # put together packet metadata
                metadata = {
                    "address": reader.get_extra_info('peername'),
                    "direction": "send",
                    "is_inject": is_inject
                }

                # pass to intercept function to potentially modify or just log
                payload = await self.intercept(header, payload, metadata)

                # write to server
                await Utils.write_message(writer, bytes(header), payload)

        # cleanup
        finally:
            writer.close()
            await writer.wait_closed()
            self.server_socket_open = False

        
    # listen for injection commands
    async def injection_command_listener(self):

        # initiate Injector object
        injector = Injector(self.master_key, self.iv)

        # terminate when sockets close
        while self.server_socket_open and self.client_socket_open:

            # Wait for user input
            command = await wait_for(
                get_event_loop().run_in_executor(None, input),
                timeout=1.0  # Check every second
            )

            # inject ping
            if command.upper() == "PING":
                self.injection_buffer.append(injector.ping())

            # inject attack
            if command.upper() == "ATTACK":
                self.injection_buffer.append(injector.attack())

    
    # intercept packet
    async def intercept(self, header, payload, metadata):
        try:
            # decrypt payload
            payload = Crypto.decrypt_payload(payload, self.master_key, self.iv)

            # create packet object
            packet = Packet(header, payload)

            # log
            await Utils.print_to_console(metadata, packet.header_data, packet.payload_data)
            await Utils.write_to_file("log.txt", metadata, packet.header_data, packet.payload_data)

            # return header and payload bytes
            return packet.payload_bytes
        
        except Exception as e:
            print(f"Error intercepting packet: {str(e)}")
            raise