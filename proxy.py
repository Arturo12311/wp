
"""HELPERS"""
from packet_parser import Packet
import asyncio
import struct
import socket
import json

with open('_names.json', 'r') as f:
    names = json.load(f)


"""PROXY"""
async def handle_client(client_reader, client_writer):
    """
    1. completes handshakes
    2. connects to server
    3. manages conversation
    """

    # handshakes
    client_addr = client_writer.get_extra_info('peername')
    print(f"\nCLIENT CONNECTED {client_addr}")

    x = await client_reader.read(3)
    if x != b'\x05\x01\x00': print(f"error with greeting message {client_addr}"); exit()
    print(f"-\n{client_addr}\n  handshake msg1 (client -> proxy): {x}\n-")

    x = b'\x05\x00'
    client_writer.write(x)
    await client_writer.drain()
    print(f"-\n{client_addr}\n  handshake reply1 (proxy -> client): {x}\n-")

    x = await client_reader.read(10)
    print(f"-\n{client_addr}\n  handshake msg2 (client -> proxy): {x}")
    host = socket.inet_ntoa(x[4:8])
    port = struct.unpack("!H", x[8:10])[0]
    print(f"  extracted server info:\n    host: {host}\n    port: {port}")

    server_reader, server_writer = await asyncio.open_connection(host, port)
    print(f"  CONNECTED TO SERVER!\n-")

    x = b'\x05\x00\x00\x01' + x[4:10]
    client_writer.write(x)
    await client_writer.drain()
    print(f"-\n{client_addr}\n  handshake reply2 (proxy -> client): {x}\n-")

    # convo
    print(f"-\n{client_addr}\nCONVO BEGIN\n-")
    await asyncio.gather(
        client_to_server(client_reader, server_writer),
        server_to_client(server_reader, client_writer)
    )
    print(f"-\n{client_addr}\nCONVO END\n-")


async def client_to_server(client_reader, server_writer):
    try:
        while True:
            # read header
            header_bytes = await client_reader.readexactly(21)
            if not header_bytes:
                break
            header = read_header(header_bytes, "send")

            # read payload
            payload_bytes = await client_reader.readexactly(header["length"])

            # send header and payload to server
            server_writer.write(header_bytes + payload_bytes)
            await server_writer.drain()

            # log packet
            adjusted_payload = b'\x00' + header_bytes[17:21] + payload_bytes
            packet = Packet(header, adjusted_payload)
            packet.log()
    finally:
        server_writer.close()

async def server_to_client(server_reader, client_writer):
    try:
        header = {}
        payload_bytes = b''
        while True:

            # read header
            header_bytes = await server_reader.readexactly(21)
            if not header_bytes:
                break
            header = read_header(header_bytes, "recv")

            # read payload
            payload_bytes = await server_reader.readexactly(header["length"])

            # send header and payload to server
            client_writer.write(header_bytes + payload_bytes)
            await client_writer.drain()

            # log packet
            adjusted_payload = b'\x00' + header_bytes[17:21] + payload_bytes
            packet = Packet(header, adjusted_payload)
            packet.log()
    finally:
        client_writer.close()


def read_header(b, type):
    op = struct.unpack("<I", b[17:21])[0]
    if str(op) not in names:
        header = {
            "type": type,
            "length": struct.unpack("<I", b[4:8])[0],
            "hash": struct.unpack("!BBBB", b[8:12]),
            "count": struct.unpack("<I", b[13:17])[0],
            "name": "unknown"
        }
        # print("\n\n\n\n----------------------------")
        # print("ERROR: no name found in opcode names")
        # print("-")
        # print(f"packet bytes: {list(b)}")
        # print("-")
        # print(f"packet op[17:21]: {op}")
        # exit()
        
    header = {
        "type": type,
        "length": struct.unpack("<I", b[4:8])[0],
        "hash": struct.unpack("!BBBB", b[8:12]),
        "count": struct.unpack("<I", b[13:17])[0],
        "name": names[str(struct.unpack("<I", b[17:21])[0])]
    }
    return header
    

async def start_proxy():   
    """
    initiates the proxy and makes it listen forever
    """
    proxy = await asyncio.start_server(handle_client, '192.168.2.145', 8888)
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()

asyncio.run(start_proxy()) #run proxy
