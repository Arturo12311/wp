import asyncio
import struct
import socket

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
    print(f"  extracted server info:\n    host: {host}\n  port: {port}")

    server_reader, server_writer = await asyncio.open_connection(host, port)
    print(f"  CONNECTED TO SERVER!\n-")

    x = b'\x05\x00\x00\x01' + x[4:10]
    client_writer.write(x)
    await client_writer.drain()
    print(f"-\n{client_addr}\n  handshake reply2 (proxy -> client): {x}\n-")

    # convo
    print(f"-\n{client_addr}\nCONVO BEGIN\n-")
    await asyncio.gather(
        client_to_server(client_reader, server_writer, client_addr),
        server_to_client(server_reader, client_writer, client_addr)
    )
    print(f"-\n{client_addr}\nCONVO END\n-")


async def client_to_server(client_reader, server_writer, client_addr):
    try:
        while True:
            msg = await client_reader.read(8192)
            if not msg:
                break
            server_writer.write(msg)
            await server_writer.drain()
            print(f"\n-\n{client_addr}\n  client -> server: {list(msg)}\n-")
            with open('log.txt', 'a') as f:
                f.write(f"{client_addr} 'sent': {list(msg)} \n-\n")
    finally:
        server_writer.close()

async def server_to_client(server_reader, client_writer, client_addr):
    try:
        while True:
            msg = await server_reader.read(8192)
            if not msg:
                break
            client_writer.write(msg)
            await client_writer.drain()
            print(f"\n-\n{client_addr}\n  server -> client: {list(msg)}\n-")
            with open('log.txt', 'a') as f:
                f.write(f"{client_addr} 'recieved': {list(msg)} \n-\n")
    finally:
        client_writer.close()

async def start_proxy():   
    """
    initiates the proxy and makes it listen forever
    """
    proxy = await asyncio.start_server(handle_client, '192.168.2.19', 8888)
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()

asyncio.run(start_proxy()) #run proxy
