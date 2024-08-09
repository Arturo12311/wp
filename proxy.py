from connection_handler import Connection
import asyncio
import socket

PROXY_HOST = '192.168.2.145'
PROXY_PORT = 8888

async def handle_client(reader, writer):
    connection = Connection(reader, writer, PROXY_PORT)
    try:
        await connection.start()
    except (ConnectionResetError, OSError):
        pass
    finally:
        await connection.close()

async def start_proxy():
    proxy = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    for sock in proxy.sockets:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print("PROXY INITIATED", flush=True)
    await proxy.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_proxy())