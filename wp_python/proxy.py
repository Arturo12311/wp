from connection_handler import Connection
import asyncio
import socket
import datetime
from config import initialize_timestamp

PROXY_HOST = '192.168.2.145'
PROXY_PORT = 8888
TIMESTAMP = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

async def handle_client(reader, writer):
    connection = Connection(reader, writer)
    try: await connection.start()
    except (ConnectionResetError, OSError): pass
    finally:
        try: await connection.close()
        except ConnectionResetError: pass
        print(f"CONNECTION CLOSED", flush=True)

async def start_proxy():
    initialize_timestamp()
    proxy = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    for sock in proxy.sockets:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print("PROXY INITIATED", flush=True)
    await proxy.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_proxy())