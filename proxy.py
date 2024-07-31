import asyncio
from connection import Connection
PROXY_HOST = '192.168.2.145'
PROXY_PORT = 8888

async def handle_client(reader, writer):
    connection = Connection(reader, writer, PROXY_HOST, PROXY_PORT)
    await connection.start()
    await writer.close()

async def start_proxy():
    proxy = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()

if __name__ == "__main__":
    asyncio.run(start_proxy())