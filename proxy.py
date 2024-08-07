"""IMPORTS"""
from connection_handler import Connection

import asyncio
import socket

PROXY_HOST = '192.168.2.145'
PROXY_PORT = 8888


############################################################################


"""MAIN CODE"""
async def handle_client(client_reader, client_writer):
    # handle connection 
    connection = Connection(client_reader, client_writer)
    await connection.start() 

    #cleanup
    await client_writer.close()


async def start_proxy():
    # setup proxy
    proxy = await asyncio.start_server(handle_client, PROXY_HOST, PROXY_PORT)

    # disable nagle algorithm
    for sock in proxy.sockets:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # run forever
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_proxy())