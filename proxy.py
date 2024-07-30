from client import Client
import asyncio

async def proxy(addr, port):
    proxy = await asyncio.start_server(lambda r, w: Client(r, w).handle_client(), addr, port)
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()

"""MAIN RUN"""
asyncio.run(proxy('192.168.2.145', 8888))



