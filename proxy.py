
async def start_proxy():
    from connection import Connection
    from asyncio    import start_server

    proxy_host = '192.168.2.145'
    proxy_port = 8888
    proxy      = await start_server(
                                    lambda r, w: Connection(r, w, proxy_host, proxy_port).start(), 
                                    proxy_host, proxy_port
                                    ) 
    async with proxy:
        # print("PROXY INITIATED")
        await proxy.serve_forever()

# run
from asyncio import run
run(start_proxy())



