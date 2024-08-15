from struct import unpack
from asyncio import IncompleteReadError

async def read_message(reader):
    try:
        header = await reader.readexactly(25)
        length = unpack("<I", header[4:8])[0]
        payload = await reader.readexactly(length)
        return header, payload
    except IncompleteReadError:
        raise #marks end of stream
            
async def write_message(writer, header, payload):
    writer.write(header + payload)
    await writer.drain()  