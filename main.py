from parser import MessageParser
import json

parser = MessageParser()

def convert_to_bytearray(string):
    return bytearray(int(x) for x in string.split(','))

# Example byte sequence
byte_sequence = "0,0,0,0,1,0,0,0,0,0,0,0"
ba = convert_to_bytearray(byte_sequence)


# Import the mitm
# turn the game messages into bytearray
# feed to parser

result = parser.parse_message(ba)
print(json.dumps(result, indent=2))


async def start_proxy():   
    """
    initiates the proxy and makes it listen forever
    """
    proxy = await asyncio.start_server(handle_client, '192.168.2.19', 8888)
    async with proxy:
        print("PROXY INITIATED")
        await proxy.serve_forever()

asyncio.run(start_proxy()) #run proxy