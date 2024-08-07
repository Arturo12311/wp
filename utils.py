"""IMPORTS"""
from asyncio import IncompleteReadError
from struct import unpack
import asyncio

import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


############################################################################


"""MAIN CODE"""
class Utils():
    
    # read from socket
    async def read_message(self, reader):
        try:
            # read header
            header = await reader.readexactly(21)

            # read payload
            length = unpack("<I", header[4:8])[0]
            payload = await reader.readexactly(length)

            # return message
            return header, payload

        # marks end of stream
        except IncompleteReadError:
            raise


    # write to socket
    async def write_message(self, writer, header, payload):
        try:
            # write message
            writer.write(header + payload)

            # ensure entire message sent
            await writer.drain()  

        except Exception as e:
            print(f"Error writing message: {str(e)}")
            raise


    # print to console async function
    async def print_to_console(self, metadata, header_data, payload_data):
        await asyncio.get_event_loop().run_in_executor(None, self._print_to_console, metadata, header_data, payload_data)

    def _print_to_console(self, metadata, header_data, payload_data):

        # print metadata
        print("\n--------------")
        for k, v in metadata.items():  
            print(f"    {k:<8}: {v}")
        print("-")

        # print header data
        print("HEADER:")
        for k, v in header_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")

        # print payload data
        print("PAYLOAD")
        for k, v in payload_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")


    # write to file async function
    async def write_to_file(self, filename, metadata, header_data, payload_data):
        await asyncio.get_event_loop().run_in_executor(None, self._write_to_file, filename, metadata, header_data, payload_data)

    def _write_to_file(self, filename, metadata, header_data, payload_data):

        # write template
        def _write(path):

            # open file
            full_path = os.path.join(CURRENT_DIR, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'a') as f:

                # write metadata
                f.write("\n-----------------------\n")
                for k, v in metadata.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")

                # write header data
                f.write("HEADER:\n")
                for k, v in header_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")

                # write payload data
                f.write("PAYLOAD\n")
                for k, v in payload_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")

        # noname
        if header_data["name"] == "unknown":
            _write("logs/er_nonames.txt")

        # remainder
        # if payload_data["rest"] != []:
        #     _write("logs/er_remainder.txt")

        # regular
        _write(f"logs/{filename}")