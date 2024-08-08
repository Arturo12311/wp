from struct import unpack
from json import load
import os
import asyncio
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
from msg import Msg

with open(os.path.join(CURRENT_DIR, "assets/names.json"), 'r') as f:
    names = load(f)
with open(os.path.join(CURRENT_DIR, "assets/structs.json"), 'r') as f:
    structs = load(f)

class Packet:
    """
    intercepted packet object
    """
    def __init__(self, header_bytes, payload_bytes, stream):
        self.stream = stream
        self.header_data = self.read_header(header_bytes)
        self.payload_data = self.read_payload(payload_bytes)


    """PARSING"""
    def read_header(self, header_bytes):
        op = unpack("<I", header_bytes[17:21])[0]
        name = names.get(str(op), "unknown")      
        header_data = {
            "count": unpack("<I", header_bytes[8:12])[0],
            "name": name,
            "op": op,
            "full_length": unpack("<I", header_bytes[4:8])[0],
            "inner_length": unpack("<I", header_bytes[13:17])[0],
            "bytes": list(header_bytes)
        }   
        return header_data
    

    def read_payload(self, payload_bytes):
        name = self.header_data["name"]
        structure = "unknown" if name == "unknown" else structs[name] 
        msg = Msg(payload_bytes)
        payload_data = {
            "bytes": list(payload_bytes),
            "struct": structure,
            "parsed": msg.msg,
            "rest": msg.rb
        }
        return payload_data
    
    """LOGGING"""
    async def print_to_console(self):
        await asyncio.get_event_loop().run_in_executor(None, self._print_to_console)

    def _print_to_console(self):
        print("\n--------------")
        print(self.stream)
        print("-")
        print("HEADER:")
        for k, v in self.header_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")
        print("PAYLOAD")
        for k, v in self.payload_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")

    async def write_to_file(self, filename):
        await asyncio.get_event_loop().run_in_executor(None, self._write_to_file, filename)

    def _write_to_file(self, filename):
        def _write(path):
            # open file
            full_path = os.path.join(CURRENT_DIR, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'a') as f:
                f.write("\n-----------------------\n")
                f.write(f"{self.stream}\n")
                f.write("-\n")
                f.write("HEADER:\n")
                for k, v in self.header_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")
                f.write("PAYLOAD\n")
                for k, v in self.payload_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")
        _write(f"logs/{filename}")

        # noname
        # if self.header_data["name"] == "unknown":
        #     _write("logs/er_nonames.txt")

        # remainder
        # if self.payload_data["rest"] != []:
        #     _write("logs/er_remainder.txt")


    

            