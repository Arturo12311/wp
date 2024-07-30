
"""
todo:
    implement packet parsing 
    add start and end points in output
"""

# from msg import Msg
from struct import unpack
import json
import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

"""PACKET CLASS"""
class Packet:
    def __init__(self, header_bytes, payload_bytes, operation):
        self.header_data = self.read_header(header_bytes, operation)
        self.payload_data = self.read_payload(payload_bytes)

    def read_header(self, header_bytes, operation):
        full_path = os.path.join(CURRENT_DIR, "assets/names.json")
        with open(full_path, 'r') as f:
            names = json.load(f)
        op = unpack("<I", header_bytes[17:21])[0]
        if str(op) not in names:
            header_data = {
                "name": "unknown",
                "op": op,
                "bytes": list(header_bytes),
                "type": operation,
                "length": unpack("<I", header_bytes[4:8])[0],
                "hash": unpack("!BBBB", header_bytes[8:12]),
                "count": unpack("<I", header_bytes[13:17])[0]
            }
        else:
            header_data = {
                "name": names[str(unpack("<I", header_bytes[17:21])[0])],
                "type": operation,
                "length": unpack("<I", header_bytes[4:8])[0],
                "hash": list(unpack("!BBBB", header_bytes[8:12])),
                "count": unpack("<I", header_bytes[13:17])[0]
            }
        return header_data
    
    def read_payload(self, payload_bytes):
        full_path = os.path.join(CURRENT_DIR, "assets/structs.json")
        with open(full_path, 'r') as f:
            structs = json.load(f)
        name = self.header_data["name"]
        structure = "unknown" if name == "unknown" else structs[name] 
        payload_data = {
            "bytes": list(payload_bytes),
            "struct": structure,
            # "msg": msg.msg,
            # "rest": msg.rb 
        }
        return payload_data

    def print_to_console(self):
        # print endpoints
        print("\n--------------")

        # print header data
        print("HEADER:")
        for k, v in self.header_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")

        # print payload data
        print("PAYLOAD")
        for k, v in self.payload_data.items():  
            print(f"    {k:<8}: {v}")
        print("-")

    def write_to_file(self):
        def _write(path):
            full_path = os.path.join(CURRENT_DIR, path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'a') as f:
                # write endpoints
                f.write("\n-----------------------\n")

                # write header_data
                f.write("HEADER:\n")
                for k, v in self.header_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")

                # write payload_data
                f.write("PAYLOAD\n")
                for k, v in self.payload_data.items():  
                    f.write(f"    {k:<8}: {v}\n")
                f.write("-\n")

        if self.header_data["name"] == "unknown":
            _write("log/er_nonames.txt")

        # if self.payload_data["rest"] != []:
        #     _write("log/er_remainder.txt")

        _write("log/log.txt")

    

            