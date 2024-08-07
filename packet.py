"""IMPORTS"""
from msg import Msg

from struct import unpack
from json import load

import os
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(CURRENT_DIR, "assets/names.json"), 'r') as f:
    names = load(f)
with open(os.path.join(CURRENT_DIR, "assets/structs.json"), 'r') as f:
    structs = load(f)


############################################################################


"""MAIN CODE"""
class Packet:
    """
    logs and/or modifies packet data
    """
    def __init__(self, header_bytes, payload_bytes):

        # header data
        self.header_data = self.read_header(header_bytes)

        # payload data
        self.payload_data, self.payload_bytes = self.read_payload(payload_bytes)


    # read header data
    def read_header(self, header_bytes):

        # assemble header data
        op = unpack("<I", header_bytes[17:21])[0]
        header_data = {
            "name": names.get(str(op), "unknown"),
            "op": op,
            "full_length": unpack("<I", header_bytes[4:8])[0],
            "count": unpack("<I", header_bytes[8:12])[0],
            "inner_length": unpack("<I", header_bytes[13:17])[0],
            "bytes": list(header_bytes)
        }

        # return header data
        return header_data
    

    # read payload data
    def read_payload(self, payload_bytes):

        # get corresponding structure
        name = self.header_data["name"]
        structure = "unknown" if name == "unknown" else structs[name] 

        # initiate msg object
        msg = Msg(payload_bytes)

        # assemble payload_data
        payload_data = {
            "bytes": list(payload_bytes),
            "struct": structure,
            "msg": msg.msg,
            "rest": msg.rb 
        }

        # return payload data and payload bytes
        return payload_data, payload_bytes