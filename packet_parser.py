
"""IMPORTS"""
from msg_parser import Msg
from msg_parser import print_dict
import struct
import json

with open('_names.json', 'r') as f:
    names = json.load(f)

with open('_structs.json', 'r') as f:
    structs = json.load(f)


"""MAIN CODE"""
class Packet:
    """
    logging functionality for packet data
    parses packet data with Msg class
    """
    def __init__(self, header_buffer, payload_buffer):
        # params
        self.header = header_buffer
        self.payload_bytes = payload_buffer

        # parse payload 
        # msg = Msg(self.payload_bytes)
        if self.header["name"] == "unknown":
            structure = "unknown"
        else:
            structure = structs[self.header["name"]]
        self.payload = {
            "bytes": list(self.payload_bytes),
            "struct": structure,
            # "msg": msg.msg,
            # "rest": msg.rb 
        }

        # combine packet data
        self.packet_data = {
            self.header["name"]: {
                "header": self.header,
                "payload": self.payload
            }
        }

    def log(self):
        self.print_to_console()
        self.write_to_file()

    def print_to_console(self):
        json.dumps(self.packet_data, indent=2)
        # print("\n--------------")
        # print("HEADER:")
        # for k, v in self.header.items():  
        #     print(f"    {k:<7}: {v}")
        # print("-")
        # print("PAYLOAD")
        # for k, v in self.header.items():  
        #     print(f"    {k:<7}: {v}")
        # print("-")

    def write_to_file(self):
        # self.payload["rest"] != []
        if self.header["name"] == "unknown":
            with open('error_log.json') as f:
                json.dump(self.packet_data, f, indent=2)
                f.write(',\n') 

        # add packet data to main log
        with open('log.json', 'a') as f:
            json.dump(self.packet_data, f, indent=2)
            f.write(',\n') 

    

            