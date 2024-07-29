from msg_parser import Msg
from msg_parser import print_dict
import struct
import json

packet = b'TOZ \x89\x00\x00\x00\xff\xff\xff\xff\x00\x89\x00\x00\x00\x9d\x92\x9d@\x00\x9d\x92\x9d@\x00\x7f\x00\x00\x00\xb3\xbfJ\xf2C\\\x8fpW\xf4\x1b\x00\xdc\xe2>m-\xef7n\xea\xdfHW\xfc\x93\xa9\xc3l\xe3^\x98\xe7\xb6\xae<h\x04\x1e\xeee\xb9\xc6E,qd\xfa\xe0T\x9fm\x0b\xbcA\xbe\xb6\x17\x03}\x08w\x8b\xdc\xeeW\xbe\xacQMt>2[\x9fF=\xfd=\xbas:q`*+\xa0~\xd5\xe9d\xaf\xab\xec\x00Q||E\x1b\x9d\x86\xab\xf4X\xfab\xb4\xa6\xc9\x8e\xac\x8d\xf6\xc7\xcc\x88y\xce\xa4:]fv\x1d\xf2\x95'
class Packet:
    """
    f0 = complete or incomplete?
    f1 = msg length
    f2 = hash
    f3 = count
    f4 = opcode
    f5 = msg
    """
    def __init__(self, ba) -> None:
        self.ba = ba
        self.type = ""
        self.length = 0
        self.hash = ""
        self.count = 0
        self.name = ""
        self.struct = ""
        self.payload = ""
        self.parse()

    def parse(self):

        # is complete? (type)
        rb = self.ba 
        self.type = struct.unpack("!BBBB", rb[:4])
        rb = rb[4:]

        # length
        self.length = struct.unpack("<I", rb[:4])[0]
        rb = rb[4:]

        # hash 
        self.hash = struct.unpack("!BBBB", rb[:4])
        rb = rb[4:]

        # nb
        null_byte = rb[:1]
        rb = rb[1:]

        # count
        self.count = struct.unpack("<I", rb[:4])[0]
        rb = rb[4:]

        # opcode
        op = struct.unpack("<I", rb[:4])[0]
        with open("_names.json", 'r') as f:
            data = json.load(f)
        op = str(op)
        if op in data:
            self.name = data[op]
        else:
            raise ValueError(f"No opname found for operation: {op}")
        rb = rb[4:]

        # data
        print(list(bytearray(rb)))
        msg = Msg(rb)
        self.struct = msg.struct
        self.payload = msg.msg

    def console_output(self):
        print("\n----------")
        print(f"{self.name}")
        print("-")
        print(f"{list(self.ba)}")
        print("-")
        print(f"type   : {self.type}")
        print(f"length : {self.length}")
        print(f"hash   : {self.hash}")
        print(f"count  : {self.count}")
        print("-")
        print_dict(self.name, self.struct)
        print("-")
        print_dict(self.name, self.payload)
        print("----------")

    def log(self):
        with open('log_v2.txt', 'a') as f:
            f.write("\n------------------------------\n")
            f.write(f"{self.name}\n")
            f.write("-\n")
            f.write(f"{list(self.ba)}\n")
            f.write("-\n")
            f.write(f"type   : {self.type}\n")
            f.write(f"length : {self.length}\n")
            f.write(f"hash   : {self.hash}\n")
            f.write(f"count  : {self.count}\n")
            f.write("-\n")
            f.write("{\n")
            for key, value in self.struct.items():
                f.write(f"  {key}: {value}\n")
            f.write("}\n")
            f.write("-\n")
            f.write("{\n")
            for key, value in self.payload.items():
                f.write(f"  {key}: {value}\n")
            f.write("}\n")
            f.write("------------------------------\n")


packet = Packet(packet)
packet.console_output()
packet.log()