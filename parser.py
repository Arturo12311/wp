import struct
import json
import re
import os

class MessageParser:
    def __init__(self):
        # Get the directory of the current script
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Load necessary data
        with open(os.path.join(current_dir, '_names.json'), 'r') as f:
            self.names = json.load(f)
        with open(os.path.join(current_dir, '_structs.json'), 'r') as f:
            self.structs = json.load(f)

    def parse_message(self, byte_array):
        msg = self.Msg(byte_array, self.names, self.structs)
        return {
            'name': msg.name,
            'op': msg.op,
            'struct': msg.struct,
            'message': msg.msg,
            'remaining_bytes': list(msg.rb or [])
        }

    class Msg:
        def __init__(self, ba, names, structs):
            self.names = names
            self.structs = structs
            
            self.nb, self.rb = self.split_null(ba)
            if self.is_null(self.nb):
                self.op = None
                self.name = None
                self.struct = None
                self.msg = None
                self.rb = ba[1:]
            else:
                self.hb, self.rb = self.split_header(self.rb)
                self.op = self.read_header(self.hb)
                self.name = self.names[str(self.op)]
                self.struct = self.structs[self.name]
                self.msg, self.rb = self.parse_struct(self.name, self.rb)

        def split_null(self, ba):
            return ba[:1], ba[1:]

        def is_null(self, nb):
            return struct.unpack("?", nb)[0] == 1

        def split_header(self, ba):
            return ba[:4], ba[4:]

        def read_header(self, hb):
            return struct.unpack("<I", hb)[0]

        def parse_struct(self, name, rb):
            if name[-1] == "0":
                nb, rb = self.split_null(rb)
                if nb not in [b'\x00', b'\x01']:
                    raise ValueError("Invalid null byte")
                if self.is_null(nb):
                    return None, rb
                struct = self.structs[name[:-1]]
            else:
                struct = self.structs[name]

            parsed_structure = {}
            for k, v in struct.items():
                parsed_value, rb = self.parse(v, rb)
                parsed_structure[k] = parsed_value
            return parsed_structure, rb

        def parse(self, x, rb):
            if x == "msg":
                msg = self.Msg(rb, self.names, self.structs)
                parsed_value, rb = msg.msg, msg.rb
            elif isinstance(x, dict):
                parsed_value, rb = self.parse_map(x, rb)
            elif isinstance(x, list):
                parsed_value, rb = self.parse_array(x, rb)
            elif re.match("FTz.*", x):
                parsed_value, rb = self.parse_struct(x[3:], rb)
            elif isinstance(x, str):
                parsed_value, rb = self.parse_basic(x, rb)
            else:
                raise ValueError(f"Unknown type: {x}")
            return parsed_value, rb

        def parse_map(self, x, rb):
            parsed_map = {}
            nb, rb = self.split_null(rb)
            if nb not in [b'\x00', b'\x01']:
                raise ValueError("Invalid null byte")
            if self.is_null(nb):
                return None, rb

            hb, rb = self.split_header(rb)
            l = self.read_header(hb)

            t1, t2 = next(iter(x.items()))
            for _ in range(l):
                v1, rb = self.parse(t1, rb)
                v2, rb = self.parse(t2, rb)
                parsed_map[v1] = v2

            return parsed_map, rb

        def parse_array(self, x, rb):
            parsed_array = []
            nb, rb = self.split_null(rb)
            if nb not in [b'\x00', b'\x01']:
                raise ValueError("Invalid null byte")
            if self.is_null(nb):
                return None, rb

            hb, rb = self.split_header(rb)
            l = self.read_header(hb)

            array_type = x[0]
            for _ in range(l):
                v, rb = self.parse(array_type, rb)
                parsed_array.append(v)

            return parsed_array, rb

        def parse_basic(self, x, rb):
            if x[-1] == "0":
                nb, rb = self.split_null(rb)
                if self.is_null(nb):
                    return None, rb
                format_string = f"<{x[:-1]}"
            elif x == "s":
                return self.parse_string(rb)
            elif re.match(r"ETzBuildingAccessPermissionKindType|ETzAffectSourceSystemCastKindType|ETzResultCodeType|ETzCharacterStateType|ETzConnectionStatusType|ETzMountInteractionStateType|ETzContaminationNaturalDecreaseType|ETzBuildingAccessPermissionKindType", x):
                format_string = "<I"
            elif re.match("ETz.*", x):
                format_string = "<B"
            elif x == "?":
                if rb[:1] not in [b'\x00', b'\x01']:
                    raise ValueError("Invalid boolean value")
                format_string = f"<{x}"
            else:
                format_string = f"<{x}"

            size = struct.calcsize(format_string)
            parsed_basic = struct.unpack(format_string, rb[:size])
            if len(parsed_basic) == 1:
                parsed_basic = parsed_basic[0]

            return parsed_basic, rb[size:]

        def parse_string(self, rb):
            nb, rb = self.split_null(rb)
            if nb not in [b'\x00', b'\x01']:
                raise ValueError("Invalid null byte")
            if self.is_null(nb):
                return None, rb

            hb, rb = self.split_header(rb)
            l = self.read_header(hb)

            format_string = f"{l}s"
            size = struct.calcsize(format_string)
            parsed_string = struct.unpack(format_string, rb[:size])
            if len(parsed_string) == 1:
                parsed_string = parsed_string[0]

            return parsed_string.decode('utf-8', errors='ignore'), rb[size:]

def convert_to_bytearray(string):
    return bytearray(int(x) for x in string.split(','))

