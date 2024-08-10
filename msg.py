import struct
import json
import re
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open("C:/al/assets/names.json", 'r') as f:
    names = json.load(f)
with open("C:/al/assets/structs.json", 'r') as f:
    structs = json.load(f)


"""
CODE LEGEND

ba = bytearray
rb = rest of bytes
nb = null byte
hb = header bytes
"""


"""MAIN CODE"""
class Msg:
    def __init__(self, ba):
        """
        Defines useful msg attributes upon initialization 
        """       
        # check if message is null
        self.nb, self.rb = self.split_null(ba)
        if self.is_null(self.nb):
            self.op = None; self.name = None; self.struct = None; self.msg = None; self.rb = ba[1:]
        
        # define msg attributes if not nulled
        else:
            self.hb, self.rb = self.split_header(self.rb)
            self.op = self.read_header(self.hb)
            self.name = names[str(self.op)]
            self.struct = structs[self.name]
            self.msg, self.rb = self.parse_struct(self.name, self.rb) #decodes message


    # splits at and reads nullbyte
    def split_null(self, ba):
        return ba[:1], ba[1:]
    def is_null(self, nb):
        if struct.unpack("?", nb)[0] == 1:
            return True


    # splits at and reads header # for anything with length specifier
    def split_header(self, ba):
        return ba[:4], ba[4:]
    def read_header(self, hb):
        return struct.unpack("<I", hb)[0]


    # parses every field in the structure 
    def parse_struct(self, name, rb):

        # handle nullbyte
        if name[-1] == "0":
            nb, rb = self.split_null(rb)
            if nb not in [b'\x00', b'\x01']: exit()
            if self.is_null(nb): return None, rb
            struct = structs[name[:-1]]
        else:
            struct = structs[name]

        # parses fields
        parsed_structure = {}
        for k, v in struct.items():
            parsed_value, rb = self.parse(v, rb)
            parsed_structure[k] = parsed_value
        return parsed_structure, rb


    # handles parsing if individual fields
    def parse(self, x, rb):

        # handle message
        if x == "msg":
            msg = Msg(rb); parsed_value = msg.msg; rb = msg.rb

        # handle map
        elif isinstance(x, dict):
            parsed_value, rb = self.parse_map(x, rb)

        # handle array
        elif isinstance(x, list):
            parsed_value, rb = self.parse_array(x, rb)

        # handle struct
        elif re.match("FTz.*", x):
            parsed_value, rb = self.parse_struct(x[3:], rb)

        # handle basic (int, char, bool...)
        elif isinstance(x, str):
            parsed_value, rb = self.parse_basic(x, rb)

        # returns the parsed value and remaining bytes
        return parsed_value, rb
    

    # parses map field type
    def parse_map(self, x, rb):
        parsed_map = {}

        # handle nullbyte
        nb, rb = self.split_null(rb)
        if nb not in [b'\x00', b'\x01']: exit()
        if self.is_null(nb): return None, rb

        # handle header
        hb, rb = self.split_header(rb)
        l = self.read_header(hb)

        # parse map
        t1, t2 = next(iter(x.items())) #gets key and value type
        for _ in range(0, l):
            v1, rb = self.parse(t1, rb)
            v2, rb = self.parse(t2, rb)
            parsed_map[v1] = v2

        return parsed_map, rb


    # parses array field type
    def parse_array(self, x, rb):
        parsed_array = []

        # handle nullbyte
        nb, rb = self.split_null(rb)
        if nb not in [b'\x00', b'\x01']: exit()
        if self.is_null(nb): return None, rb

        # handle header
        hb, rb = self.split_header(rb)
        l = self.read_header(hb)

        # parse array
        array_type = x[0]
        for _ in range (0, l):
            v, rb = self.parse(array_type, rb)
            parsed_array.append(v)

        return parsed_array, rb
    

    # parses basic field type
    def parse_basic(self, x, rb):

        # handle nullable basic types
        if x[-1] == "0":
            nb, rb = self.split_null(rb)
            if self.is_null(nb): 
                return None, rb
            format_string = f"<{x[:-1]}"

        # handle string types
        elif x == "s":
            v, rb = self.parse_string(rb)
            return v, rb
        
        # handle enum edge cases (4bytes)
        elif re.match(r"ETzBuildingAccessPermissionKindType|ETzAffectSourceSystemCastKindType|ETzResultCodeType|ETzCharacterStateType|ETzConnectionStatusType|ETzMountInteractionStateType|ETzContaminationNaturalDecreaseType|ETzBuildingAccessPermissionKindType", x):
            format_string = "<I"

        # handle regular enum (1byte)
        elif re.match("ETz.*", x):
            format_string = "<B"

        # handle bool type
        elif x == "?":
            if rb[:1] not in [b'\x00', b'\x01']: exit()
            format_string = f"<{x}"

        # handle regular basic type
        else:
            format_string = f"<{x}"

        # parse the basic type
        size = struct.calcsize(format_string)
        parsed_basic = struct.unpack(format_string, rb[:size])
        if len(parsed_basic) == 1: parsed_basic = parsed_basic[0] #since struct unpack always returns tuple

        return parsed_basic, rb[size:]
    

    # parses string type (simular to array)
    def parse_string(self, rb):

        # handle nullbyte
        nb, rb = self.split_null(rb)
        if nb not in [b'\x00', b'\x01']: exit()
        if self.is_null(nb): return None, rb
        
        # handle header
        hb, rb = self.split_header(rb)
        l = self.read_header(hb)

        # parse the string
        format_string = f"{l}s"
        size = struct.calcsize(format_string)
        parsed_string = struct.unpack(format_string, rb[:size])
        if len(parsed_string) == 1: parsed_string = parsed_string[0]

        return parsed_string.decode('utf-8', errors='ignore'), rb[size:]
    
    # def console_output(self):
    #     # print_dict(self.name, self.struct)
    #     # print("-")
    #     print_dict(self.name, self.msg)
    #     print("-")
    #     print(f"remaining bytes: {list(self.rb or [])}")

    #     pass

    # def log():
    #     pass

"""PACKER"""
class MsgPacker:
    def __init__(self):
        # Load the necessary JSON files
        with open('assets/names.json', 'r') as f:
            self.names = json.load(f)
        with open('assets/structs.json', 'r') as f:
            self.structs = json.load(f)

    def pack_message(self, name, msg):
        op = next(key for key, value in self.names.items() if value == name)
        packed = struct.pack('<?', False)  # Not null
        packed += struct.pack('<I', int(op))  # Header
        packed += self.pack_struct(name, msg)
        return packed

    def pack_struct(self, name, msg):
        packed = b''
        struct = self.structs[name]
        for k, v in struct.items():
            packed += self.pack(v, msg[k])
        return packed

    def pack(self, field_type, value):
        if field_type == "msg":
            return self.pack_message(value['name'], value['msg'])
        elif isinstance(field_type, dict):
            return self.pack_map(field_type, value)
        elif isinstance(field_type, list):
            return self.pack_array(field_type[0], value)
        elif re.match("FTz.*", field_type):
            return self.pack_struct(field_type[3:], value)
        else:
            return self.pack_basic(field_type, value)

    def pack_map(self, field_type, value):
        if value is None:
            return struct.pack('<?', True)
        packed = struct.pack('<?', False)  # Not null
        packed += struct.pack('<I', len(value))  # Length
        key_type, val_type = next(iter(field_type.items()))
        for k, v in value.items():
            packed += self.pack(key_type, k)
            packed += self.pack(val_type, v)
        return packed

    def pack_array(self, item_type, value):
        if value is None:
            return struct.pack('<?', True)
        packed = struct.pack('<?', False)  # Not null
        packed += struct.pack('<I', len(value))  # Length
        for item in value:
            packed += self.pack(item_type, item)
        return packed

    def pack_basic(self, field_type, value):
        if field_type[-1] == "0":
            if value is None:
                return struct.pack('<?', True)
            packed = struct.pack('<?', False)  # Not null
            field_type = field_type[:-1]
        else:
            packed = b''

        if field_type == "s":
            if value is None:
                return struct.pack('<?', True)
            encoded = value.encode('utf-8')
            packed += struct.pack('<?', False)  # Not null
            packed += struct.pack('<I', len(encoded))  # Length
            packed += encoded
        elif re.match(r"ETzBuildingAccessPermissionKindType|ETzAffectSourceSystemCastKindType|ETzResultCodeType|ETzCharacterStateType|ETzConnectionStatusType|ETzMountInteractionStateType|ETzContaminationNaturalDecreaseType|ETzBuildingAccessPermissionKindType", field_type):
            packed += struct.pack('<I', value)
        elif re.match("ETz.*", field_type):
            packed += struct.pack('<B', value)
        else:
            packed += struct.pack(f'<{field_type}', value)

        return packed
    

"""HELPERS"""

# converts string to bytearray # since bytes in log are represented as string
def convert_to_bytearray(string):
    ba = bytearray(int(x) for x in string.split(','))
    return ba

# useful for neater console output
def print_dict(name, dict):
    print(f"\"{name}\": {{")
    for key, value in dict.items():
        print(f"    {key}: {value}")
    print(f"  }}")


# """RUN"""
# def main():

#     # loop through each packet in log
#     for k, v in log.items():

#         # read message
#         ba = convert_to_bytearray(v)
#         msg = Msg(ba)

#         # output to console
#         print("\n\n")
#         print("-" * 100)
#         print("-" * 100)
#         print(f"{list(ba)}")
#         print("---")
#         print(msg.name)
#         print("---")
#         print_dict(msg.name, msg.struct)
#         print("---")
#         print_dict(msg.name, msg.msg)
#         print("---")
#         print(f"remaining bytes: {list(msg.rb or [])}")
#         print("---")
# main()