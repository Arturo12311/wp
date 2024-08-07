"""IMPORTS"""
from crypto_handler import Crypto
from asyncio import get_event_loop
from struct import pack


############################################################################


"""MAIN CODE"""
class Injector():
    def __init__():
        pass

    def inject_ping(self, master_key, iv):  

        # payload to inject
        op = bytes([0, 141, 76, 212, 177])
        encoded_1337 = pack('<Q', 1337)
        injection_packet = bytes(op) + encoded_1337

        # encrypt 
        encrypted_payload = Crypto.encrypt_payload(injection_packet, master_key, iv)

        # header
        header = bytes([84, 79, 90, 32, 16, 0, 0, 0, 255, 255, 255, 255, 0, 13, 0, 0, 0, 141, 76, 212, 177])
        packet = header + encrypted_payload

        # return packet to inject
        return packet

    
    def inject_attack(self):     
        pass