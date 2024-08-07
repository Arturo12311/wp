"""IMPORTS"""
from crypto_handler import Crypto
from asyncio import get_event_loop
from struct import pack


############################################################################


"""MAIN CODE"""
class Injector():
    def __init__(self, master_key, iv):

        # cypher params for encryption
        self.master_key = master_key
        self.iv = iv


    # inject ping packet
    def ping(self, master_key, iv):  

        # payload to inject
        op = bytes([0, 141, 76, 212, 177])
        encoded_1337 = pack('<Q', 1337)
        injection_packet = bytes(op) + encoded_1337

        # encrypt payload
        encrypted_payload = Crypto.encrypt_payload(injection_packet, self.master_key, self.iv)

        # header
        header = bytes([84, 79, 90, 32, 16, 0, 0, 0, 255, 255, 255, 255, 0, 13, 0, 0, 0, 141, 76, 212, 177])

        # return packet to inject
        packet = header + encrypted_payload
        return packet

    
    def attack(self):     
        pass