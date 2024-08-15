from socket import inet_ntoa
from struct import unpack
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from crypto import rsa_decrypt, rsa_encrypt, import_RSA_key, gen_master_key
from utils import read_message, write_message


"""PROXIFY HANDSHAKE"""
async def complete_proxify_handshake(reader, writer):
    # client -> proxy
    x = await reader.read(3)
    if x != b'\x05\01\x00':
        return False

    # proxy -> client
    writer.write(b'\x05\x00')
    await writer.drain()

    # client -> proxy
    x = await reader.read(10)
    server_host = inet_ntoa(x[4:8])
    server_port = unpack("!H", x[8:10])[0]

    # proxy -> client
    writer.write(b'\x05\x00\x00\x01' + x[4:10])
    await writer.drain()

    return server_host, server_port


"""TLS HANDSHAKE"""
async def complete_tls_handshake(client_reader, client_writer, server_reader, server_writer):
    public_key = import_RSA_key("public")
    private_key = import_RSA_key("private")

    # client -> server
    header, payload = await read_message(client_reader) 
    client_random_bytes = payload[10:]                            
    await write_message(server_writer, header, payload) 

    # server -> client
    header, payload = await read_message(server_reader)
    server_random_bytes = payload[10:-269]
    server_modulus = int.from_bytes(payload[-256:], byteorder='big')
    server_public_numbers = rsa.RSAPublicNumbers(65537, server_modulus)
    server_key = server_public_numbers.public_key(backend=default_backend())
    proxy_public_numbers = public_key.public_numbers()
    proxy_modulus = proxy_public_numbers.n
    proxy_modulus_bytes = proxy_modulus.to_bytes((proxy_modulus.bit_length() + 7) // 8, byteorder='big')
    payload = payload[:-256] + proxy_modulus_bytes
    await write_message(client_writer, header, payload) 

    # client -> server
    header, payload = await read_message(client_reader) 
    decrypted_secret = rsa_decrypt(payload[10:], private_key)
    encrypted_for_server = rsa_encrypt(decrypted_secret, server_key)
    master_key, iv = gen_master_key(client_random_bytes, server_random_bytes, decrypted_secret)
    adjusted_payload = payload[:10] + encrypted_for_server
    await write_message(server_writer, header, adjusted_payload) 

    # server -> client
    header, payload = await read_message(server_reader)
    await write_message(client_writer, header, payload) 

    return master_key, iv
