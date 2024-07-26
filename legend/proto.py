import socket
import struct    


proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
proxy.bind(('192.168.2.19', 8888))
proxy.listen(5); print("PROXY LISTENING\n\n")
while True:
    client, client_addr = proxy.accept()
    if not client: continue

    client.recv(1024)

    client.send(b'\x05\x00')

    x = client.recv(1024)
    server_addr = (socket.inet_ntoa(x[4:8]), struct.unpack("!H", x[8:10])[0])
    print(server_addr)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect(server_addr)
    client.send(b'\x05\x00\x00\x01' + x[4:10])

    msgs = []
    while True:
        client_msg = client.recv(4096); 
        msgs.append({"CLIENT": list(client_msg)}); print("-\nCLIENT MSG: ", list(client_msg))
        if client_msg == b'': break 
        server.send(client_msg)

        server_msg = server.recv(4096); 
        msgs.append({"SERVER": list(server_msg)}); print("-\nSERVER MSG: ", list(server_msg))
        if server_msg == b'': break
        client.send(server_msg)
    
    client.close()
    server.close()

    with open('log.txt', 'a') as f:
        f.write("\n\n-----------------------------------\n")
        f.write(f"CONNECTION LOG\n")
        f.write(f"client: {client_addr}\n")
        f.write(f"server: {server_addr}\n-\n")
        for i, (k, v) in enumerate(msgs.items()):
            f.write(f"#{i} {k}: {v}\n-\n")
            if i < len(msgs) - 1:
                f.write("-\n")


        

    

    

